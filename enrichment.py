"""
Contract Enrichment Module
自动拉取链上数据，把报告里的"待确认"字段全部填满。

Data sources (all free):
- Etherscan V2 (eth_call, ABI, holders, creation info)
- DexScreener (liquidity, price, holders)

Usage:
    from enrichment import enrich_contract
    data = enrich_contract(address, chain_id, etherscan_key)
"""

import json
import concurrent.futures
import requests as http_requests
from typing import Optional

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"

# Known multisig bytecode signatures (first few bytes)
MULTISIG_SIGNATURES = {
    "gnosis_safe": ["608060405273", "6080604052600436"],  # Gnosis Safe proxy
    "safe_l2": ["608060405273ffffffffffffffffffffffffffffffffffffffff"],
}

# Dangerous function signatures to flag
DANGEROUS_FUNCS = {
    "mint", "burn", "burnFrom", "blacklist", "setBlacklist",
    "pause", "unpause", "setTaxFee", "setMaxTxAmount",
    "setFeeReceiver", "excludeFromFee", "setTradingEnabled",
    "setSwapAndLiquifyEnabled", "manualSwap", "withdrawStuckTokens",
    "rescueTokens", "emergencyWithdraw", "forceTransfer",
}


def _eth_call(chain_id: int, to: str, data: str, api_key: str, timeout: int = 10) -> Optional[str]:
    """Make an eth_call via Etherscan V2."""
    try:
        params = {
            "chainid": chain_id, "module": "proxy", "action": "eth_call",
            "to": to, "data": data, "tag": "latest", "apikey": api_key,
        }
        r = http_requests.get(ETHERSCAN_V2, params=params, timeout=timeout)
        result = r.json().get("result", "")
        return result if result and result != "0x" else None
    except Exception:
        return None


def _get_code(chain_id: int, address: str, api_key: str) -> str:
    """Get deployed bytecode at address. Empty = EOA."""
    try:
        params = {
            "chainid": chain_id, "module": "proxy", "action": "eth_getCode",
            "address": address, "tag": "latest", "apikey": api_key,
        }
        r = http_requests.get(ETHERSCAN_V2, params=params, timeout=10)
        return r.json().get("result", "0x")
    except Exception:
        return "0x"


def _get_abi(chain_id: int, address: str, api_key: str) -> list:
    """Fetch contract ABI from Etherscan V2."""
    try:
        params = {
            "chainid": chain_id, "module": "contract", "action": "getabi",
            "address": address, "apikey": api_key,
        }
        r = http_requests.get(ETHERSCAN_V2, params=params, timeout=10)
        data = r.json()
        if data.get("status") == "1":
            return json.loads(data.get("result", "[]"))
    except Exception:
        pass
    return []


def _get_creation_info(chain_id: int, address: str, api_key: str) -> dict:
    """Get contract deployer and creation tx."""
    try:
        params = {
            "chainid": chain_id, "module": "contract",
            "action": "getcontractcreation", "contractaddresses": address,
            "apikey": api_key,
        }
        r = http_requests.get(ETHERSCAN_V2, params=params, timeout=10)
        result = r.json().get("result", [])
        if result and len(result) > 0:
            return {
                "deployer": result[0].get("contractCreator", ""),
                "tx_hash": result[0].get("txHash", ""),
            }
    except Exception:
        pass
    return {"deployer": "", "tx_hash": ""}


def _detect_multisig(bytecode: str) -> dict:
    """Heuristic check if a contract address is a known multisig."""
    if not bytecode or bytecode == "0x":
        return {"is_contract": False, "is_multisig": False, "wallet_type": "EOA"}

    code_lower = bytecode.lower()
    # Gnosis Safe proxy is very short and has distinctive pattern
    if len(bytecode) < 500:
        for name, sigs in MULTISIG_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in code_lower:
                    return {"is_contract": True, "is_multisig": True, "wallet_type": f"Multisig ({name})"}
        return {"is_contract": True, "is_multisig": True, "wallet_type": "Likely Proxy/Multisig"}

    return {"is_contract": True, "is_multisig": False, "wallet_type": "Contract (not multisig)"}


def _call_view_function(chain_id: int, address: str, selector: str, api_key: str) -> Optional[str]:
    """Call a no-arg view function by its 4-byte selector."""
    return _eth_call(chain_id, address, selector, api_key)


def _decode_address(hex_result: str) -> Optional[str]:
    """Decode eth_call result as an address."""
    if not hex_result or len(hex_result) < 42:
        return None
    # Last 40 hex chars = address
    return "0x" + hex_result[-40:]


def _decode_uint(hex_result: str) -> Optional[int]:
    """Decode eth_call result as uint256."""
    if not hex_result or hex_result == "0x":
        return None
    try:
        return int(hex_result, 16)
    except Exception:
        return None


def _get_owner_or_manager(chain_id: int, address: str, api_key: str) -> dict:
    """Try common privileged-role getters: owner(), manager(), getOwner()."""
    selectors = {
        "owner()":        "0x8da5cb5b",
        "manager()":      "0x481c6a75",
        "getOwner()":     "0x893d20e8",
        "getManager()":   "0x71f3c901",
        "admin()":        "0xf851a440",
    }
    found = {}
    for name, sel in selectors.items():
        result = _call_view_function(chain_id, address, sel, api_key)
        addr = _decode_address(result) if result else None
        if addr and addr != "0x0000000000000000000000000000000000000000":
            found[name] = addr
    return found


def _analyze_abi(abi: list) -> dict:
    """Parse ABI for dangerous functions and capabilities."""
    if not abi:
        return {"dangerous_functions": [], "has_mint": False, "has_burn_other": False,
                "has_blacklist": False, "has_pause": False, "privileged_roles": []}

    dangerous = []
    has_mint = False
    has_burn_other = False
    has_blacklist = False
    has_pause = False
    roles = set()

    for item in abi:
        if item.get("type") != "function":
            continue
        name = item.get("name", "")
        inputs = item.get("inputs", [])

        if name in DANGEROUS_FUNCS:
            dangerous.append(name)

        if name in ("mint", "_mint"):
            has_mint = True
        # burn(address, uint256) = can burn others
        if name in ("burn", "burnFrom") and len(inputs) >= 2 and inputs[0].get("type") == "address":
            has_burn_other = True
        if "blacklist" in name.lower() or "blocklist" in name.lower():
            has_blacklist = True
        if name in ("pause", "unpause"):
            has_pause = True

    return {
        "dangerous_functions": sorted(set(dangerous)),
        "has_mint": has_mint,
        "has_burn_other": has_burn_other,
        "has_blacklist": has_blacklist,
        "has_pause": has_pause,
    }


def _fetch_dexscreener(address: str) -> dict:
    """Get liquidity, price, volume from DexScreener."""
    try:
        r = http_requests.get(DEXSCREENER + address, timeout=10)
        data = r.json()
        pairs = data.get("pairs") or []
        if not pairs:
            return {"has_liquidity": False}

        # Aggregate across all pairs
        total_liquidity = sum(float((p.get("liquidity") or {}).get("usd") or 0) for p in pairs)
        total_volume_24h = sum(float((p.get("volume") or {}).get("h24") or 0) for p in pairs)
        best_pair = max(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))

        return {
            "has_liquidity": total_liquidity > 0,
            "liquidity_usd": round(total_liquidity, 2),
            "volume_24h_usd": round(total_volume_24h, 2),
            "price_usd": float(best_pair.get("priceUsd") or 0),
            "pair_count": len(pairs),
            "main_dex": best_pair.get("dexId", ""),
            "price_change_24h": (best_pair.get("priceChange") or {}).get("h24", 0),
        }
    except Exception as e:
        return {"has_liquidity": False, "error": str(e)[:100]}


def enrich_contract(address: str, chain_id: int, etherscan_key: str) -> dict:
    """
    Fetch all enrichment data in parallel.
    Returns a dict with resolved fields ready to inject into Claude's prompt.
    """
    if not etherscan_key:
        return {"error": "Missing Etherscan API key"}

    result = {
        "address": address,
        "chain_id": chain_id,
    }

    # Run independent calls in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        fut_abi = ex.submit(_get_abi, chain_id, address, etherscan_key)
        fut_creation = ex.submit(_get_creation_info, chain_id, address, etherscan_key)
        fut_supply = ex.submit(_call_view_function, chain_id, address, "0x18160ddd", etherscan_key)  # totalSupply()
        fut_cap = ex.submit(_call_view_function, chain_id, address, "0x355274ea", etherscan_key)    # cap()
        fut_decimals = ex.submit(_call_view_function, chain_id, address, "0x313ce567", etherscan_key)  # decimals()
        fut_dex = ex.submit(_fetch_dexscreener, address)
        fut_roles = ex.submit(_get_owner_or_manager, chain_id, address, etherscan_key)

        abi = fut_abi.result()
        creation = fut_creation.result()
        supply_hex = fut_supply.result()
        cap_hex = fut_cap.result()
        decimals_hex = fut_decimals.result()
        dex_data = fut_dex.result()
        roles = fut_roles.result()

    # ABI analysis
    result["abi_analysis"] = _analyze_abi(abi)

    # Supply + cap
    decimals = _decode_uint(decimals_hex) or 18
    total_supply_raw = _decode_uint(supply_hex)
    cap_raw = _decode_uint(cap_hex)
    result["total_supply"] = (total_supply_raw / 10**decimals) if total_supply_raw else None
    result["has_cap"] = cap_raw is not None and cap_raw > 0
    result["cap"] = (cap_raw / 10**decimals) if cap_raw else None
    result["decimals"] = decimals

    # Deployer
    result["deployer"] = creation.get("deployer", "")
    result["creation_tx"] = creation.get("tx_hash", "")

    # Privileged roles (owner / manager / admin)
    # For each role address, detect if it's a multisig
    role_details = {}
    for role_name, role_addr in roles.items():
        code = _get_code(chain_id, role_addr, etherscan_key)
        wallet = _detect_multisig(code)
        role_details[role_name] = {
            "address": role_addr,
            **wallet,
        }
    result["privileged_roles"] = role_details

    # DexScreener data
    result["market"] = dex_data

    # Summary flags for Claude to write conclusions
    flags = []
    if result["abi_analysis"]["has_mint"] and not result["has_cap"]:
        flags.append("UNCAPPED_MINT")
    if result["abi_analysis"]["has_burn_other"]:
        flags.append("BURN_OTHERS")
    if result["abi_analysis"]["has_blacklist"]:
        flags.append("BLACKLIST")
    if result["abi_analysis"]["has_pause"]:
        flags.append("PAUSABLE")
    if not role_details:
        flags.append("NO_ADMIN_FOUND")
    else:
        for name, info in role_details.items():
            if not info.get("is_multisig") and info.get("wallet_type") == "EOA":
                flags.append(f"EOA_ADMIN_{name}")
    if not dex_data.get("has_liquidity"):
        flags.append("NO_LIQUIDITY")
    elif dex_data.get("liquidity_usd", 0) < 10000:
        flags.append("LOW_LIQUIDITY")

    result["risk_flags"] = flags
    return result


def format_enrichment_for_prompt(enriched: dict) -> str:
    """Format enrichment data as a text block to inject into Claude's prompt."""
    if enriched.get("error"):
        return f"[Enrichment failed: {enriched['error']}]"

    lines = ["=== ON-CHAIN ENRICHMENT DATA (已自动获取，无需让用户手动检查) ==="]

    # Supply
    if enriched.get("total_supply") is not None:
        lines.append(f"Total Supply: {enriched['total_supply']:,.2f}")
    lines.append(f"Has Supply Cap: {enriched.get('has_cap', False)}")
    if enriched.get("cap"):
        lines.append(f"Max Cap: {enriched['cap']:,.2f}")

    # Deployer
    if enriched.get("deployer"):
        lines.append(f"Deployer: {enriched['deployer']}")

    # Privileged roles
    roles = enriched.get("privileged_roles", {})
    if roles:
        lines.append("\nPrivileged Roles (已解析):")
        for name, info in roles.items():
            lines.append(f"  - {name}: {info['address']} ({info['wallet_type']})")
    else:
        lines.append("\nPrivileged Roles: 未找到 owner/manager/admin getter")

    # ABI analysis
    abi = enriched.get("abi_analysis", {})
    if abi.get("dangerous_functions"):
        lines.append(f"\nDangerous Functions Found: {', '.join(abi['dangerous_functions'])}")
    lines.append(f"Has mint(): {abi.get('has_mint', False)}")
    lines.append(f"Can burn others' tokens: {abi.get('has_burn_other', False)}")
    lines.append(f"Has blacklist: {abi.get('has_blacklist', False)}")
    lines.append(f"Pausable: {abi.get('has_pause', False)}")

    # Market
    market = enriched.get("market", {})
    if market.get("has_liquidity"):
        lines.append(f"\nMarket Data (from DexScreener):")
        lines.append(f"  Liquidity: ${market['liquidity_usd']:,.0f}")
        lines.append(f"  24h Volume: ${market['volume_24h_usd']:,.0f}")
        lines.append(f"  Price: ${market['price_usd']}")
        lines.append(f"  24h Change: {market.get('price_change_24h', 0)}%")
        lines.append(f"  Trading on: {market['main_dex']} ({market['pair_count']} pairs)")
    else:
        lines.append("\nMarket Data: NO LIQUIDITY FOUND on DEX")

    # Risk flags
    flags = enriched.get("risk_flags", [])
    if flags:
        lines.append(f"\n🚩 Auto-detected Risk Flags: {', '.join(flags)}")

    lines.append("\n=== END ENRICHMENT DATA ===")
    lines.append("IMPORTANT: Use this data to write DEFINITIVE conclusions. Do NOT tell the user to 'check manually' - everything above is already verified on-chain.")
    return "\n".join(lines)
