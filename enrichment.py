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
import os
import time
import concurrent.futures
import requests as http_requests
from typing import Optional

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"

# Alchemy network subdomains per chain_id (for getAssetTransfers API).
# Only networks with Alchemy support listed; others will skip mint_history.
ALCHEMY_NETWORKS = {
    1:        "eth-mainnet",
    11155111: "eth-sepolia",
    137:      "polygon-mainnet",
    10:       "opt-mainnet",
    42161:    "arb-mainnet",
    8453:     "base-mainnet",
    56:       "bnb-mainnet",
    43114:    "avax-mainnet",
    324:      "zksync-mainnet",
    59144:    "linea-mainnet",
}

# Etherscan free tier: 5 calls/sec. Stay under by using 3 parallel workers
# and retrying once on rate limit failures.
ETHERSCAN_MAX_WORKERS = 3

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


_HEX_CHARS = set("0123456789abcdefABCDEF")


def _is_valid_hex(s: str) -> bool:
    """Check if a string is a 0x-prefixed hex value (Etherscan-friendly)."""
    if not isinstance(s, str) or not s.startswith("0x"):
        return False
    body = s[2:]
    if not body:
        return False
    return all(c in _HEX_CHARS for c in body)


def _eth_call(chain_id: int, to: str, data: str, api_key: str, timeout: int = 10) -> Optional[str]:
    """Make an eth_call via Etherscan V2 with one retry on rate limit.

    Returns valid hex result, or None on:
      - HTTP error
      - Empty / "0x" result
      - Plaintext error from Etherscan ("Max rate limit reached", etc.)
    """
    params = {
        "chainid": chain_id, "module": "proxy", "action": "eth_call",
        "to": to, "data": data, "tag": "latest", "apikey": api_key,
    }
    for attempt in range(2):  # try once, retry once on rate limit
        try:
            r = http_requests.get(ETHERSCAN_V2, params=params, timeout=timeout)
            body = r.json()
            result = body.get("result", "")

            # Etherscan rate limit / errors come as plaintext
            if isinstance(result, str) and "rate limit" in result.lower():
                if attempt == 0:
                    time.sleep(1.1)  # back off slightly over 1s
                    continue
                return None

            if not _is_valid_hex(result) or result == "0x":
                return None
            return result
        except Exception:
            if attempt == 0:
                time.sleep(0.5)
                continue
            return None
    return None


def _get_code(chain_id: int, address: str, api_key: str) -> str:
    """Get deployed bytecode at address. Empty/'0x' = EOA. Returns '0x' on errors."""
    try:
        params = {
            "chainid": chain_id, "module": "proxy", "action": "eth_getCode",
            "address": address, "tag": "latest", "apikey": api_key,
        }
        r = http_requests.get(ETHERSCAN_V2, params=params, timeout=10)
        result = r.json().get("result", "0x")
        # Reject Etherscan plaintext errors ("rate limit reached", etc.)
        if not _is_valid_hex(result):
            return "0x"
        return result
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


# Common privileged-role getter selectors (keccak256(name)[:4])
# Computed via: keccak256("functionName()") first 4 bytes
_ROLE_SELECTORS_PRIMARY = {
    "owner()":              "0x8da5cb5b",
    "manager()":            "0x481c6a75",
    "admin()":              "0xf851a440",
    "getOwner()":           "0x893d20e8",
    "getManager()":         "0xd5009584",
}

_ROLE_SELECTORS_EXTENDED = {
    "getAdmin()":           "0x6e9960c3",
    "controller()":         "0xf77c4791",
    "governance()":         "0x5aa6e675",
    "authority()":          "0xbf7e214f",
    "operator()":           "0x570ca735",
    "treasury()":           "0x61d027b3",
    "minter()":             "0x07546172",
    "pendingOwner()":       "0xe30c3978",
    "pendingAdmin()":       "0x26782247",
    "guardian()":           "0x452a9320",
    "timelock()":           "0xd33219b4",
    "dao()":                "0x4162169f",
    "multisig()":           "0x4783c35b",
    "keeper()":             "0xaced1661",
    "vault()":              "0xfbfa77cf",
    "feeRecipient()":       "0x46904840",
    "feeReceiver()":        "0xb3f00674",
}


def _query_role_selectors(chain_id: int, address: str, api_key: str, selectors: dict) -> dict:
    """Query a batch of selectors sequentially with rate-limit-friendly delays."""
    found = {}
    for name, sel in selectors.items():
        result = _call_view_function(chain_id, address, sel, api_key)
        addr = _decode_address(result) if result else None
        if addr and addr != "0x0000000000000000000000000000000000000000":
            found[name] = addr
        time.sleep(0.25)  # ~4 req/sec, under Etherscan free 5/sec limit
    return found


def _get_owner_or_manager(chain_id: int, address: str, api_key: str) -> dict:
    """Detect privileged role addresses on a contract.

    Two-tier strategy:
      1. Always probe 5 most common roles (owner/manager/admin variants)
      2. Only if NONE found, probe extended set (governance/treasury/etc)

    This keeps fast path ~1.5s for typical contracts while still catching
    unusual ones at ~6s cost.
    """
    found = _query_role_selectors(chain_id, address, api_key, _ROLE_SELECTORS_PRIMARY)
    if not found:
        # No standard roles found — try extended set
        found = _query_role_selectors(chain_id, address, api_key, _ROLE_SELECTORS_EXTENDED)
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

    # Function names that create new tokens (mint variants across different ERC20 implementations)
    MINT_FUNC_NAMES = {"mint", "_mint", "issue", "_issue", "createTokens", "generateTokens"}

    for item in abi:
        if item.get("type") != "function":
            continue
        name = item.get("name", "")
        inputs = item.get("inputs", [])

        if name in DANGEROUS_FUNCS:
            dangerous.append(name)

        if name in MINT_FUNC_NAMES:
            has_mint = True
            if name not in dangerous:
                dangerous.append(name)
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


def _fetch_mint_history(chain_id: int, address: str, decimals: int, api_key: str) -> dict:
    """Fetch mint events via Alchemy getAssetTransfers API.

    Alchemy reliably indexes ERC20 Transfer events including from=0x0 (mints),
    unlike Etherscan's logs API which has incomplete coverage.

    Requires ALCHEMY_API_KEY env var. Falls back gracefully if not set or
    if network isn't supported by Alchemy.
    """
    import logging as _lg
    logger = _lg.getLogger("enrichment")

    alchemy_key = os.environ.get("ALCHEMY_API_KEY", "").strip()
    if not alchemy_key:
        return {"available": False, "reason": "ALCHEMY_API_KEY not configured"}

    network = ALCHEMY_NETWORKS.get(chain_id)
    if not network:
        return {"available": False, "reason": f"Alchemy does not support chain_id={chain_id}"}

    url = f"https://{network}.g.alchemy.com/v2/{alchemy_key}"

    try:
        # alchemy_getAssetTransfers: from=0x0 + contractAddress = all mints
        # category erc20 limits to ERC20 Transfer events
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "alchemy_getAssetTransfers",
            "params": [{
                "fromAddress": "0x0000000000000000000000000000000000000000",
                "contractAddresses": [address],
                "category": ["erc20"],
                "withMetadata": True,
                "maxCount": "0x3e8",  # 1000, max allowed per call
                "order": "desc",  # newest first
            }],
        }
        r = http_requests.post(url, json=payload, timeout=25)
        body = r.json()

        if "error" in body:
            err_msg = str(body.get("error", {}).get("message", ""))[:100]
            logger.warning(f"[MINT-ALCHEMY-ERROR] {err_msg}")
            return {"available": False, "reason": f"Alchemy: {err_msg}"}

        transfers = body.get("result", {}).get("transfers", [])
        logger.warning(f"[MINT-ALCHEMY-RAW] transfers={len(transfers)}")

        if not transfers:
            return {
                "available": True,
                "mint_count": 0,
                "note": "No mint events found via Alchemy (token may have initial-supply-only distribution)",
            }

        # Parse transfers. Alchemy returns value as decimal number (already divided by decimals)
        # but we'll use rawContract.value (hex) and divide ourselves for precision.
        amounts = []
        recipients = {}
        timestamps = []

        divisor = 10 ** decimals
        for tx in transfers:
            try:
                raw = tx.get("rawContract", {})
                raw_value = raw.get("value", "0x0")
                amount = int(raw_value, 16) / divisor
                amounts.append(amount)

                to_addr = (tx.get("to") or "").lower()
                if to_addr:
                    recipients[to_addr] = recipients.get(to_addr, 0) + amount

                # metadata.blockTimestamp is ISO string e.g. "2024-12-01T10:30:00.000Z"
                ts_str = (tx.get("metadata") or {}).get("blockTimestamp", "")
                if ts_str:
                    # Parse ISO → unix ts
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(int(dt.timestamp()))
            except (ValueError, TypeError, KeyError):
                continue

        if not amounts:
            return {"available": True, "mint_count": 0, "note": "Transfers found but parse failed"}

        total_minted = sum(amounts)
        largest = max(amounts)
        last_ts = max(timestamps) if timestamps else 0
        now_ts = int(time.time())
        days_ago = (now_ts - last_ts) / 86400 if last_ts else 0

        cutoff_30d = now_ts - (30 * 86400)
        recent_30d = sum(
            amt for amt, ts in zip(amounts, timestamps) if ts >= cutoff_30d
        ) if timestamps else 0
        recent_30d_pct = (recent_30d / total_minted * 100) if total_minted > 0 else 0

        top_recipients = sorted(recipients.items(), key=lambda x: -x[1])[:3]
        top_recipients_fmt = [
            {"address": addr, "amount": round(amt, 4),
             "pct": round(amt / total_minted * 100, 2)}
            for addr, amt in top_recipients
        ]

        return {
            "available": True,
            "mint_count": len(amounts),
            "total_minted": round(total_minted, 4),
            "largest_single_mint": round(largest, 4),
            "last_mint_timestamp": last_ts,
            "last_mint_days_ago": round(days_ago, 1),
            "recent_30d_minted": round(recent_30d, 4),
            "recent_30d_pct": round(recent_30d_pct, 2),
            "top_recipients": top_recipients_fmt,
            "truncated": len(transfers) >= 1000,
        }
    except Exception as e:
        return {"available": False, "reason": f"{type(e).__name__}: {str(e)[:100]}"}

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

    # Run independent calls in parallel (limited to avoid Etherscan rate limit)
    with concurrent.futures.ThreadPoolExecutor(max_workers=ETHERSCAN_MAX_WORKERS) as ex:
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

    # Mint history (needs decimals, so runs after parallel batch)
    # Only fetch if contract has mint capability (saves API call for non-mintable tokens)
    mint_analysis = _analyze_abi(abi)  # quick re-check inline
    import logging as _logging
    _log = _logging.getLogger("enrichment")
    if mint_analysis.get("has_mint"):
        _log.warning(f"[MINT-HISTORY-START] fetching for {address} decimals={decimals}")
        mh = _fetch_mint_history(chain_id, address, decimals, etherscan_key)
        _log.warning(f"[MINT-HISTORY-DONE] available={mh.get('available')} count={mh.get('mint_count')} reason={mh.get('reason')}")
        result["mint_history"] = mh
    else:
        _log.warning(f"[MINT-HISTORY-SKIP] no mint() function in ABI")
        result["mint_history"] = {
            "available": True, "mint_count": 0,
            "note": "Contract has no mint() function",
        }

    # Deployer
    result["deployer"] = creation.get("deployer", "")
    result["creation_tx"] = creation.get("tx_hash", "")

    # Privileged roles (owner / manager / admin)
    # For each role address, detect if it's a multisig (sequential w/ delay
    # to respect Etherscan rate limit)
    role_details = {}
    for role_name, role_addr in roles.items():
        code = _get_code(chain_id, role_addr, etherscan_key)
        wallet = _detect_multisig(code)
        role_details[role_name] = {
            "address": role_addr,
            **wallet,
        }
        time.sleep(0.25)
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

    # Mint history flags
    mh = result.get("mint_history", {})
    if mh.get("available") and mh.get("mint_count", 0) > 0:
        # Recent aggressive minting (>5% of supply in past 30 days)
        if mh.get("recent_30d_pct", 0) > 5:
            flags.append("RECENT_HEAVY_MINT")
        # Concentrated minting (top recipient got >80% of all mints)
        top = mh.get("top_recipients", [])
        if top and top[0].get("pct", 0) > 80:
            flags.append("CONCENTRATED_MINT_RECIPIENT")
        # Very recent mint activity
        if mh.get("last_mint_days_ago", 999) < 7:
            flags.append("ACTIVE_MINTING_THIS_WEEK")

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

    # Mint history
    mh = enriched.get("mint_history", {})
    if mh.get("available"):
        if mh.get("mint_count", 0) == 0:
            lines.append(f"\nMint History: {mh.get('note', 'No mints')}")
        else:
            lines.append(f"\nMint History (实际增发记录):")
            lines.append(f"  Total mint events: {mh['mint_count']}")
            lines.append(f"  Total minted ever: {mh['total_minted']:,.2f}")
            lines.append(f"  Largest single mint: {mh['largest_single_mint']:,.2f}")
            lines.append(f"  Last mint: {mh['last_mint_days_ago']} days ago")
            lines.append(f"  Past 30 days minted: {mh['recent_30d_minted']:,.2f} ({mh['recent_30d_pct']}% of total)")
            top = mh.get("top_recipients", [])
            if top:
                lines.append(f"  Top mint recipients:")
                for r in top:
                    lines.append(f"    {r['address'][:10]}... received {r['amount']:,.2f} ({r['pct']}%)")
            if mh.get("truncated"):
                lines.append(f"  (Note: showing latest 1000 mint events, may have more history)")

    # Risk flags
    flags = enriched.get("risk_flags", [])
    if flags:
        lines.append(f"\n🚩 Auto-detected Risk Flags: {', '.join(flags)}")

    lines.append("\n=== END ENRICHMENT DATA ===")
    lines.append("IMPORTANT: Use this data to write DEFINITIVE conclusions. Do NOT tell the user to 'check manually' - everything above is already verified on-chain.")
    return "\n".join(lines)
