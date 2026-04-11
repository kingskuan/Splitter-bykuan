"""
Slither Smart Contract Analysis Microservice
POST /analyze - Analyze Solidity contracts via Slither
"""

import os
import json
import time
import uuid
import shutil
import subprocess
import tempfile
import re
import requests as http_requests
from functools import wraps
from flask import Flask, request, jsonify

# Enrichment module (on-chain data auto-fetch)
try:
    from enrichment import enrich_contract
    ENRICHMENT_ENABLED = True
except ImportError:
    ENRICHMENT_ENABLED = False
    print("WARNING: enrichment.py not found, skipping on-chain enrichment")

app = Flask(__name__)

API_KEY = os.environ.get("API_KEY", "")
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT", "120"))

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

# Etherscan V2 unified API: one key, all chains via chainid parameter
# https://docs.etherscan.io/etherscan-v2
NETWORK_CHAIN_IDS = {
    "mainnet":      1,
    "ethereum":     1,
    "eth":          1,
    "sepolia":      11155111,
    "goerli":       5,
    "bsc":          56,
    "bsc-testnet":  97,
    "polygon":      137,
    "polygon-zkevm": 1101,
    "arbitrum":     42161,
    "arbitrum-nova": 42170,
    "optimism":     10,
    "base":         8453,
    "base-sepolia": 84532,
    "avalanche":    43114,
    "fantom":       250,
    "gnosis":       100,
    "linea":        59144,
    "scroll":       534352,
    "blast":        81457,
    "mantle":       5000,
    "zksync":       324,
}


def require_api_key(f):
    """Simple API key authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return f(*args, **kwargs)  # No key configured = open access
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated


def fetch_source_from_etherscan(address: str, network: str) -> dict:
    """Fetch contract source code from Etherscan V2 unified API."""
    chain_id = NETWORK_CHAIN_IDS.get(network)
    if not chain_id:
        raise ValueError(f"Unsupported network: {network}. Supported: {list(NETWORK_CHAIN_IDS.keys())}")

    if not ETHERSCAN_API_KEY:
        raise ValueError(
            "Missing ETHERSCAN_API_KEY environment variable. "
            "Get one free from https://etherscan.io/myapikey (works for all chains via V2 API)."
        )

    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    }

    resp = http_requests.get(ETHERSCAN_V2_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        msg = data.get("message", "Unknown error")
        result = data.get("result", "")
        raise ValueError(f"Etherscan V2 API error for {network} (chainid={chain_id}): {msg} ({result})")

    result = data["result"][0]
    source = result.get("SourceCode", "")
    contract_name = result.get("ContractName", "Unknown")
    compiler_version = result.get("CompilerVersion", "")

    if not source or source == "":
        raise ValueError(f"Contract {address} is not verified on {network}")

    # Handle multi-file JSON format (Etherscan wraps in double braces)
    if source.startswith("{{"):
        source = source[1:-1]  # Remove outer braces

    return {
        "source_code": source,
        "contract_name": contract_name,
        "compiler_version": compiler_version,
    }


def extract_solc_version(source_code: str) -> str:
    """Extract solc version from pragma statement."""
    match = re.search(r"pragma\s+solidity\s+[\^~>=<]*\s*(0\.\d+\.\d+)", source_code)
    if match:
        return match.group(1)
    return "0.8.20"  # Default fallback


_VERSION_RE = re.compile(r"^0\.\d{1,2}\.\d{1,2}$")
_SOLC_ARTIFACTS_DIR = "/root/.solc-select/artifacts"
_DEFAULT_SOLC = "0.8.20"


def validate_solc_version(version: str) -> str:
    """Whitelist validate version string. Returns safe version or default."""
    if not version or not _VERSION_RE.match(version):
        return _DEFAULT_SOLC
    return version


def resolve_solc_binary(version: str) -> str:
    """Return absolute path to solc binary for given version.

    Avoids the global-state race condition from `solc-select use`:
    instead of mutating a shared pointer, we pass --solc <path> directly
    to Slither. Pre-installed versions are in the Docker image.

    Falls back to on-demand download via solc-select (still mutates global
    state but only once per missing version; subsequent calls use the path).
    """
    version = validate_solc_version(version)
    binary_path = os.path.join(_SOLC_ARTIFACTS_DIR, f"solc-{version}", f"solc-{version}")

    if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
        return binary_path

    # Not pre-installed — try to download. Use solc-select as a last resort.
    # This path mutates global state briefly, but we still return the binary
    # path afterwards so concurrent requests for different versions don't
    # collide during actual Slither execution.
    app.logger.info(f"solc {version} not pre-installed, downloading via solc-select")
    try:
        result = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=120, check=False
        )
        app.logger.info(f"solc-select install {version}: exit={result.returncode}")
        if os.path.exists(binary_path) and os.access(binary_path, os.X_OK):
            return binary_path
    except Exception as e:
        app.logger.warning(f"Failed to install solc {version}: {e}")

    # Final fallback: default version (must be pre-installed)
    default_path = os.path.join(_SOLC_ARTIFACTS_DIR, f"solc-{_DEFAULT_SOLC}", f"solc-{_DEFAULT_SOLC}")
    app.logger.warning(f"Falling back to {_DEFAULT_SOLC} at {default_path}")
    return default_path


def prepare_source_files(work_dir: str, source_code: str, contract_name: str) -> str:
    """Write source code to temp directory, handling single and multi-file formats."""
    try:
        # Try parsing as JSON (multi-file format from Etherscan)
        sources = json.loads(source_code)
        if isinstance(sources, dict):
            # Could be {sources: {}, settings: {}} or direct {filename: {content: ...}}
            if "sources" in sources:
                sources = sources["sources"]
            main_file = None
            for filename, content in sources.items():
                filepath = os.path.join(work_dir, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                code = content if isinstance(content, str) else content.get("content", "")
                with open(filepath, "w") as f:
                    f.write(code)
                if main_file is None and contract_name and contract_name in filename:
                    main_file = filepath
            return main_file or work_dir  # Slither can analyze a directory
    except (json.JSONDecodeError, AttributeError):
        pass

    # Single file
    filename = f"{contract_name or 'Contract'}.sol"
    filepath = os.path.join(work_dir, filename)
    with open(filepath, "w") as f:
        f.write(source_code)
    return filepath


def run_slither(target: str, work_dir: str, solc_path: str) -> dict:
    """Run Slither analysis with explicit solc binary (no global state)."""
    # Diagnostic: check solc binary
    try:
        ver = subprocess.run([solc_path, "--version"], capture_output=True, text=True, timeout=5)
        app.logger.info(f"Using solc at {solc_path}: {ver.stdout[:150]}")
    except Exception as e:
        app.logger.warning(f"Cannot invoke solc at {solc_path}: {e}")

    cmd = [
        "slither", target,
        "--solc", solc_path,
        "--json", "-",
        "--exclude-informational",
        "--exclude-optimization",
    ]
    app.logger.info(f"Running: slither {target} --solc {solc_path} (cwd={work_dir})")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=ANALYSIS_TIMEOUT,
        cwd=work_dir,
        env=os.environ.copy(),
    )

    output = result.stdout.strip()
    stderr = result.stderr.strip()

    # Log for debugging
    app.logger.info(f"Slither exit={result.returncode}, stdout={len(output)}b, stderr={len(stderr)}b")
    if stderr:
        app.logger.info(f"Slither stderr: {stderr[:1000]}")

    # Slither outputs JSON to stdout even on non-zero exit (findings = exit 1/255)
    if not output:
        # Try to surface the real error from stderr
        if stderr:
            # Extract most relevant error line
            err_lines = [l for l in stderr.split("\n") if l.strip() and not l.startswith("Warning")]
            err_msg = " | ".join(err_lines[-3:]) if err_lines else stderr[:500]
            raise RuntimeError(f"Slither failed (exit {result.returncode}): {err_msg[:800]}")
        raise RuntimeError(f"Slither returned no output (exit {result.returncode}). No stderr either — possible OOM or timeout.")

    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Slither output not valid JSON: {output[:300]}... stderr: {stderr[:300]}")


def fetch_external_risks(address: str, network: str) -> dict:
    """Fetch off-chain & live-state risks via GoPlus Security API (free, no key).

    Returns holder concentration, LP lock status, tax, honeypot detection, etc.
    https://docs.gopluslabs.io/reference/api-overview
    """
    chain_id = NETWORK_CHAIN_IDS.get(network)
    if not chain_id:
        return {"available": False, "reason": f"Network {network} not supported"}

    try:
        url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}"
        resp = http_requests.get(
            url,
            params={"contract_addresses": address.lower()},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("code") != 1:
            return {"available": False, "reason": data.get("message", "GoPlus error")}

        result = (data.get("result") or {}).get(address.lower())
        if not result:
            return {"available": False, "reason": "Token not found in GoPlus database"}

        # Extract fields (GoPlus uses string "0"/"1" instead of bool)
        def flag(key, default=None):
            v = result.get(key)
            if v == "1": return True
            if v == "0": return False
            return default

        def num(key, default=0.0):
            try: return float(result.get(key, default))
            except (ValueError, TypeError): return default

        # Top holder concentration
        holders = result.get("holders") or []
        top10_pct = sum(num_or_zero(h.get("percent", 0)) for h in holders[:10]) * 100

        # LP lock status
        lp_holders = result.get("lp_holders") or []
        lp_locked_pct = sum(
            num_or_zero(lp.get("percent", 0)) * 100
            for lp in lp_holders
            if lp.get("is_locked") == 1 or "lock" in str(lp.get("tag", "")).lower() or lp.get("address", "").lower() in ("0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000000")
        )

        return {
            "available": True,
            "source": "GoPlus Security",
            # Honeypot & trading
            "is_honeypot": flag("is_honeypot"),
            "cannot_buy": flag("cannot_buy"),
            "cannot_sell_all": flag("cannot_sell_all"),
            "trading_cooldown": flag("trading_cooldown"),
            "transfer_pausable": flag("transfer_pausable"),
            # Tax
            "buy_tax_pct": round(num("buy_tax") * 100, 2),
            "sell_tax_pct": round(num("sell_tax") * 100, 2),
            # Permissions (live state)
            "is_mintable": flag("is_mintable"),
            "owner_can_change_balance": flag("owner_change_balance"),
            "hidden_owner": flag("hidden_owner"),
            "can_take_back_ownership": flag("can_take_back_ownership"),
            "self_destruct": flag("selfdestruct"),
            "external_call_risk": flag("external_call"),
            # Lists
            "is_blacklisted": flag("is_blacklisted"),
            "is_whitelisted": flag("is_whitelisted"),
            # Anti-whale
            "is_anti_whale": flag("is_anti_whale"),
            "anti_whale_modifiable": flag("anti_whale_modifiable"),
            # Proxy / upgrade
            "is_proxy": flag("is_proxy"),
            # Source
            "is_open_source": flag("is_open_source"),
            # Holder distribution
            "holder_count": int(num("holder_count")),
            "top10_holders_pct": round(top10_pct, 2),
            "top_holders": [
                {
                    "address": h.get("address", "")[:10] + "...",
                    "percent": round(num_or_zero(h.get("percent", 0)) * 100, 2),
                    "is_contract": h.get("is_contract") == 1,
                    "tag": h.get("tag", ""),
                }
                for h in holders[:5]
            ],
            # Owner / creator
            "owner_address": result.get("owner_address", ""),
            "owner_balance_pct": round(num("owner_percent") * 100, 2),
            "creator_address": result.get("creator_address", ""),
            "creator_balance_pct": round(num("creator_percent") * 100, 2),
            # LP
            "lp_holder_count": len(lp_holders),
            "lp_locked_or_burned_pct": round(lp_locked_pct, 2),
            # Token info
            "token_name": result.get("token_name", ""),
            "token_symbol": result.get("token_symbol", ""),
            "total_supply": result.get("total_supply", ""),
        }
    except Exception as e:
        app.logger.warning(f"GoPlus fetch failed: {e}")
        return {"available": False, "reason": str(e)[:200]}


def num_or_zero(v):
    try:
        return float(v) if v else 0.0
    except (ValueError, TypeError):
        return 0.0


def extract_centralization_risks(source_code: str) -> dict:
    """Scan Solidity source for centralization/trust risks that Slither misses.

    Returns structured risk info + raw code excerpts of dangerous functions.
    """
    risks = {
        "can_mint": False,
        "mint_details": [],
        "can_burn_others": False,
        "can_pause": False,
        "has_blacklist": False,
        "has_whitelist": False,
        "has_fees": False,
        "fee_changeable": False,
        "is_upgradeable": False,
        "can_transfer_ownership": False,
        "can_rescue_tokens": False,
        "has_trading_control": False,
        "has_max_tx_limit": False,
        "has_anti_whale": False,
        "owner_only_functions": [],
        "role_based_functions": [],
        "dangerous_excerpts": [],
        "inherits_minter": False,
    }

    # CRITICAL: Etherscan multi-file format returns JSON where newlines are
    # literal `\n` (two chars). Regex with `\s` won't match across them.
    # Detect and unwrap to real Solidity text.
    real_source = source_code
    stripped = source_code.strip()
    if stripped.startswith("{") and ('"content"' in stripped or '"sources"' in stripped):
        try:
            parsed = json.loads(stripped)
            sources = parsed.get("sources", parsed) if isinstance(parsed, dict) else {}
            collected = []
            if isinstance(sources, dict):
                for filename, file_data in sources.items():
                    if isinstance(file_data, dict) and "content" in file_data:
                        collected.append(file_data["content"])
                    elif isinstance(file_data, str):
                        collected.append(file_data)
            if collected:
                real_source = "\n\n".join(collected)
                app.logger.info(f"Unpacked multi-file source: {len(collected)} files, {len(real_source)} chars total")
        except (json.JSONDecodeError, AttributeError) as e:
            app.logger.warning(f"Multi-file source parse failed, using raw: {e}")

    # Strip comments AND string literals to avoid false positives
    code_clean = re.sub(r"//.*?$|/\*.*?\*/", "", real_source, flags=re.MULTILINE | re.DOTALL)
    code_clean = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code_clean)
    code_clean = re.sub(r"'(?:[^'\\]|\\.)*'", "''", code_clean)
    code_no_comments = code_clean

    # 1. MINTING — multiple detection strategies
    # Strategy A: function explicitly named *mint* with body adding to supply
    mint_pattern = re.compile(
        r"function\s+(\w*[Mm]int\w*)\s*\([^)]*\)[^{]*\{[^}]*(?:_totalSupply\s*\+=|totalSupply\s*\+=|_balances\[[^\]]+\]\s*\+=|_mint\s*\(|balances\[[^\]]+\]\s*\+=)",
        re.DOTALL
    )
    for m in mint_pattern.finditer(code_no_comments):
        risks["can_mint"] = True
        fn_name = m.group(1)
        snippet = m.group(0)[:500]
        has_cap = bool(re.search(r"require\s*\([^)]*(?:cap|MAX_SUPPLY|maxSupply|_cap|TOTAL_SUPPLY)[^)]*\)", snippet, re.I))
        risks["mint_details"].append({
            "function": fn_name,
            "has_cap": has_cap,
            "snippet": snippet[:300],
        })

    # Strategy B: ANY function that calls _mint( (catches custom function names like "release", "issue", "distribute")
    # This is the catch-all that fixes UXLINK-style misses
    any_fn_with_mint = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{]*\{(?:[^{}]|\{[^{}]*\})*?\b_mint\s*\(",
        re.DOTALL
    )
    for m in any_fn_with_mint.finditer(code_no_comments):
        fn_name = m.group(1)
        # Skip OZ internal helpers and constructors
        if fn_name in ("_mint", "_beforeTokenTransfer", "_afterTokenTransfer", "_update"):
            continue
        if not any(d.get("function") == fn_name for d in risks["mint_details"]):
            risks["can_mint"] = True
            risks["mint_details"].append({
                "function": fn_name,
                "has_cap": False,
                "snippet": m.group(0)[:300],
            })

    # Strategy C: Inherits from known mintable parent contracts
    inherit_patterns = [
        r"\bcontract\s+\w+\s+is\s+[^{]*\b(ERC20PresetMinterPauser|ERC20Mintable|MintableToken|ERC20Capped)\b",
        r"\bMINTER_ROLE\b",
        r"\bMINTER\b\s*=\s*keccak256",
    ]
    for p in inherit_patterns:
        if re.search(p, code_no_comments):
            risks["can_mint"] = True
            risks["inherits_minter"] = True
            if not risks["mint_details"]:
                risks["mint_details"].append({
                    "function": "inherited_or_role_based",
                    "has_cap": False,
                    "snippet": "Mint capability via inheritance or MINTER_ROLE — review parent contracts",
                })
            break

    # 2. BURN others' tokens
    if re.search(r"function\s+\w*[Bb]urn\w*\s*\(\s*address\s+\w+", code_no_comments):
        risks["can_burn_others"] = True

    # 3. PAUSABLE
    if re.search(r"\b(Pausable|_pause\s*\(|whenNotPaused|_paused\s*=\s*true)", code_no_comments):
        risks["can_pause"] = True

    # 4. BLACKLIST
    blacklist_patterns = [
        r"mapping\s*\([^)]*\)\s*(?:public\s+)?(?:_?[Bb]lacklist|_?[Bb]lackList|_?isBlocked|_?banned|_?frozen)",
        r"function\s+\w*[Bb]lacklist\w*\s*\(",
        r"function\s+\w*[Bb]lock\w*\s*\(\s*address",
        r"function\s+\w*[Ff]reeze\w*\s*\(\s*address",
    ]
    if any(re.search(p, code_no_comments) for p in blacklist_patterns):
        risks["has_blacklist"] = True

    # 5. WHITELIST
    if re.search(r"mapping\s*\([^)]*\)\s*(?:public\s+)?_?[Ww]hitelist|function\s+\w*[Ww]hitelist\w*\s*\(", code_no_comments):
        risks["has_whitelist"] = True

    # 6. FEES / TAXES
    fee_state = re.search(r"(uint\d*\s+(?:public\s+)?(?:_?fee|_?tax|buyFee|sellFee|buyTax|sellTax|marketingFee|liquidityFee)\w*)", code_no_comments, re.I)
    if fee_state:
        risks["has_fees"] = True
        # Check if setter exists
        if re.search(r"function\s+\w*[Ss]et\w*(?:[Ff]ee|[Tt]ax)\w*\s*\(", code_no_comments):
            risks["fee_changeable"] = True

    # 7. UPGRADEABLE (proxy patterns)
    if re.search(r"(UUPSUpgradeable|TransparentUpgradeableProxy|Initializable|_authorizeUpgrade|upgradeTo\s*\(|upgradeToAndCall)", code_no_comments):
        risks["is_upgradeable"] = True

    # 8. OWNERSHIP TRANSFER
    if re.search(r"function\s+transferOwnership\s*\(|Ownable", code_no_comments):
        risks["can_transfer_ownership"] = True

    # 9. RESCUE / WITHDRAW stuck tokens (can be legit, can be rug)
    if re.search(r"function\s+\w*(?:[Rr]escue|[Ww]ithdraw(?:Token|Stuck|Any|ERC20)|[Ss]weep|[Rr]etrieve)\w*\s*\(", code_no_comments):
        risks["can_rescue_tokens"] = True

    # 10. TRADING ENABLE/DISABLE (honeypot pattern)
    if re.search(r"(tradingEnabled|tradingActive|launched|tradingOpen|swapEnabled)\s*(?:=|\?)", code_no_comments):
        risks["has_trading_control"] = True

    # 11. MAX TX / MAX WALLET
    if re.search(r"(maxTx|maxTransaction|maxWallet|maxHolding)", code_no_comments, re.I):
        risks["has_max_tx_limit"] = True
        risks["has_anti_whale"] = True

    # 12. Extract all onlyOwner / onlyRole functions (up to 20)
    owner_fn_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{]*?\b(onlyOwner|onlyAdmin|onlyGovernance|onlyOperator)\b",
        re.DOTALL
    )
    seen_fns = set()
    for m in owner_fn_pattern.finditer(code_no_comments):
        fn = m.group(1)
        if fn not in seen_fns and len(seen_fns) < 20:
            seen_fns.add(fn)
            risks["owner_only_functions"].append(fn)

    # 13. Role-based (AccessControl)
    role_fn_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)[^{]*?onlyRole\s*\(\s*(\w+)\s*\)",
        re.DOTALL
    )
    seen_roles = set()
    for m in role_fn_pattern.finditer(code_no_comments):
        fn, role = m.group(1), m.group(2)
        key = f"{fn}:{role}"
        if key not in seen_roles and len(seen_roles) < 20:
            seen_roles.add(key)
            risks["role_based_functions"].append({"function": fn, "role": role})

    # 14. Extract dangerous function bodies as excerpts (for LLM review)
    dangerous_keywords = ["mint", "blacklist", "setFee", "setTax", "pause", "rescue", "withdrawToken", "setTrading", "excludeFrom", "_authorizeUpgrade"]
    for kw in dangerous_keywords:
        pattern = re.compile(
            rf"function\s+\w*{kw}\w*\s*\([^)]*\)[^{{]*\{{[^}}]{{0,400}}\}}",
            re.IGNORECASE | re.DOTALL
        )
        for m in pattern.finditer(code_no_comments):
            excerpt = m.group(0)[:600].strip()
            if excerpt and len(risks["dangerous_excerpts"]) < 15:
                risks["dangerous_excerpts"].append(excerpt)

    return risks


# Known contract bytecode signatures for owner type detection
GNOSIS_SAFE_MARKERS = [
    "a619486e",  # masterCopy selector
    "6a761202",  # execTransaction selector
    "468721a7",  # execTransactionFromModule
]
TIMELOCK_MARKERS = [
    "31d50750",  # getMinDelay
    "8f2a0bb0",  # scheduleBatch
    "134008d3",  # execute(bytes32,...)
]


def analyze_owner_address(contract_address: str, network: str) -> dict:
    """Fetch contract owner() and classify as EOA / Multisig / Timelock / Unknown."""
    chain_id = NETWORK_CHAIN_IDS.get(network)
    if not chain_id or not ETHERSCAN_API_KEY:
        return {"available": False, "reason": "No API key or unsupported network"}

    try:
        # Step 1: eth_call to owner() selector 0x8da5cb5b
        call_params = {
            "chainid": chain_id,
            "module": "proxy",
            "action": "eth_call",
            "to": contract_address,
            "data": "0x8da5cb5b",  # owner()
            "tag": "latest",
            "apikey": ETHERSCAN_API_KEY,
        }
        r1 = http_requests.get(ETHERSCAN_V2_URL, params=call_params, timeout=15)
        result_hex = r1.json().get("result", "")

        if not result_hex or result_hex == "0x" or len(result_hex) < 66:
            # Try manager() selector 0x481c6a75 as fallback
            call_params["data"] = "0x481c6a75"
            r1 = http_requests.get(ETHERSCAN_V2_URL, params=call_params, timeout=15)
            result_hex = r1.json().get("result", "")

        if not result_hex or result_hex == "0x" or len(result_hex) < 66:
            return {"available": False, "reason": "Contract has no owner()/manager() function"}

        # Parse address from 32-byte result (last 20 bytes)
        owner_addr = "0x" + result_hex[-40:]
        if owner_addr == "0x" + "0" * 40:
            return {
                "available": True,
                "owner_address": owner_addr,
                "owner_type": "Renounced (zero address)",
                "risk_level": "low",
                "description": "Ownership renounced - no admin can modify contract",
            }

        # Step 2: eth_getCode on owner address
        code_params = {
            "chainid": chain_id,
            "module": "proxy",
            "action": "eth_getCode",
            "address": owner_addr,
            "tag": "latest",
            "apikey": ETHERSCAN_API_KEY,
        }
        r2 = http_requests.get(ETHERSCAN_V2_URL, params=code_params, timeout=15)
        code = (r2.json().get("result") or "0x").lower()

        if code == "0x" or len(code) < 10:
            # EOA - externally owned account, single private key
            return {
                "available": True,
                "owner_address": owner_addr,
                "owner_type": "EOA (single private key)",
                "risk_level": "critical",
                "description": "Owner is an EOA - single point of failure. If private key is compromised, attacker gains full control.",
            }

        # Contract - check bytecode markers
        is_safe = any(marker in code for marker in GNOSIS_SAFE_MARKERS)
        is_timelock = any(marker in code for marker in TIMELOCK_MARKERS)

        if is_timelock:
            return {
                "available": True,
                "owner_address": owner_addr,
                "owner_type": "TimelockController",
                "risk_level": "low",
                "description": "Owner is a Timelock - admin actions delayed, giving users time to react.",
            }
        if is_safe:
            # Try to get threshold via getThreshold() selector 0xe75235b8
            call_params["to"] = owner_addr
            call_params["data"] = "0xe75235b8"
            r3 = http_requests.get(ETHERSCAN_V2_URL, params=call_params, timeout=15)
            thresh_hex = r3.json().get("result", "0x0")
            threshold = int(thresh_hex, 16) if thresh_hex and thresh_hex != "0x" else 0
            return {
                "available": True,
                "owner_address": owner_addr,
                "owner_type": f"Gnosis Safe multisig (threshold={threshold})",
                "risk_level": "medium" if threshold >= 3 else "high",
                "description": f"Owner is a Gnosis Safe requiring {threshold} signature(s). Safer than EOA but trust depends on signers.",
            }

        return {
            "available": True,
            "owner_address": owner_addr,
            "owner_type": "Unknown contract",
            "risk_level": "high",
            "description": "Owner is a contract but not a recognized multisig or timelock. Manual verification required.",
        }
    except Exception as e:
        return {"available": False, "reason": f"Owner analysis failed: {str(e)[:200]}"}


def analyze_max_supply(source_code: str) -> dict:
    """Deep analysis of _maxSupply / MAX_SUPPLY in the contract."""
    # Strip comments
    code = re.sub(r"//.*?$", "", source_code, flags=re.MULTILINE)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    result = {
        "has_cap": False,
        "cap_value": None,
        "is_mutable": None,
        "is_constant": False,
        "is_immutable": False,
        "setter_function": None,
        "is_erc20votes_default": False,
        "description": "",
    }

    # Check for ERC20Votes default _maxSupply (2^224 - 1, effectively unlimited)
    if re.search(r"_maxSupply\s*\(\s*\)\s*internal\s+view\s+virtual\s+returns", code):
        # Has override or uses default ERC20Votes
        override_match = re.search(
            r"function\s+_maxSupply\s*\(\s*\)\s*internal\s+view\s+(?:virtual\s+)?(?:override\s+)?returns\s*\([^)]*\)\s*\{([^}]+)\}",
            code,
        )
        if override_match:
            body = override_match.group(1).strip()
            result["cap_value"] = body[:200]
        else:
            result["is_erc20votes_default"] = True
            result["cap_value"] = "2^224 - 1 (ERC20Votes default, effectively unlimited)"
            result["description"] = "Uses ERC20Votes default _maxSupply = 2^224-1 ≈ 26.9 billion billion tokens. This is NOT a real cap."

    # Look for MAX_SUPPLY / _maxSupply state variable
    var_patterns = [
        (r"uint\d*\s+(?:public\s+|private\s+|internal\s+)?constant\s+(?:MAX_SUPPLY|_maxSupply|maxSupply)\s*=\s*([^;]+);", "constant"),
        (r"uint\d*\s+(?:public\s+|private\s+|internal\s+)?immutable\s+(?:MAX_SUPPLY|_maxSupply|maxSupply)\s*=\s*([^;]+);", "immutable"),
        (r"uint\d*\s+(?:public\s+|private\s+|internal\s+)?(?:MAX_SUPPLY|_maxSupply|maxSupply)\s*=\s*([^;]+);", "storage"),
    ]

    for pattern, kind in var_patterns:
        m = re.search(pattern, code)
        if m:
            result["has_cap"] = True
            result["cap_value"] = m.group(1).strip()[:100]
            if kind == "constant":
                result["is_constant"] = True
                result["is_mutable"] = False
                result["description"] = f"MAX_SUPPLY is a hardcoded constant: {result['cap_value']}"
            elif kind == "immutable":
                result["is_immutable"] = True
                result["is_mutable"] = False
                result["description"] = f"MAX_SUPPLY is immutable (set at deploy): {result['cap_value']}"
            else:
                result["is_mutable"] = True
                result["description"] = f"MAX_SUPPLY is a mutable storage variable - may be changeable by owner!"
            break

    # Look for setter functions
    setter_patterns = [
        r"function\s+(setMaxSupply|updateMaxSupply|_setMaxSupply|changeMaxSupply)\s*\(",
    ]
    for p in setter_patterns:
        m = re.search(p, code)
        if m:
            result["setter_function"] = m.group(1)
            result["is_mutable"] = True
            result["description"] += f" Setter function '{m.group(1)}' exists - owner can raise the cap."
            break

    if not result["has_cap"] and not result["is_erc20votes_default"]:
        result["description"] = "No explicit MAX_SUPPLY found. Check mint() logic for hidden limits."

    return result


def categorize_findings(slither_output: dict) -> dict:
    """Extract and categorize findings by impact level."""
    categories = {"critical": [], "high": [], "medium": [], "low": []}

    detectors = slither_output.get("results", {}).get("detectors", [])

    for detector in detectors:
        impact = detector.get("impact", "").lower()
        confidence = detector.get("confidence", "").lower()

        finding = {
            "check": detector.get("check", "unknown"),
            "impact": impact,
            "confidence": confidence,
            "description": (detector.get("description", "")[:300]).strip(),
            "first_markdown_element": detector.get("first_markdown_element", ""),
        }

        # Map Slither impact levels to our categories
        if impact == "high" and confidence in ("high", "medium"):
            categories["critical"].append(finding)
        elif impact == "high":
            categories["high"].append(finding)
        elif impact == "medium":
            categories["medium"].append(finding)
        elif impact == "low":
            categories["low"].append(finding)

    return categories


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "slither-analyzer",
        "status": "ok",
        "endpoints": ["/health", "/analyze"],
        "supported_networks": list(NETWORK_CHAIN_IDS.keys()),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "slither-analyzer"})


@app.route("/debug", methods=["GET"])
def debug():
    """Diagnostic endpoint - check config without exposing secrets."""
    return jsonify({
        "enrichment_enabled": ENRICHMENT_ENABLED,
        "etherscan_key_set": bool(ETHERSCAN_API_KEY),
        "etherscan_key_length": len(ETHERSCAN_API_KEY) if ETHERSCAN_API_KEY else 0,
        "api_key_set": bool(API_KEY),
        "supported_networks": list(NETWORK_CHAIN_IDS.keys()),
    })


@app.route("/analyze", methods=["POST"])
@require_api_key
def analyze():
    start_time = time.time()

    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "JSON body required"}), 400

    address = data.get("address", "").strip()
    network = data.get("network", "mainnet").strip().lower()
    source_code = data.get("source_code", "").strip()
    contract_name = data.get("contract_name", "").strip()

    if not source_code and not address:
        return jsonify({
            "status": "error",
            "message": "Either 'address' or 'source_code' is required"
        }), 400

    work_dir = tempfile.mkdtemp(prefix="slither_")

    try:
        # Step 1: Get source code
        if not source_code:
            etherscan_data = fetch_source_from_etherscan(address, network)
            source_code = etherscan_data["source_code"]
            contract_name = contract_name or etherscan_data["contract_name"]
            compiler_version = etherscan_data.get("compiler_version", "")
        else:
            compiler_version = ""

        if not contract_name:
            contract_name = "Contract"

        # Step 2: Detect solc version (whitelist validated)
        solc_version = extract_solc_version(source_code)
        if compiler_version:
            ver_match = re.search(r"(0\.\d+\.\d+)", compiler_version)
            if ver_match:
                solc_version = ver_match.group(1)
        solc_version = validate_solc_version(solc_version)

        # Resolve binary path (no global state mutation)
        solc_path = resolve_solc_binary(solc_version)

        # Step 3: Write source files
        target = prepare_source_files(work_dir, source_code, contract_name)

        # Step 3.5: Extract centralization/trust risks via regex (fast, no LLM)
        centralization_risks = extract_centralization_risks(source_code)

        # Step 3.55: Deep max_supply analysis
        max_supply_analysis = analyze_max_supply(source_code)

        # Step 3.6: Fetch external/live-state risks via GoPlus (only if we have an address)
        external_risks = {"available": False, "reason": "no address provided"}
        owner_analysis = {"available": False, "reason": "no address provided"}
        if address:
            external_risks = fetch_external_risks(address, network)
            owner_analysis = analyze_owner_address(address, network)

        # Step 4: Run Slither with explicit solc binary
        slither_output = run_slither(target, work_dir, solc_path)

        # Step 5: Categorize findings
        findings = categorize_findings(slither_output)

        duration_ms = int((time.time() - start_time) * 1000)

        total = sum(len(v) for v in findings.values())

        # Count centralization red flags (combines static + live state from GoPlus)
        ext = external_risks if external_risks.get("available") else {}
        central_flags = sum([
            centralization_risks["can_mint"] or ext.get("is_mintable") is True,
            centralization_risks["can_burn_others"],
            centralization_risks["can_pause"] or ext.get("transfer_pausable") is True,
            centralization_risks["has_blacklist"] or ext.get("is_blacklisted") is True,
            centralization_risks["fee_changeable"],
            centralization_risks["is_upgradeable"] or ext.get("is_proxy") is True,
            centralization_risks["has_trading_control"],
            centralization_risks["can_rescue_tokens"],
            ext.get("is_honeypot") is True,
            ext.get("hidden_owner") is True,
            ext.get("can_take_back_ownership") is True,
            ext.get("owner_can_change_balance") is True,
            ext.get("self_destruct") is True,
            (ext.get("buy_tax_pct", 0) >= 10) or (ext.get("sell_tax_pct", 0) >= 10),
            (ext.get("top10_holders_pct", 0) >= 70),
            (ext.get("lp_locked_or_burned_pct", 100) < 50),
        ])

        summary = (
            f"Slither: {total} code issue(s) "
            f"({len(findings['critical'])}C/{len(findings['high'])}H/{len(findings['medium'])}M/{len(findings['low'])}L). "
            f"Trust risks: {central_flags} red flag(s). "
            f"Solc {solc_version}, {duration_ms}ms."
        )

        # ── On-chain enrichment: fetch live data to eliminate "please verify manually" ──
        enriched = None
        app.logger.warning(f"[ENRICH-DEBUG] enabled={ENRICHMENT_ENABLED} address={bool(address)} network={network} key_set={bool(ETHERSCAN_API_KEY)}")
        if ENRICHMENT_ENABLED and address:
            chain_id = NETWORK_CHAIN_IDS.get(network)
            app.logger.warning(f"[ENRICH-DEBUG] chain_id={chain_id}")
            if chain_id and ETHERSCAN_API_KEY:
                try:
                    enriched = enrich_contract(address, chain_id, ETHERSCAN_API_KEY)
                    app.logger.warning(f"[ENRICH-OK] flags={enriched.get('risk_flags', [])} roles={list(enriched.get('privileged_roles', {}).keys())}")
                except Exception as e:
                    app.logger.warning(f"[ENRICH-FAIL] {type(e).__name__}: {e}")
                    enriched = {"error": str(e)[:200]}
            else:
                app.logger.warning(f"[ENRICH-SKIP] chain_id={chain_id} key={bool(ETHERSCAN_API_KEY)}")
        else:
            app.logger.warning(f"[ENRICH-SKIP] enabled={ENRICHMENT_ENABLED} has_address={bool(address)}")

        return jsonify({
            "status": "ok",
            "contract_name": contract_name,
            "address": address or None,
            "network": network,
            "solc_version": solc_version,
            "findings": findings,
            "centralization_risks": centralization_risks,
            "max_supply_analysis": max_supply_analysis,
            "owner_analysis": owner_analysis,
            "external_risks": external_risks,
            "enriched": enriched,
            "summary": summary,
            "duration_ms": duration_ms,
        })

    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        return jsonify({
            "status": "error",
            "message": f"Analysis timed out after {ANALYSIS_TIMEOUT}s",
            "duration_ms": duration_ms,
        }), 504

    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    except Exception as e:
        app.logger.exception("Analysis failed")
        return jsonify({
            "status": "error",
            "message": f"Analysis failed: {str(e)[:300]}",
        }), 500

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
