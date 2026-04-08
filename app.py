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


def install_solc_version(version: str):
    """Install and select a specific solc version."""
    # Check if already installed (pre-baked in Docker image)
    solc_path = f"/root/.solc-select/artifacts/solc-{version}/solc-{version}"
    if os.path.exists(solc_path):
        app.logger.info(f"solc {version} already installed at {solc_path}")
        try:
            subprocess.run(["solc-select", "use", version], capture_output=True, timeout=10, check=False)
        except Exception as e:
            app.logger.warning(f"solc-select use {version} failed: {e}")
        return

    app.logger.info(f"solc {version} not pre-installed, attempting download...")
    try:
        result = subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=120, check=False
        )
        app.logger.info(f"solc-select install {version}: exit={result.returncode}, stdout={result.stdout[:200]}, stderr={result.stderr[:200]}")
        if result.returncode != 0 and "already installed" not in (result.stdout + result.stderr):
            app.logger.warning(f"solc-select install {version} failed, falling back to 0.8.20")
            subprocess.run(["solc-select", "use", "0.8.20"], capture_output=True, timeout=10, check=False)
            return
        subprocess.run(["solc-select", "use", version], capture_output=True, timeout=10, check=False)
    except Exception as e:
        app.logger.warning(f"Failed to install solc {version}: {e}, falling back to 0.8.20")
        subprocess.run(["solc-select", "use", "0.8.20"], capture_output=True, timeout=10, check=False)


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


def run_slither(target: str, work_dir: str) -> dict:
    """Run Slither analysis and return parsed results."""
    # Diagnostic: which solc is active
    try:
        ver = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=5)
        app.logger.info(f"Active solc: {ver.stdout[:200]}")
    except Exception as e:
        app.logger.warning(f"Cannot get solc version: {e}")

    cmd = [
        "slither", target,
        "--json", "-",
        "--exclude-informational",
        "--exclude-optimization",
    ]
    app.logger.info(f"Running: {' '.join(cmd)} (cwd={work_dir})")

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
        "status": "running",
        "endpoints": {
            "GET /health": "health check",
            "POST /analyze": "analyze contract (requires X-API-Key header)",
        },
        "supported_networks": list(NETWORK_CONFIG.keys()),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "slither-analyzer"})


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

        # Step 2: Detect and install correct solc version
        solc_version = extract_solc_version(source_code)
        if compiler_version:
            # Extract version number from compiler string like "v0.8.20+commit.xxx"
            ver_match = re.search(r"(0\.\d+\.\d+)", compiler_version)
            if ver_match:
                solc_version = ver_match.group(1)

        install_solc_version(solc_version)

        # Step 3: Write source files
        target = prepare_source_files(work_dir, source_code, contract_name)

        # Step 4: Run Slither
        slither_output = run_slither(target, work_dir)

        # Step 5: Categorize findings
        findings = categorize_findings(slither_output)

        duration_ms = int((time.time() - start_time) * 1000)

        total = sum(len(v) for v in findings.values())
        summary = (
            f"Found {total} issue(s): "
            f"{len(findings['critical'])} critical, "
            f"{len(findings['high'])} high, "
            f"{len(findings['medium'])} medium, "
            f"{len(findings['low'])} low. "
            f"Solc version: {solc_version}. "
            f"Analysis took {duration_ms}ms."
        )

        return jsonify({
            "status": "ok",
            "contract_name": contract_name,
            "address": address or None,
            "network": network,
            "solc_version": solc_version,
            "findings": findings,
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
