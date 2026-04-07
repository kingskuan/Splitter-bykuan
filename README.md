# Slither Smart Contract Analyzer API

Flask microservice that runs [Slither](https://github.com/crytic/slither) static analysis on Solidity contracts via HTTP.

## Deploy to Railway

1. Push this repo to GitHub
2. Connect to Railway → New Project → Deploy from GitHub
3. Set environment variables:
   - `API_KEY` — your secret key for auth
   - `ETHERSCAN_API_KEY` — for fetching verified contracts
   - `ANALYSIS_TIMEOUT` — (optional, default 120s)

Railway auto-detects the Dockerfile.

## API Usage

### Health Check
```
GET /health
```

### Analyze Contract
```bash
curl -X POST https://your-app.railway.app/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "address": "0x1234...",
    "network": "mainnet"
  }'
```

### With Source Code Directly
```bash
curl -X POST https://your-app.railway.app/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "source_code": "pragma solidity ^0.8.20; contract Foo { ... }",
    "contract_name": "Foo"
  }'
```

### Response Format
```json
{
  "status": "ok",
  "contract_name": "MyToken",
  "address": "0x...",
  "network": "mainnet",
  "solc_version": "0.8.20",
  "findings": {
    "critical": [{"check": "...", "impact": "high", "confidence": "high", "description": "..."}],
    "high": [],
    "medium": [],
    "low": []
  },
  "summary": "Found 3 issue(s): 1 critical, 0 high, 2 medium, 0 low...",
  "duration_ms": 4523
}
```

### Supported Networks
mainnet, sepolia, goerli, bsc, bsc-testnet, polygon, arbitrum, optimism, base, avalanche

## Telegram Bot Integration
```python
import requests

def analyze_contract(address, network="mainnet"):
    resp = requests.post(
        "https://your-app.railway.app/analyze",
        json={"address": address, "network": network},
        headers={"X-API-Key": "YOUR_KEY"},
        timeout=150,
    )
    return resp.json()
```
