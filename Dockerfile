FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-install multiple solc versions covering historical Solidity releases.
# Direct binary downloads bypass solc-select's GitHub API (rate limited in CI).
# Each version ~30MB, total ~300MB (acceptable).
#
# Coverage rationale:
#   0.4.26 — latest 0.4.x, covers USDT and most 2017-2018 tokens
#   0.5.17 — latest 0.5.x, covers 2018-2019 contracts
#   0.6.12 — latest 0.6.x, covers 2019-2020 contracts (incl. many DeFi)
#   0.7.6  — latest 0.7.x, covers Uniswap V3 era
#   0.8.20 — modern default, covers 2021+ contracts
#   0.8.26 — latest stable for newest contracts
RUN set -e && \
    for VERSION in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20 0.8.26; do \
        mkdir -p /root/.solc-select/artifacts/solc-${VERSION} && \
        wget -q "https://github.com/ethereum/solidity/releases/download/v${VERSION}/solc-static-linux" \
            -O /root/.solc-select/artifacts/solc-${VERSION}/solc-${VERSION} && \
        chmod +x /root/.solc-select/artifacts/solc-${VERSION}/solc-${VERSION} && \
        /root/.solc-select/artifacts/solc-${VERSION}/solc-${VERSION} --version ; \
    done && \
    echo '0.8.20' > /root/.solc-select/global-version && \
    ln -sf /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 /usr/local/bin/solc

# Copy all Python modules (app.py, enrichment.py, and any future modules)
COPY *.py ./

# Copy SlithKing custom Semgrep rules
COPY slithking-rules.yaml ./

# Install Semgrep (separate from requirements.txt — large package, ~100MB)
# Then warm up: run once on dummy Solidity to pre-cache parser binary.
# This prevents runtime downloads in Railway's restricted network.
RUN pip install --no-cache-dir semgrep && \
    semgrep --version && \
    echo 'pragma solidity ^0.8.0; contract T { function x() public {} }' > /tmp/_warmup.sol && \
    SEMGREP_SEND_METRICS=off semgrep --metrics off --disable-version-check \
        --config /app/slithking-rules.yaml --json /tmp/_warmup.sol > /dev/null 2>&1 || true && \
    rm -f /tmp/_warmup.sol

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--timeout", "180", "--workers", "1"]
