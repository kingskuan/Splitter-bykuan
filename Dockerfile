FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install solc 0.8.20 directly from solidity binaries CDN
# Bypasses solc-select's GitHub API call which gets rate-limited in CI
RUN mkdir -p /root/.solc-select/artifacts/solc-0.8.20 && \
    wget -q https://github.com/ethereum/solidity/releases/download/v0.8.20/solc-static-linux \
        -O /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 && \
    chmod +x /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 && \
    echo '0.8.20' > /root/.solc-select/global-version && \
    ln -sf /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 /usr/local/bin/solc && \
    /root/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 --version

# Copy all Python modules (app.py, enrichment.py, and any future modules)
COPY *.py ./

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--timeout", "180", "--workers", "1"]
