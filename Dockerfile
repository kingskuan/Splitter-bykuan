FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-install solc binaries directly from binaries.soliditylang.org
# Avoids solc-select's GitHub API rate limit. Uses "latest" symlinks per minor version.
RUN mkdir -p /root/.solc-select/artifacts && \
    cd /root/.solc-select/artifacts && \
    for v in 0.5.16 0.6.12 0.7.6 0.8.17 0.8.19 0.8.20 0.8.24 0.8.26; do \
        echo "Downloading solc $v..." && \
        mkdir -p solc-$v && \
        curl -sSL -f "https://binaries.soliditylang.org/linux-amd64/list.json" -o /tmp/list.json && \
        FNAME=$(python3 -c "import json; d=json.load(open('/tmp/list.json')); print(d['releases']['$v'])") && \
        curl -sSL -f "https://binaries.soliditylang.org/linux-amd64/$FNAME" -o solc-$v/solc-$v && \
        chmod +x solc-$v/solc-$v && \
        echo "  installed solc-$v" ; \
    done && \
    rm /tmp/list.json && \
    echo '{"version": "0.8.20"}' > /root/.solc-select/global-version && \
    ls -la /root/.solc-select/artifacts/

COPY app.py .

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--timeout", "180", "--workers", "2", "--log-level", "info"]
