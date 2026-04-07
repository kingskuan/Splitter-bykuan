FROM python:3.11-slim

# System deps for solc and slither
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install solc-select and pre-install common versions
RUN solc-select install 0.8.20 && \
    solc-select install 0.8.19 && \
    solc-select install 0.8.17 && \
    solc-select install 0.8.24 && \
    solc-select install 0.8.26 && \
    solc-select use 0.8.20

COPY app.py .

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--timeout", "180", "--workers", "2"]
