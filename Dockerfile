FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# solc versions are installed on-demand at runtime by app.py
# (avoids GitHub API rate limit during Railway builds)

# Copy all Python modules (app.py, enrichment.py, and any future modules)
COPY *.py ./

ENV PORT=8080
EXPOSE 8080

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080", "--timeout", "180", "--workers", "2"]
