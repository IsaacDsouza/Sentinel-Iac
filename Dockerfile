# sentinel-iac multi-stage build
# Usage:
#   docker build --target api -t sentinel-iac:latest .
#   docker build --target cli -t sentinel-iac-cli:latest .

# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir -e . && \
    rm -rf /root/.cache/pip

# --- API stage ---
FROM base AS api

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# --- CLI stage ---
FROM base AS cli

ENTRYPOINT ["sentinel"]
