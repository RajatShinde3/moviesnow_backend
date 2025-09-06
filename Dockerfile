# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first
COPY requirements.txt ./
RUN python -m pip install --upgrade pip wheel && \
    pip install -r requirements.txt

# Copy application
COPY app ./app
COPY scripts ./scripts
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic

# Create a non-root user
RUN useradd -m -u 10001 appuser
USER appuser

EXPOSE 8000

# Default command (override in compose/orchestrator as needed)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips=*"]
