# ==============================================================================
# SentinelScan Backend Dockerfile
# Multi-stage/Hardened Non-Root Container Image
# ==============================================================================

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Install minimal OS dependencies for healthchecks and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create unprivileged application user
RUN groupadd --system --gid 10001 sentinel && \
    useradd --system --uid 10001 --gid sentinel --no-create-home sentinel

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files and database migrations
COPY alembic.ini .
COPY alembic/ alembic/
COPY app/ app/

# Create directory for SQLite storage and grant ownership to non-root user
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run database migrations and launch Uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2"]
