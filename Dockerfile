# Multi-stage Dockerfile for Mobscan
# Stage 1: Builder
FROM python:3.11-slim as builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="Mobscan Team"
LABEL description="OWASP MASTG Automated Mobile Security Testing Framework"
LABEL version="1.1.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MOBSCAN_HOME=/app \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR ${MOBSCAN_HOME}

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    zip \
    unzip \
    graphviz \
    openjdk-11-jdk-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/requirements.txt .

# Install Python packages from wheels
RUN pip install --upgrade pip && \
    pip install --no-cache /wheels/* && \
    pip install gunicorn uvicorn[standard] && \
    rm -rf /wheels

# Copy application code
COPY mobscan ./mobscan
COPY setup.py .
COPY pyproject.toml .
COPY README.md .

# Install Mobscan package
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /apps /reports /.cache /tmp/mobscan && \
    chmod 755 /apps /reports /.cache /tmp/mobscan && \
    useradd -m -u 1000 mobscan && \
    chown -R mobscan:mobscan ${MOBSCAN_HOME}

# Switch to non-root user
USER mobscan

WORKDIR /apps

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose ports
EXPOSE 8000

# Default command - run API server
CMD ["uvicorn", "mobscan.api.app:create_app", "--host", "${HOST}", "--port", "${PORT}"]
