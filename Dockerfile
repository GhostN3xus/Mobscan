FROM python:3.11-slim

LABEL maintainer="Security Team"
LABEL description="Mobscan - OWASP MASTG Automated Mobile Security Testing Framework"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MOBSCAN_HOME=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    zip \
    unzip \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    libssl-dev \
    libffi-dev \
    graphviz \
    openjdk-11-jdk \
    android-sdk \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR ${MOBSCAN_HOME}

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install gunicorn uvicorn[standard]

# Copy application code
COPY mobscan ./mobscan
COPY setup.py .
COPY README.md .

# Install Mobscan
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /apps /reports /.cache /tmp/mobscan && \
    chmod 777 /apps /reports /.cache /tmp/mobscan

# Set working directory for app files
WORKDIR /apps

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports
EXPOSE 8000 8001

# Default command - run API server
CMD ["uvicorn", "mobscan.api.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
