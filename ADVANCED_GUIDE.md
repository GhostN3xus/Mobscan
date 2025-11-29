# Mobscan v1.1.0 - Advanced Guide

## Troubleshooting, Performance Tuning & Security Hardening

---

## Table of Contents

1. [Troubleshooting Guide](#troubleshooting)
2. [Performance Tuning](#performance)
3. [Security Hardening](#security)
4. [Best Practices](#best-practices)

---

## Troubleshooting Guide

### Connection Issues

#### Redis Connection Error

**Error Message**:
```
mobscan.utils.cache: ERROR - Failed to connect to Redis: [Errno 111] Connection refused
```

**Diagnosis**:
```bash
# Check if Redis container is running
docker ps | grep redis

# Check Redis port
netstat -tuln | grep 6379

# Test Redis connectivity
redis-cli ping
```

**Solutions**:

1. **Start Redis**:
```bash
docker-compose up -d redis
# Wait 2-3 seconds for startup
sleep 3
redis-cli ping  # Should return PONG
```

2. **Check Redis configuration**:
```bash
# View Redis config
docker-compose exec redis redis-cli CONFIG GET "*"

# Verify bind address
docker-compose exec redis redis-cli CONFIG GET bind
```

3. **Reset Redis connection**:
```python
from mobscan.utils.cache import initialize_cache

# Try with increased timeout
cache = initialize_cache(
    redis_host="localhost",
    redis_port=6379,
    use_redis=True
)

# Check status
print(cache.get_stats())
```

#### ADB Device Not Detected

**Error Message**:
```
adb: command not found
or
error: no devices/emulators found
```

**Diagnosis**:
```bash
# Check ADB installation
which adb
adb version

# List devices
adb devices -l

# Check USB connectivity (Linux)
lsusb | grep -i android

# Check permissions (Linux)
ls -la /dev/bus/usb/
```

**Solutions**:

1. **Install ADB**:
```bash
# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y android-tools-adb

# macOS
brew install android-platform-tools

# Windows
# Download from https://developer.android.com/tools/releases/platform-tools
```

2. **Configure device for ADB**:
```bash
# On Android device:
# 1. Enable Developer Options: Settings > About > Build Number (tap 7 times)
# 2. Enable USB Debugging: Settings > Developer Options > USB Debugging
# 3. Connect via USB
# 4. Tap "Allow" on device authorization prompt

# Verify connection
adb devices
# Should show: <serial>    device
```

3. **Fix permission issues (Linux)**:
```bash
# Add user to plugdev group
sudo usermod -aG plugdev $USER
newgrp plugdev

# Create udev rule for Android devices
echo 'SUBSYSTEMS=="usb", ATTRS{idVendor}=="18d1", MODE="0666"' | \
  sudo tee /etc/udev/rules.d/51-android.rules

sudo udevadm control --reload-rules
sudo udevadm trigger
```

4. **Use emulator instead**:
```bash
# Start Android emulator
emulator -avd MyEmulator &

# Wait for boot
sleep 10

# Verify connection
adb devices
```

#### MobSF Connection Timeout

**Error Message**:
```
RequestException: Connection timeout after 30s to http://localhost:8001
```

**Diagnosis**:
```bash
# Check MobSF container
docker-compose ps mobsf

# Check MobSF port
netstat -tuln | grep 8001

# Test HTTP connectivity
curl -i http://localhost:8001/api/v1/home

# Check container logs
docker-compose logs mobsf
```

**Solutions**:

1. **Start MobSF**:
```bash
docker-compose up -d mobsf
docker-compose logs -f mobsf  # Wait for "listening on"
```

2. **Increase timeout**:
```python
from mobscan.modules.integration.mobsf_integration import MobSFClient

client = MobSFClient(
    host="localhost",
    port=8001,
    timeout=120  # Increase to 2 minutes
)
```

3. **Check disk space** (MobSF requirement):
```bash
df -h | grep -E '^/dev/'
# Need at least 5GB free
```

### Logging Issues

#### Logs Not Being Written

**Diagnosis**:
```bash
# Check log directory
ls -la logs/

# Check file permissions
stat logs/mobscan.json.log

# Verify logger is initialized
python -c "from mobscan.utils.logger import get_logger; logger = get_logger('test'); logger.info('Test')"
```

**Solutions**:

1. **Create log directory**:
```bash
mkdir -p logs
chmod 755 logs
```

2. **Verify logging configuration**:
```python
from mobscan.utils.logger import setup_logger

logger = setup_logger(
    "mobscan",
    level="INFO",
    log_file="logs/mobscan.json.log",
    json_format=True
)

# Test logging
logger.info("Test message")

# Verify file
cat logs/mobscan.json.log
```

3. **Check file permissions**:
```bash
# Ensure file is writable
touch logs/test.log
echo "test" >> logs/test.log
rm logs/test.log
```

### Memory Issues

#### High Memory Usage

**Diagnosis**:
```bash
# Monitor Mobscan memory
ps aux | grep mobscan | grep -v grep

# Check memory of container
docker stats mobscan-api

# Profile memory usage
python -m memory_profiler mobscan/core/engine.py
```

**Solutions**:

1. **Reduce parallel workers**:
```python
from mobscan.core.config import MobscanConfig

config = MobscanConfig.default_config()
config.parallel_workers = 2  # Reduce from default 4
```

2. **Use Redis instead of memory cache**:
```python
from mobscan.utils.cache import initialize_cache

# Use Redis (more memory efficient)
cache = initialize_cache(use_redis=True)

# Not memory cache
cache = initialize_cache(use_redis=False)  # Avoid this for large data
```

3. **Reduce scan intensity**:
```python
from mobscan.core.config import ScanIntensity

config = MobscanConfig.default_config()
config.scan_intensity = ScanIntensity.QUICK  # Use smaller scans
```

4. **Enable memory cleanup**:
```python
import gc

# Force garbage collection
gc.collect()

# Set memory limit (if using resource module)
import resource
resource.setrlimit(resource.RLIMIT_AS, (2147483648, 2147483648))  # 2GB
```

---

## Performance Tuning

### 1. Cache Optimization

```python
from mobscan.utils.cache import CacheManager

# Configure cache for maximum performance
cache = CacheManager(
    redis_host="redis.prod.internal",
    redis_port=6379,
    redis_db=0,
    use_redis=True,
    ttl_default=86400  # 24 hours for long-lived data
)

# Monitor cache performance
stats = cache.get_stats()
print(f"Keys in cache: {stats['keys']}")
print(f"Used memory: {stats['used_memory']}")

# Cache frequently accessed data with long TTL
cache.set("app_metadata:app123", metadata, ttl=86400)

# Cache scan results
cache.set(f"scan_result:{scan_id}", results, ttl=3600)
```

**Cache Hit Ratio Optimization**:
```python
# Monitor hit ratio
initial_hits = stats['cache_hits']
initial_misses = stats['cache_misses']

# Run operations...

# Calculate hit ratio
hits = stats['cache_hits'] - initial_hits
misses = stats['cache_misses'] - initial_misses
hit_ratio = hits / (hits + misses) if (hits + misses) > 0 else 0

print(f"Cache hit ratio: {hit_ratio * 100:.2f}%")
# Target: > 80% hit ratio
```

### 2. Database Query Optimization

```python
# Use bulk operations
from mobscan.models.finding import Finding

# Bad: Multiple inserts
for finding in findings:
    db.session.add(finding)
    db.session.commit()

# Good: Batch insert
db.session.add_all(findings)
db.session.commit()

# With bulk insert
bulk_insert(findings)  # Much faster
```

### 3. Parallel Processing

```python
from mobscan.core.config import MobscanConfig
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

config = MobscanConfig.default_config()

# Optimal: Use CPU count
cpu_count = multiprocessing.cpu_count()
config.parallel_workers = cpu_count

# For I/O-heavy tasks, can use more
config.parallel_workers = cpu_count * 2

# Example: Parallel module execution
with ProcessPoolExecutor(max_workers=config.parallel_workers) as executor:
    futures = [
        executor.submit(module.execute, app_path)
        for module in modules
    ]
    results = [f.result() for f in futures]
```

### 4. Network Optimization

```python
# Use connection pooling
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()

# Configure retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Use with context manager
with session.get("https://api.example.com/data") as response:
    data = response.json()
```

### 5. Async Operations

```python
import asyncio
import aiohttp

async def fetch_data(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

async def fetch_multiple(urls):
    tasks = [fetch_data(url) for url in urls]
    return await asyncio.gather(*tasks)

# Run async operations
results = asyncio.run(fetch_multiple(urls))
```

### 6. Logging Performance

```python
import logging

# Use appropriate log level
# DEBUG: Verbose (slowest)
# INFO: Normal (balanced)
# WARNING: Less verbose (faster)

# Configure for production
config.log_level = "WARNING"  # Reduce I/O overhead

# Async logging (if available)
logging.getLogger().setLevel(logging.INFO)

# Buffer logs for batch writing
handler = logging.handlers.MemoryHandler(capacity=1000)
```

### 7. Module Selection

```python
from mobscan.core.config import MobscanConfig

config = MobscanConfig.default_config()

# Fast scan: Only SAST
config.modules_enabled = ["sast"]
# ~5 minutes

# Standard scan
config.modules_enabled = ["sast", "sca"]
# ~15 minutes

# Full scan: All modules
config.modules_enabled = ["sast", "dast", "frida", "sca"]
# ~60+ minutes
```

### Benchmarking

```bash
# Measure scan time
time mobscan scan app.apk --intensity quick

# Profile execution
python -m cProfile -s cumulative mobscan/cli.py scan app.apk

# Memory profiling
python -m memory_profiler mobscan/core/engine.py
```

---

## Security Hardening

### 1. API Security

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthCredential
from fastapi_limiter import FastAPILimiter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization"],
)

# Trusted hosts only
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["mobscan.example.com"],
)

# Rate limiting
@FastAPILimiter.limit("100/minute")
async def scan(request):
    pass

# Security headers
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

### 2. Authentication & Authorization

```python
from jwt import encode, decode, ExpiredSignatureError
from datetime import datetime, timedelta
import secrets

# JWT Token Management
def create_access_token(user_id: str, expires_delta: timedelta = None):
    if expires_delta is None:
        expires_delta = timedelta(hours=1)

    expire = datetime.utcnow() + expires_delta
    payload = {"user_id": user_id, "exp": expire}
    token = encode(payload, "secret-key", algorithm="HS256")
    return token

def verify_token(token: str) -> str:
    try:
        payload = decode(token, "secret-key", algorithms=["HS256"])
        return payload.get("user_id")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")

# API Key management
def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

# Use API key in requests
headers = {"X-API-Key": api_key}
```

### 3. Data Protection

```python
from cryptography.fernet import Fernet
import os

# Encrypt sensitive data
def encrypt_data(data: str, key: bytes) -> str:
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data.encode()).decode()

# Store encryption key securely
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    raise ValueError("ENCRYPTION_KEY not set")

# Encrypt sensitive values in cache
sensitive_data = {"api_key": "secret123"}
encrypted = encrypt_data(json.dumps(sensitive_data), encryption_key.encode())
cache.set("sensitive:key1", encrypted)

# Decrypt when needed
decrypted = decrypt_data(cache.get("sensitive:key1"), encryption_key.encode())
```

### 4. Audit Logging

```python
from mobscan.utils.logger import set_log_context
from datetime import datetime

def audit_log(action: str, user: str, resource: str, result: str, **kwargs):
    """Log security-relevant actions"""
    set_log_context(
        audit=True,
        action=action,
        user=user,
        resource=resource,
        result=result,
        timestamp=datetime.utcnow().isoformat(),
        **kwargs
    )

    logger.info(f"[AUDIT] {action} by {user} on {resource}: {result}")

# Usage examples
audit_log(
    action="scan_created",
    user="admin@example.com",
    resource="app123",
    result="success",
    intensity="full"
)

audit_log(
    action="auth_failed",
    user="unknown",
    resource="api",
    result="failure",
    reason="invalid_token"
)

audit_log(
    action="data_exported",
    user="analyst@example.com",
    resource="scan_123",
    result="success",
    format="pdf"
)
```

### 5. Secrets Management

```bash
# Never commit secrets
echo ".env" >> .gitignore
echo "secrets/" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

# Use environment variables
export MOBSF_API_KEY="key_from_vault"
export REDIS_PASSWORD="password_from_vault"
export DATABASE_URL="postgresql://user:pass@host/db"

# Or use a secrets manager
# HashiCorp Vault
# AWS Secrets Manager
# Google Cloud Secret Manager
# Azure Key Vault
```

**Using HashiCorp Vault**:
```python
import hvac

client = hvac.Client(url='http://127.0.0.1:8200', token='your-token')

# Read secret
secret = client.secrets.kv.read_secret_version(
    path='mobscan/prod/api_key'
)
api_key = secret['data']['data']['key']

# Read database password
db_secret = client.secrets.kv.read_secret_version(
    path='mobscan/prod/database'
)
db_password = db_secret['data']['data']['password']
```

### 6. Network Security

```python
# TLS/SSL Configuration
config = {
    "ssl_enabled": True,
    "ssl_cert_path": "/path/to/cert.pem",
    "ssl_key_path": "/path/to/key.pem",
    "ssl_verify": True,
    "tls_version": "TLSv1.2",
}

# Proxy settings with verification
proxy_settings = {
    "https_only": True,
    "verify_ssl": True,
    "cert_path": "/path/to/ca-bundle.crt",
}
```

### 7. Input Validation & Sanitization

```python
from pydantic import BaseModel, validator, constr
import re

class ScanRequest(BaseModel):
    app_path: constr(regex="^[a-zA-Z0-9._/-]+\.apk$")  # Whitelist pattern
    intensity: str

    @validator('intensity')
    def validate_intensity(cls, v):
        allowed = ["quick", "standard", "full"]
        if v not in allowed:
            raise ValueError(f"Intensity must be one of {allowed}")
        return v

# Sanitize file paths
import os
from pathlib import Path

def safe_file_path(user_input: str, base_path: str) -> str:
    """Resolve file path safely, preventing directory traversal"""
    requested_path = Path(user_input).resolve()
    base = Path(base_path).resolve()

    # Ensure requested path is within base path
    try:
        requested_path.relative_to(base)
    except ValueError:
        raise ValueError("Access denied: path traversal detected")

    return str(requested_path)
```

---

## Best Practices

### 1. Development Environment

```bash
# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or venv\Scripts\activate  # Windows

# Install dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # pytest, black, etc

# Pre-commit hooks for code quality
pip install pre-commit
pre-commit install
```

### 2. Configuration Management

```python
from dotenv import load_dotenv
import os

# Load from .env file
load_dotenv()

# Get configuration with defaults
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")

# Never hardcode secrets
# SECRET_KEY = "hardcoded"  # WRONG!
SECRET_KEY = os.getenv("SECRET_KEY")  # RIGHT
```

### 3. Error Handling

```python
from mobscan.utils.logger import get_logger

logger = get_logger(__name__)

try:
    result = perform_scan("app.apk")
except FileNotFoundError as e:
    logger.error(f"APK file not found: {e}", extra={"error_type": "FILE_NOT_FOUND"})
    raise
except TimeoutError as e:
    logger.warning(f"Scan timed out: {e}")
    # Graceful degradation
except Exception as e:
    logger.exception(f"Unexpected error during scan: {e}")
    raise
```

### 4. Testing Strategy

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# E2E tests
pytest tests/integration/test_e2e_workflow.py -v

# Coverage report
pytest --cov=mobscan tests/

# Specific test
pytest tests/integration/test_e2e_workflow.py::TestCachingWorkflow -v
```

### 5. Monitoring & Alerting

```python
# Health check endpoint
@app.get("/health")
async def health_check():
    cache_ok = cache.get_stats()["connected"]
    redis_ok = cache.is_connected()

    return {
        "status": "ok" if cache_ok and redis_ok else "degraded",
        "cache": "ok" if cache_ok else "error",
        "redis": "ok" if redis_ok else "error",
    }

# Prometheus metrics endpoint
@app.get("/metrics")
async def metrics():
    from mobscan.utils.metrics import export_metrics
    return Response(content=export_metrics(), media_type="text/plain")
```

---

## Conclusion

This advanced guide covers critical aspects of troubleshooting, performance optimization, and security hardening for Mobscan v1.1.0. Implement these practices to ensure a robust, secure, and high-performing mobile security testing framework.

For additional support:
- GitHub Issues: https://github.com/GhostN3xus/Mobscan/issues
- Documentation: https://mobscan.readthedocs.io/
- Community: https://github.com/GhostN3xus/Mobscan/discussions

---

**Last Updated**: 2025-11-29
**Version**: 1.1.0
