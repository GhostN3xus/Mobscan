# Installation Guide

## Prerequisites

- **Python 3.10+**
- **Docker & Docker Compose** (recommended for tools isolation)
- **Java 11+** (for decompilers)
- **Node.js 16+** (optional, for some tools)
- **Git** (for version control)

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Linux, macOS, or Windows (WSL2) |
| RAM | 8GB minimum (16GB recommended) |
| Storage | 50GB free space |
| CPU | Multi-core processor (4+ cores recommended) |

---

## Installation Methods

### 1. Local Installation (Python Virtual Environment)

#### Step 1: Clone Repository

```bash
git clone https://github.com/GhostN3xus/Mobscan.git
cd Mobscan
```

#### Step 2: Create Virtual Environment

```bash
# Linux/macOS
python3.11 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

#### Step 3: Install Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

#### Step 4: Install Mobscan

```bash
pip install -e .
```

#### Step 5: Verify Installation

```bash
mobscan --version
mobscan --help
```

---

### 2. Docker Installation

#### Option A: Using Docker Image

```bash
# Build Docker image
docker build -t mobscan:latest .

# Run container
docker run -it --rm \
  -v $(pwd)/apps:/apps \
  -v $(pwd)/reports:/reports \
  mobscan:latest \
  mobscan scan /apps/app.apk
```

#### Option B: Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f mobscan-api

# Stop services
docker-compose down
```

**Services included:**
- mobscan-api: Main API server (port 8000)
- redis: Cache (port 6379)
- postgres: Database (port 5432)
- mobsf: Static analysis (port 8001)
- mitmproxy: MITM proxy (port 8080)
- nginx: Reverse proxy (port 80)

---

### 3. Development Installation

For developers wanting to contribute:

```bash
# Clone and setup
git clone https://github.com/GhostN3xus/Mobscan.git
cd Mobscan
python -m venv venv
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
pytest tests/ -v

# Check code quality
black mobscan/
flake8 mobscan/
mypy mobscan/
```

---

## Tool Installation

### Android SDK (Optional but Recommended)

```bash
# Ubuntu/Debian
sudo apt-get install android-sdk

# macOS
brew install android-sdk

# Windows
# Download from: https://developer.android.com/studio
```

### Additional Tools

#### Frida & Objection

```bash
pip install frida frida-tools
pip install objection
```

#### JADX

```bash
# Download from: https://github.com/skylot/jadx/releases
# Extract and add to PATH
export PATH=$PATH:/path/to/jadx/bin
```

#### Ghidra

```bash
# Download from: https://ghidra-sre.org/
# Extract and configure
export GHIDRA_HOME=/path/to/ghidra
```

#### MobSF (Docker)

```bash
docker pull mobsf/mobsf:latest
```

---

## Configuration

### 1. Basic Configuration

Create `config.yaml`:

```yaml
scan:
  intensity: full
  parallel_workers: 4
  timeout_global: 7200

modules:
  - sast
  - dast
  - frida

tools:
  mobsf:
    enabled: true
    docker_image: mobsf/mobsf:latest
  frida:
    enabled: true
    version: 16.0.0

reporting:
  formats: [json, pdf, markdown]
  output_directory: ./reports
  masvs_levels: [L1, L2]
```

### 2. Environment Variables

```bash
# Create .env file
export MOBSCAN_LOG_LEVEL=INFO
export MOBSCAN_DATABASE_URL=postgresql://user:password@localhost/mobscan
export MOBSCAN_REDIS_URL=redis://localhost:6379
export MOBSCAN_API_KEY=your_api_key_here
export MOBSCAN_PARALLEL_WORKERS=4
```

### 3. API Configuration

For API server, create `.env`:

```bash
# Server
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Database
DATABASE_URL=postgresql://mobscan:password@localhost:5432/mobscan

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
JWT_SECRET=your_secret_key_here
API_KEY=your_api_key_here

# Logging
LOG_LEVEL=INFO
```

---

## Quick Start

### Command Line Usage

```bash
# Basic scan
mobscan scan /path/to/app.apk

# Full scan with options
mobscan scan app.apk \
  --platform android \
  --output-dir ./reports \
  --format pdf,json,markdown \
  --intensity full \
  --masvs-level L1 L2 \
  --parallel 4 \
  --timeout 3600 \
  --verbose

# Interactive mode (web dashboard)
mobscan interactive --port 8000

# Start API server
mobscan api --port 8000
```

### Python API Usage

```python
from mobscan.core.engine import TestEngine
from mobscan.core.config import MobscanConfig

# Create engine
config = MobscanConfig.default_config()
engine = TestEngine(config)

# Run scan
result = engine.initialize_scan("app.apk", "MyApp")
result = engine.execute_tests()

# Generate report
json_report = engine.generate_report("json")
pdf_report = engine.generate_report("pdf")
```

### REST API Usage

```bash
# Start API server
docker-compose up -d

# Submit scan
curl -X POST http://localhost:8000/api/v1/scans \
  -F "file=@app.apk" \
  -F "intensity=full" \
  -F "formats=pdf,json"

# Get results
curl http://localhost:8000/api/v1/scans/{scan_id}/result
```

---

## Troubleshooting

### Issue: Python version mismatch

```bash
# Check Python version
python --version  # Should be 3.10+

# Use explicit version
python3.11 -m venv venv
```

### Issue: Docker daemon not running

```bash
# Start Docker daemon
sudo systemctl start docker
docker --version  # Verify
```

### Issue: Permission denied errors

```bash
# Linux/macOS
chmod +x scripts/*.sh
sudo chown -R $USER:$USER .

# Windows (Run as Administrator)
```

### Issue: Module not found errors

```bash
# Reinstall package
pip install --force-reinstall -e .

# Check installation
python -c "import mobscan; print(mobscan.__version__)"
```

### Issue: Database connection errors

```bash
# Check database status
docker ps  # Verify postgres is running

# Check logs
docker-compose logs postgres

# Reset database
docker-compose down -v  # Remove volumes
docker-compose up -d    # Recreate
```

---

## Verification

### Test Installation

```bash
# Run unit tests
pytest tests/ -v

# Check imports
python -c "from mobscan.core.engine import TestEngine; print('OK')"

# Test CLI
mobscan --help
mobscan scan --help

# Test API
curl http://localhost:8000/health
```

---

## Next Steps

1. **Review Documentation**: Read [ARCHITECTURE.md](./ARCHITECTURE.md)
2. **Check Examples**: See [examples/](../examples/)
3. **Run Test Scan**: Use sample APK to verify setup
4. **Configure Tools**: Set up your preferred security tools
5. **Create Custom Rules**: Add organization-specific checks
6. **Integration**: Integrate with your CI/CD pipeline

---

## Support

- **Documentation**: https://mobscan.readthedocs.io
- **Issues**: https://github.com/GhostN3xus/Mobscan/issues
- **Discussions**: https://github.com/GhostN3xus/Mobscan/discussions

---

## Uninstallation

```bash
# Local installation
deactivate  # Deactivate venv
rm -rf venv/

# Docker
docker-compose down -v
docker rmi mobscan:latest

# Python package
pip uninstall mobscan
```
