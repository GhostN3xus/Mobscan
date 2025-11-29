# 📖 Mobscan Usage Guide

Complete guide for using Mobscan - OWASP MASTG Automated Mobile Security Testing Framework.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Usage](#advanced-usage)
5. [Configuration](#configuration)
6. [Custom Rules](#custom-rules)
7. [CI/CD Integration](#cicd-integration)
8. [API Usage](#api-usage)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

## Quick Start

### Basic Scan

```bash
# Scan an Android APK
mobscan scan /path/to/app.apk

# Scan an iOS IPA
mobscan scan /path/to/app.ipa --platform ios

# Scan with specific output format
mobscan scan app.apk --format pdf,json,html
```

### View Results

```bash
# Results are saved to ./reports by default
ls reports/

# View JSON results
cat reports/report.json | jq

# Open HTML dashboard
open reports/report.html
```

---

## Installation

### Using pip

```bash
pip install -r requirements.txt
python setup.py install
```

### Using Docker

```bash
docker build -t mobscan:latest .
docker run -v $(pwd)/apps:/apps -v $(pwd)/reports:/reports mobscan scan /apps/app.apk
```

### Development Mode

```bash
git clone https://github.com/yourusername/mobscan.git
cd mobscan
pip install -e .
```

---

## Basic Usage

### Command-Line Interface

#### 1. Scan Command

```bash
mobscan scan [OPTIONS] APP_PATH
```

**Options:**

- `--platform` - Target platform (android/ios)
- `--output-dir, -o` - Output directory for reports
- `--format, -f` - Report formats (json, pdf, docx, markdown, html)
- `--intensity` - Scan intensity (quick, standard, full, comprehensive)
- `--masvs-level` - MASVS levels to check (L1, L2, R)
- `--parallel` - Number of parallel workers
- `--timeout` - Global timeout in seconds
- `--config` - Configuration file (YAML/JSON)
- `--verbose, -v` - Verbose output

**Examples:**

```bash
# Quick scan
mobscan scan app.apk --intensity quick

# Full scan with PDF and JSON reports
mobscan scan app.apk --intensity full --format pdf,json

# Scan with custom configuration
mobscan scan app.apk --config scan_config.yaml

# Scan with MASVS L2 compliance check
mobscan scan app.apk --masvs-level L2 --intensity comprehensive
```

#### 2. API Command

Start REST API server:

```bash
mobscan api --port 8000 --host 0.0.0.0
```

#### 3. Interactive Command

Start web dashboard:

```bash
mobscan interactive --port 8000
```

#### 4. Init Command

Initialize Mobscan environment:

```bash
mobscan init --install-deps --setup-docker
```

#### 5. Validate Command

Validate application file:

```bash
mobscan validate app.apk
```

---

## Advanced Usage

### Using Configuration Files

Create `scan_config.yaml`:

```yaml
scan:
  intensity: full
  modules:
    - sast
    - dast
    - frida
    - sca
  formats:
    - json
    - pdf

platforms:
  android:
    emulator:
      enabled: true
      api_level: 30

tools:
  mobsf:
    enabled: true
    url: http://localhost:8000
  frida:
    enabled: true
    custom_scripts:
      - ./hooks/ssl_bypass.js
```

Run with config:

```bash
mobscan scan app.apk --config scan_config.yaml
```

### Module-Specific Scans

#### SAST Only

```bash
mobscan scan app.apk --modules sast --intensity full
```

#### DAST Only

```bash
mobscan scan app.apk --modules dast --proxy localhost:8080
```

#### Frida Instrumentation

```bash
mobscan scan app.apk --modules frida --script-dir ./custom_scripts
```

#### SCA (Software Composition Analysis)

```bash
mobscan scan app.apk --modules sca --check-vulnerabilities
```

### Parallel Execution

```bash
# Run with 8 parallel workers
mobscan scan app.apk --parallel 8 --intensity comprehensive
```

### Custom Timeouts

```bash
# Set global timeout to 1 hour
mobscan scan app.apk --timeout 3600
```

---

## Configuration

### Environment Variables

Create `.env` file:

```bash
# API Keys
MOBSF_API_KEY=your_api_key_here
BURP_API_KEY=your_burp_key_here

# Paths
ANDROID_SDK_ROOT=/opt/android-sdk
JAVA_HOME=/usr/lib/jvm/java-11

# Tool URLs
MOBSF_URL=http://localhost:8000
FRIDA_SERVER=http://localhost:27042

# Logging
LOG_LEVEL=INFO
LOG_FILE=./mobscan.log

# Database
DATABASE_URL=sqlite:///./mobscan.db
```

### Configuration File Structure

See `mobscan/examples/sample_scans/sample_scan_config.yaml` for complete example.

**Key sections:**

1. **scan** - Basic scan settings
2. **platforms** - Platform-specific settings
3. **tools** - External tool configurations
4. **sast** - Static analysis settings
5. **dast** - Dynamic analysis settings
6. **reporting** - Report customization
7. **advanced** - Advanced options

---

## Custom Rules

### Creating Custom Security Rules

Create `custom_rules.yaml`:

```yaml
rules:
  - id: CUSTOM-001
    name: Hardcoded API Keys
    severity: critical
    category: MASTG-STORAGE-2
    description: Detects hardcoded API keys

    patterns:
      - type: regex
        pattern: 'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']'

    remediation: Store API keys securely using Keystore/Keychain

    cvss_score: 9.1
    cwe: ["CWE-798"]
    masvs: ["MSTG-STORAGE-14"]
```

Use custom rules:

```bash
mobscan scan app.apk --custom-rules ./custom_rules.yaml
```

See `mobscan/examples/custom_rules/example_custom_rule.yaml` for more examples.

---

## CI/CD Integration

### GitHub Actions

`.github/workflows/mobscan.yml`:

```yaml
name: Mobile Security Scan

on: [push, pull_request]

jobs:
  mobscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'

      - name: Install Mobscan
        run: |
          pip install -r requirements.txt
          python setup.py install

      - name: Run Security Scan
        run: |
          mobscan scan ./app/build/outputs/apk/release/app.apk \
            --output-dir ./reports \
            --format json,html \
            --intensity full \
            --fail-on critical,high

      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### GitLab CI

`.gitlab-ci.yml`:

```yaml
stages:
  - security

mobscan_scan:
  stage: security
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - python setup.py install
    - mobscan scan app.apk --output reports/ --format json,pdf
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

### Jenkins

`Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        pip install -r requirements.txt
                        python setup.py install
                        mobscan scan app.apk --output reports/ --format json,html
                    '''
                }
            }
        }

        stage('Publish Reports') {
            steps {
                publishHTML([
                    reportDir: 'reports',
                    reportFiles: 'report.html',
                    reportName: 'Mobscan Security Report'
                ])
            }
        }
    }
}
```

---

## API Usage

### Starting the API Server

```bash
mobscan api --port 8000 --host 0.0.0.0
```

### API Endpoints

#### Submit Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -F "file=@app.apk" \
  -F "intensity=full" \
  -F "formats=pdf,json"
```

#### Get Scan Status

```bash
curl http://localhost:8000/api/v1/scans/{scan_id}
```

#### Download Report

```bash
curl http://localhost:8000/api/v1/scans/{scan_id}/report?format=pdf \
  --output report.pdf
```

#### List All Scans

```bash
curl http://localhost:8000/api/v1/scans
```

### Python API

```python
from mobscan.core.engine import TestEngine
from mobscan.core.config import MobscanConfig, ScanIntensity

# Create configuration
config = MobscanConfig.default_config()
config.scan_intensity = ScanIntensity.FULL
config.parallel_workers = 4

# Initialize engine
engine = TestEngine(config)

# Run scan
engine.initialize_scan("/path/to/app.apk", "my_app")
result = engine.execute_tests()

# Generate report
report = engine.generate_report("json")

# Get statistics
stats = engine.get_scan_statistics()
print(f"Total findings: {stats['total_findings']}")
```

---

## Troubleshooting

### Common Issues

#### 1. APK/IPA Not Found

```
Error: File not found: app.apk
```

**Solution:** Verify file path is correct and accessible.

#### 2. Permission Denied

```
Error: Permission denied: /path/to/app.apk
```

**Solution:** Check file permissions:

```bash
chmod +r app.apk
```

#### 3. MobSF Connection Error

```
Error: Unable to connect to MobSF
```

**Solution:** Ensure MobSF is running:

```bash
docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

#### 4. Frida Server Not Found

```
Error: Frida server not responding
```

**Solution:** Start Frida server on device/emulator:

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

#### 5. Insufficient Memory

```
Error: Out of memory
```

**Solution:** Increase memory limit:

```bash
mobscan scan app.apk --memory-limit 8G
```

### Debug Mode

Enable verbose logging:

```bash
mobscan scan app.apk --verbose --log-level DEBUG
```

View logs:

```bash
tail -f mobscan.log
```

---

## Best Practices

### 1. Security Scan Strategy

**Development:**

```bash
mobscan scan app.apk --intensity quick --modules sast,sca
```

**Pre-Production:**

```bash
mobscan scan app.apk --intensity full --modules sast,dast,sca
```

**Production Release:**

```bash
mobscan scan app.apk \
  --intensity comprehensive \
  --modules sast,dast,frida,sca \
  --masvs-level L1,L2 \
  --fail-on critical,high
```

### 2. Report Organization

```bash
# Organize reports by version
mobscan scan app.apk --output reports/v1.2.3/

# Include build metadata
mobscan scan app.apk \
  --output reports/build-$(date +%Y%m%d-%H%M%S)/ \
  --format json,pdf,html
```

### 3. Continuous Monitoring

Schedule regular scans:

```bash
# Daily scan (cron)
0 2 * * * cd /path/to/project && mobscan scan latest.apk --output daily-scan/
```

### 4. Team Collaboration

```bash
# Generate shareable reports
mobscan scan app.apk \
  --format pdf,html \
  --include-evidence \
  --company-name "Your Company" \
  --logo ./logo.png
```

### 5. Incremental Scanning

```bash
# Use caching for faster rescans
mobscan scan app.apk --use-cache --cache-ttl 3600
```

---

## Additional Resources

- **Documentation:** https://mobscan.readthedocs.io
- **OWASP MASTG:** https://mas.owasp.org/MASTG/
- **OWASP MASVS:** https://mas.owasp.org/MASVS/
- **Issues:** https://github.com/mobscan/issues
- **Discord:** https://discord.gg/mobscan

---

**Need Help?**

- Report bugs: https://github.com/mobscan/issues
- Contact: security@mobscan.dev
- Community: https://discord.gg/mobscan
