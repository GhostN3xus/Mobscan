# 🔒 Mobscan - OWASP MASTG Automated Mobile Security Testing Framework

**Enterprise-grade, fully automated mobile application security testing framework** for Android and iOS aligned with OWASP MASTG standards.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Usage Guide](#usage-guide)
- [Testing Coverage](#testing-coverage)
- [Reports](#reports)
- [CI/CD Integration](#cicd-integration)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**Mobscan** is an automated, end-to-end mobile application security testing platform designed for:

- **Security Teams**: Perform comprehensive pentesting against OWASP MASTG standards
- **DevSecOps**: Integrate security testing into CI/CD pipelines
- **AppSec Engineers**: Generate detailed technical and executive reports
- **Mobile Development Teams**: Identify and remediate security vulnerabilities

### 🎖️ Standards Compliance

- ✅ **OWASP MASTG** (Mobile Application Security Testing Guide)
- ✅ **OWASP MASVS** (Mobile Application Security Verification Standard) L1, L2, R
- ✅ **CVSS v3.1** vulnerability scoring
- ✅ **CWE** (Common Weakness Enumeration) mapping
- ✅ **OWASP Top 10 Mobile**

---

## ✨ Key Features

### 🔍 Testing Capabilities

| Category | Coverage | Automation |
|----------|----------|-----------|
| **MASTG-ARCH** | Architecture & Design | 85% |
| **MASTG-STORAGE** | Local Data Storage | 95% |
| **MASTG-CRYPTO** | Cryptography | 90% |
| **MASTG-AUTH** | Authentication & Sessions | 88% |
| **MASTG-NET** | Network Communication | 92% |
| **MASTG-PLATFORM** | Platform APIs & IPC | 87% |
| **MASTG-RESILIENCE** | Jailbreak/Root Detection | 90% |
| **MASTG-CODE** | Code Quality & Reversibility | 85% |
| **MASTG-RE** | Reverse Engineering Resilience | 80% |

### 🛠️ Integrated Tools

- **MobSF** - Mobile Security Framework for SAST
- **Frida** - Dynamic instrumentation
- **Objection** - Runtime exploitation
- **JADX** - Bytecode decompiler
- **Ghidra** - Binary analysis
- **Radare2** - Advanced reverse engineering
- **mitmproxy** - MITM and traffic analysis
- **Burp Suite Mobile Assistant** - API testing
- **apktool** - APK reverse engineering
- **drozer** - IPC fuzzing

### 📊 Report Generation

- **Technical Reports**: PDF, DOCX, Markdown with detailed findings
- **Executive Reports**: Risk summary with visual indicators
- **JSON Export**: Structured data for integrations
- **Dashboard**: Real-time testing status and metrics

### 🚀 Automation Features

- **Parallel Test Execution**: Run multiple test suites simultaneously
- **Container-based**: Docker support for isolated environments
- **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **Incremental Scanning**: Smart caching for faster retesting
- **AI-assisted Analysis**: Intelligent finding categorization (optional)
- **Automatic Frida Scripts**: Dynamic payload generation

### 📈 Advanced Features

- **MASVS-Gap Analysis**: Compliance scoring against L1/L2/R
- **Historical Tracking**: Trend analysis and benchmark comparison
- **Remediation Guidance**: Context-aware fix recommendations
- **Batch Testing**: Process multiple apps in one pipeline run
- **Custom Test Rules**: Extensible testing framework
- **Finding Deduplication**: Smart vulnerability consolidation

---

## 🏗️ Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     API REST Layer                       │
│          (Flask/FastAPI + Authentication)                │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────────────┐
│                  Orchestration Engine                    │
│     (Test Planning, Sequencing, Dependency Mgmt)         │
└──┬──────────────┬──────────────┬───────────────────┬────┘
   │              │              │                   │
┌──▼──┐    ┌─────▼─────┐   ┌────▼─────┐    ┌──────▼──────┐
│SAST │    │    DAST   │   │ Frida    │    │ Report Gen  │
│Mod  │    │   Module  │   │ Module   │    │   Module    │
├─────┤    ├───────────┤   ├──────────┤    ├─────────────┤
│MobSF│    │API Tests  │   │Instrumen-│    │PDF/DOCX/MD/ │
│JADX │    │MITM Tests │   │ tation   │    │JSON/HTML    │
│Ghidra   │Cert Pin   │   │Bypass    │    │Dashboard    │
└─────┘    │Crypto     │   │Exploits  │    └─────────────┘
           └───────────┘   └──────────┘
```

### Module Breakdown

#### 1. **SAST Module** (Static Analysis)
- APK/IPA decompilation and analysis
- Hardcoded secrets detection
- Insecure API usage patterns
- Vulnerable dependencies
- Code quality metrics

#### 2. **DAST Module** (Dynamic Analysis)
- API endpoint discovery and testing
- Authentication mechanism testing
- Session management testing
- Network traffic analysis
- Certificate pinning validation

#### 3. **Instrumentation Module**
- Frida hook generation
- Runtime object inspection
- Method hooking and monitoring
- Memory analysis
- Bypass script execution

#### 4. **Integration Layer**
- Tool orchestration
- Result aggregation
- Finding deduplication
- MASVS mapping

#### 5. **Reporting Module**
- Multi-format export
- Vulnerability prioritization
- CVSS/CWE calculation
- Remediation suggestions
- Executive summaries

---

## 📦 Installation

### Requirements

- **Python 3.10+**
- **Docker** (recommended for tool isolation)
- **Android SDK** (for APK analysis)
- **Node.js 16+** (for some tools)
- **Java 11+** (for decompilers)

### Quick Installation

```bash
# Clone repository
git clone https://github.com/GhostN3xus/Mobscan.git
cd mobscan

# Install with dependencies
pip install -r requirements.txt

# Install optional tools (Docker-based)
./scripts/install_tools.sh

# Run setup wizard
python mobscan/cli.py init

# Verify installation
python mobscan/cli.py --version
```

### Docker Installation

```bash
docker build -t mobscan:latest .
docker run -it --rm \
  -v $(pwd)/apps:/apps \
  -v $(pwd)/reports:/reports \
  mobscan:latest mobscan scan /apps/app.apk
```

---

## 🚀 Quick Start

### Scan an APK

```bash
mobscan scan /path/to/app.apk \
  --output /path/to/reports \
  --format pdf,json \
  --intensity full \
  --parallel 4
```

### Scan an IPA

```bash
mobscan scan /path/to/app.ipa \
  --platform ios \
  --output /path/to/reports \
  --masvs-level L2
```

### Interactive Mode

```bash
mobscan interactive
# Opens web dashboard at http://localhost:8000
```

### API Usage

```bash
# Start API server
mobscan api --port 8000

# Submit scan
curl -X POST http://localhost:8000/api/v1/scans \
  -F "file=@app.apk" \
  -F "intensity=full" \
  -F "formats=pdf,json"
```

---

## 📁 Project Structure

```
mobscan/
├── mobscan/
│   ├── __init__.py
│   ├── cli.py                    # CLI entry point
│   ├── api/                      # REST API
│   │   ├── app.py
│   │   ├── routes/
│   │   │   ├── scans.py
│   │   │   ├── reports.py
│   │   │   └── results.py
│   │   └── models/
│   ├── core/                     # Core orchestration
│   │   ├── engine.py             # Test orchestrator
│   │   ├── pipeline.py           # Pipeline management
│   │   └── config.py             # Configuration
│   ├── modules/                  # Test modules
│   │   ├── sast/                 # Static analysis
│   │   │   ├── mobsf.py
│   │   │   ├── jadx.py
│   │   │   ├── secrets.py
│   │   │   └── dependencies.py
│   │   ├── dast/                 # Dynamic analysis
│   │   │   ├── api_tester.py
│   │   │   ├── mitm.py
│   │   │   ├── cert_pinning.py
│   │   │   └── auth_tester.py
│   │   ├── frida/                # Instrumentation
│   │   │   ├── hooks.py
│   │   │   ├── payload_generator.py
│   │   │   └── scripts/
│   │   └── integration/          # Tools integration
│   │       ├── tool_manager.py
│   │       └── tools/
│   ├── mastg/                    # MASTG reference
│   │   ├── architecture.py
│   │   ├── storage.py
│   │   ├── crypto.py
│   │   ├── authentication.py
│   │   ├── network.py
│   │   ├── platform.py
│   │   ├── resilience.py
│   │   ├── code_quality.py
│   │   └── reverse_engineering.py
│   ├── reports/                  # Report generation
│   │   ├── generator.py
│   │   ├── templates/
│   │   │   ├── technical.html
│   │   │   ├── executive.html
│   │   │   └── dashboard.html
│   │   └── exporters/
│   │       ├── pdf.py
│   │       ├── docx.py
│   │       ├── json.py
│   │       └── markdown.py
│   ├── utils/                    # Utilities
│   │   ├── logger.py
│   │   ├── validators.py
│   │   ├── adb.py
│   │   ├── package_extractor.py
│   │   └── helpers.py
│   └── models/                   # Data models
│       ├── finding.py
│       ├── scan_result.py
│       └── masvs_mapping.py
├── scripts/
│   ├── install_tools.sh
│   ├── setup_environment.sh
│   ├── generate_frida_scripts.py
│   └── ci_integration/
├── pipelines/
│   ├── github_actions.yaml
│   ├── gitlab_ci.yaml
│   ├── jenkinsfile
│   └── azure_devops.yaml
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yaml
│   └── entrypoint.sh
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── MASTG_COVERAGE.md
│   ├── API_DOCUMENTATION.md
│   └── INSTALLATION.md
├── examples/
│   ├── sample_scans/
│   └── custom_rules/
├── requirements.txt
├── setup.py
├── Dockerfile
├── docker-compose.yaml
└── .gitignore
```

---

## 📖 Usage Guide

### Basic Scan

```bash
mobscan scan /path/to/app.apk
```

### Advanced Scan with Options

```bash
mobscan scan app.apk \
  --platform android \
  --output-dir ./reports \
  --format pdf,json,html \
  --masvs-level L2 \
  --intensity full \
  --parallel 6 \
  --timeout 3600 \
  --modules sast,dast,frida \
  --skip-tools mobsf \
  --custom-rules ./rules.yaml
```

### Configuration File

```bash
mobscan scan app.apk --config scan_config.yaml
```

**scan_config.yaml**:
```yaml
scan:
  intensity: full
  modules:
    - sast
    - dast
    - frida
  format: [pdf, json]

platforms:
  android:
    emulator: true
    api_level: 30

tools:
  mobsf: enabled
  frida: enabled
  burp: disabled

reporting:
  include_evidence: true
  masvs_levels: [L1, L2]
```

---

## 🧪 Testing Coverage

### MASTG Categories Coverage

| Category | Test Count | Tools | Examples |
|----------|-----------|-------|----------|
| **MASTG-ARCH-1** | 8 | MobSF, JADX | Identify architecture, data flow |
| **MASTG-STORAGE-1** | 12 | Frida, Objection | Shared preferences, keychain |
| **MASTG-CRYPTO-1** | 15 | Ghidra, Radare2 | Weak crypto, key management |
| **MASTG-AUTH-1** | 10 | API Tester, DAST | Bypass, session fixation |
| **MASTG-NET-1** | 14 | mitmproxy, Burp | Certificate pinning, TLS |
| **MASTG-PLATFORM-1** | 11 | ADB, Frida | IPC flaws, permission abuse |
| **MASTG-RESILIENCE-1** | 9 | Frida, Objection | Root/jailbreak bypass |
| **MASTG-CODE-1** | 13 | JADX, Ghidra | Reversibility, symbols |
| **MASTG-RE-1** | 8 | Radare2, Ghidra | Anti-reversing techniques |

**Total Tests**: 100+ automated tests per app

---

## 📊 Reports

### Technical Report Sections

1. **Executive Summary**
   - Risk score (0-10)
   - Critical/High/Medium/Low findings count
   - MASVS compliance level

2. **Detailed Findings**
   - Title, description, severity
   - CVSS score, CWE, OWASP reference
   - Affected code location
   - Step-by-step exploitation
   - Screenshots/evidence

3. **Test Evidence**
   - Logs from each tool
   - API requests/responses
   - Frida hook outputs
   - Network captures

4. **Remediation**
   - Code fixes
   - Architecture changes
   - Configuration hardening
   - Security best practices

### Report Export

```bash
# Auto-generate all formats
mobscan report generate --scan-id abc123 --all-formats

# Specific formats
mobscan report pdf --scan-id abc123 --output report.pdf
mobscan report docx --scan-id abc123 --output report.docx
mobscan report json --scan-id abc123 --output report.json
mobscan report markdown --scan-id abc123 --output report.md
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Mobile Security Scan
on: [push, pull_request]

jobs:
  mobscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Mobscan
        uses: mobscan-action@v1
        with:
          app-path: ./builds/app.apk
          format: json,pdf
          masvs-level: L2

      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### GitLab CI

```yaml
mobscan_scan:
  image: mobscan:latest
  script:
    - mobscan scan ./app.apk --output reports/ --format pdf,json
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## 📄 License

MIT License - See LICENSE file for details

---

## 📞 Support & Contact

- **Documentation**: https://mobscan.readthedocs.io
- **Issues**: https://github.com/mobscan/issues
- **Discord**: https://discord.gg/mobscan
- **Email**: security@mobscan.dev

---

**Made with ❤️ for mobile security professionals**
