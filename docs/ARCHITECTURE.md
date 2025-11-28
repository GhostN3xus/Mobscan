# Mobscan Enterprise Security Architecture

## Enterprise Mobile Security Automation Framework

Mobscan is an enterprise-grade mobile security automation framework built to rigorously follow OWASP MASTG (Mobile Application Security Testing Guide) and MASVS (Mobile Application Security Verification Standard).

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Analysis Pipeline](#analysis-pipeline)
4. [Modules](#modules)
5. [Integration](#integration)
6. [Standards & Compliance](#standards--compliance)
2. [High-Level Architecture](#high-level-architecture)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Module Architecture](#module-architecture)
6. [Integration Points](#integration-points)
7. [Deployment Architecture](#deployment-architecture)
8. [Security Considerations](#security-considerations)

---

## Overview

Mobscan is an enterprise-grade, distributed mobile application security testing framework designed to automate and orchestrate comprehensive security assessments of Android and iOS applications according to OWASP MASTG standards.

### Design Principles

- **Modularity**: Each component is independent and replaceable
- **Scalability**: Support for parallel test execution and distributed scanning
- **Extensibility**: Easy addition of new test modules and tools
- **Transparency**: Complete logging and audit trails
- **Resilience**: Fault tolerance and graceful degradation

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                            │
│  (CLI, Web Dashboard, API Clients, Mobile Apps)                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                      API GATEWAY LAYER                          │
│  (FastAPI/Flask, Authentication, Rate Limiting, Routing)        │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                  ORCHESTRATION ENGINE LAYER                     │
│  (Test Engine, Pipeline Manager, Workflow Coordinator)          │
└──┬──────────────────────┬──────────────────────┬────────────────┘
   │                      │                      │
   │                      │                      │
┌──▼──────┐      ┌─────────▼────────┐    ┌──────▼──────┐
│SAST     │      │    DAST          │    │  Frida/     │
│Module   │      │    Module        │    │  Instrument │
├─────────┤      ├──────────────────┤    ├─────────────┤
│• MobSF  │      │• API Testing     │    │• Hook Gen   │
│• JADX   │      │• MITM Proxy      │    │• Bypass     │
│• Ghidra │      │• Cert Pinning    │    │• Memory     │
│• Secrets│      │• Crypto Tests    │    │• Injection  │
└─────────┘      └──────────────────┘    └─────────────┘
   │                      │                      │
   └──────────────────────┼──────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                   DATA AGGREGATION LAYER                        │
│  (Finding Consolidation, Deduplication, MASVS Mapping)          │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                    REPORTING LAYER                              │
│  (PDF/DOCX/JSON/Markdown Generation, Dashboard)                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                   PERSISTENCE LAYER                             │
│  (Database, File Storage, Cache, Archives)                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. **API Layer** (`mobscan/api/`)

The REST API serves as the primary interface for Mobscan.

**Components:**
- `app.py`: Main FastAPI application
- `routes/`: Endpoint definitions
  - `scans.py`: Scan management endpoints
  - `reports.py`: Report generation endpoints
  - `results.py`: Result retrieval endpoints

**Key Endpoints:**
- `POST /api/v1/scans`: Submit new scan
- `GET /api/v1/scans/{id}/status`: Get scan status
- `GET /api/v1/scans/{id}/result`: Retrieve full results
- `GET /api/v1/reports/{id}`: Generate report

### 2. **Core Engine** (`mobscan/core/`)

The orchestration engine manages test execution.

**Components:**
- `config.py`: Configuration management
  - Tool configurations
  - Platform settings
  - Report generation options
  - Scan intensity levels

- `engine.py`: Main orchestrator
  - Test scheduling
  - Module coordination
  - Result aggregation
  - MASVS mapping

- `pipeline.py`: Test pipeline management
  - Dependency resolution
  - Parallel execution coordination
  - Error handling and recovery

### 3. **Test Modules** (`mobscan/modules/`)

Specialized modules for different testing approaches.

#### SAST Module (`modules/sast/`)

Static Application Security Testing

**Responsibilities:**
- APK/IPA decompilation
- Source code analysis
- Hardcoded secrets detection
- Vulnerable dependency identification
- Code quality metrics

**Tools Integrated:**
- MobSF (Mobile Security Framework)
- JADX (Bytecode decompiler)
- Ghidra (Binary analysis)
- Semgrep (Pattern-based SAST)

#### DAST Module (`modules/dast/`)

Dynamic Application Security Testing

**Responsibilities:**
- Runtime behavior analysis
- API endpoint testing
- Network traffic inspection
- Certificate pinning validation
- Authentication mechanism testing

**Tools Integrated:**
- mitmproxy
- Burp Suite Community
- Custom API tester
- Network traffic analyzer

#### Frida Module (`modules/frida/`)

Runtime Instrumentation and Hook-based Testing

**Responsibilities:**
- Dynamic instrumentation
- Method hooking and monitoring
- Memory inspection
- Bypass script execution
- Jailbreak/root detection testing

**Tools Integrated:**
- Frida
- Objection
- Custom Frida scripts
- Bypass payloads

### 4. **MASTG Reference** (`mobscan/mastg/`)

OWASP MASTG test case definitions and implementations.

**Categories:**
- `architecture.py`: MASTG-ARCH tests
- `storage.py`: MASTG-STORAGE tests
- `crypto.py`: MASTG-CRYPTO tests
- `authentication.py`: MASTG-AUTH tests
- `network.py`: MASTG-NET tests
- `platform.py`: MASTG-PLATFORM tests
- `resilience.py`: MASTG-RESILIENCE tests
- `code_quality.py`: MASTG-CODE tests
- `reverse_engineering.py`: MASTG-RE tests

### 5. **Models** (`mobscan/models/`)

Data models for the framework.

**Key Models:**
- `finding.py`: Security finding/vulnerability
- `scan_result.py`: Complete scan result
- `masvs_mapping.py`: MASTG-to-MASVS mapping

### 6. **Reporting** (`mobscan/reports/`)

Report generation and export.

**Components:**
- `generator.py`: Report generation engine
- `exporters/`:
  - `pdf.py`: PDF export
  - `docx.py`: DOCX export
  - `json.py`: JSON export
  - `markdown.py`: Markdown export

---

## Data Flow

### Scan Execution Flow

```
1. User submits app file
   ↓
2. API receives request
   ↓
3. File validation & extraction
   ↓
4. Scan initialization
   ↓
5. Test module loading
   ↓
6. Parallel test execution
   ├─ SAST tests
   ├─ DAST tests
   └─ Frida tests
   ↓
7. Finding consolidation
   ↓
8. Deduplication
   ↓
9. MASVS mapping
   ↓
10. Compliance calculation
    ↓
11. Report generation
    ↓
12. Result storage
    ↓
13. User notification
```

### Finding Flow

```
Raw Finding
    ↓
CVSS Calculation
    ↓
CWE Classification
    ↓
MASTG Mapping
    ↓
MASVS Requirement Association
    ↓
Evidence Collection
    ↓
Remediation Suggestion
    ↓
Stored Finding Object
```

---

## Module Architecture

### SAST Module Architecture

```
APK/IPA File
    ↓
┌─────────────────────────────────────┐
│  Package Extraction & Decompilation │
│  (apktool, jadx, CFR)               │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Static Analysis Engine             │
│  ├─ Bytecode Analysis               │
│  ├─ String Scanning                 │
│  ├─ Permission Analysis             │
│  └─ Manifest Analysis               │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Rule Engine                        │
│  ├─ Custom Rules                    │
│  ├─ OWASP Rules                     │
│  └─ CWE Rules                       │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Finding Generation                 │
│  (Severity, Impact, Evidence)       │
└─────────────────────────────────────┘
    ↓
Findings List
```

### DAST Module Architecture

```
App Running on Emulator/Device
    ↓
┌─────────────────────────────────────┐
│  Network Proxy Setup (mitmproxy)    │
│  ├─ Traffic Interception            │
│  ├─ Certificate Injection           │
│  └─ Request/Response Modification   │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Test Case Execution                │
│  ├─ Authentication Tests            │
│  ├─ API Endpoint Tests              │
│  ├─ Session Management Tests        │
│  └─ Data Validation Tests           │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Traffic Analysis                   │
│  ├─ Certificate Pinning Check       │
│  ├─ Encryption Validation           │
│  └─ Protocol Analysis               │
└─────────────────────────────────────┘
    ↓
Findings List
```

### Frida Module Architecture

```
Target App Running with Frida
    ↓
┌─────────────────────────────────────┐
│  Frida Script Generator             │
│  ├─ Hook Template Compilation       │
│  ├─ Payload Generation              │
│  └─ Bypass Script Creation          │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Instrumentation Engine             │
│  ├─ Method Hooking                  │
│  ├─ Call Interception               │
│  ├─ Return Value Modification       │
│  └─ Memory Inspection               │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Exploitation Tests                 │
│  ├─ Bypass Scripts                  │
│  ├─ Detection Evasion               │
│  └─ Control Flow Manipulation       │
└─────────────────────────────────────┘
    ↓
Findings List
```

---

## Integration Points

### Tool Integration Interface

All tools follow a common interface:

```python
class BaseToolAdapter:
    def initialize(self) -> bool
    def execute(self, app_path: str) -> List[Finding]
    def cleanup(self)
```

### External Systems

**API Integrations:**
- GitHub/GitLab for CI/CD
- Slack/Teams for notifications
- Security dashboards for reporting
- SIEM systems for aggregation

**Data Integrations:**
- Vulnerability databases (NVD, CVE, CWE)
- MASVS/MASTG reference data
- Custom compliance rules

---

## Deployment Architecture

### Local Development

```
developer machine
├── Python venv
├── Local tools (mobsf, frida)
└── SQLite database
```

### Docker Container

```
Docker Image
├── Python runtime
├── Pre-installed tools
├── Application code
└── Configuration
```

### Kubernetes Deployment

```
Kubernetes Cluster
├── mobscan-api (replica set)
├── postgres (stateful set)
├── redis (stateful set)
├── mitmproxy (daemon set)
└── Storage (persistent volumes)
```

### Distributed Architecture

```
Load Balancer
├── API Server 1
├── API Server 2
└── API Server N
    ├─ Shared Database (PostgreSQL)
    ├─ Shared Cache (Redis)
    └─ Shared Storage (S3/NFS)
```

---

## Security Considerations

### Data Protection

1. **In Transit**: All API communications use TLS/SSL
2. **At Rest**: Sensitive data encrypted in database
3. **In Memory**: Careful handling of credentials and tokens

### Access Control

- API authentication via JWT tokens
- Role-based access control (RBAC)
- Audit logging for all operations
- Rate limiting per user/IP

### Isolation

- Test execution in isolated containers
- Network segmentation between components
- Secrets management (environment variables, vaults)

### Compliance

- Audit trails for regulatory compliance
- Data retention policies
- GDPR/CCPA considerations for personal data

---

## Performance Optimization

### Caching Strategy

- SAST results cached (invalidated on app change)
- Tool outputs cached (4-hour TTL)
- MASTG reference data cached in memory

### Parallelization

- Multiple test suites run simultaneously
- Independent module execution
- Configurable worker pool size

### Resource Management

- Memory limits per container
- CPU throttling for resource constrained environments
- Automatic cleanup of temporary files

---

## Extensibility Points

### Adding New Tools

Create a tool adapter:
```python
class MyToolAdapter(BaseToolAdapter):
    def execute(self, app_path: str) -> List[Finding]:
        # Implementation
        pass
```

### Adding New Test Modules

Create a module:
```python
class MyTestModule(BaseModule):
    def run(self, app_info: ApplicationInfo) -> List[Finding]:
        # Implementation
        pass
```

### Custom Rules

Define YAML-based rules:
```yaml
rules:
  - id: custom-rule-1
    title: My Custom Rule
    pattern: "insecure_pattern"
    severity: HIGH
```

---

## Monitoring and Observability

### Logging

- Structured logging in JSON format
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Centralized log aggregation (ELK, Splunk)

### Metrics

- Test execution time
- Finding distribution by severity
- Tool success/failure rates
- API response times

### Tracing

- Request tracing across components
- Distributed tracing (Jaeger, Zipkin)
- Performance profiling

---

This architecture is designed to be flexible, scalable, and maintainable while providing comprehensive mobile application security testing capabilities aligned with OWASP MASTG standards.
