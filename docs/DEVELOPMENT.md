# Development Guide

This guide provides information for developers who want to contribute to the Mobscan project.

## Setting Up Development Environment

### Prerequisites

- Python 3.10+
- Git
- Docker & Docker Compose
- Virtual Environment Tool

### Initial Setup

```bash
# Clone repository
git clone https://github.com/GhostN3xus/Mobscan.git
cd Mobscan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

## Project Structure

```
Mobscan/
├── mobscan/                 # Main package
│   ├── api/                 # REST API
│   ├── core/                # Core engine
│   ├── models/              # Data models
│   ├── modules/             # Test modules
│   │   ├── sast/           # Static analysis
│   │   ├── dast/           # Dynamic analysis
│   │   └── frida/          # Instrumentation
│   ├── mastg/              # MASTG reference
│   ├── reports/            # Report generation
│   └── utils/              # Utilities
├── tests/                   # Test suite
├── docs/                    # Documentation
├── scripts/                 # Build/deployment scripts
└── pipelines/              # CI/CD configurations
```

## Development Workflow

### 1. Creating a New Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
# or
git checkout -b docs/your-documentation
```

### 2. Making Changes

Follow these guidelines:

- **Modularity**: Keep changes focused and minimal
- **Testing**: Write tests for new functionality
- **Documentation**: Update docs for API changes
- **Code Style**: Follow PEP 8 (enforced by black)
- **Type Hints**: Add type hints to function signatures

### 3. Code Quality Checks

Before committing:

```bash
# Format code
black mobscan/ tests/

# Check style
flake8 mobscan/ tests/

# Type checking
mypy mobscan/ --ignore-missing-imports

# Run tests
pytest tests/ -v

# Check coverage
pytest tests/ --cov=mobscan --cov-report=html
```

### 4. Committing Changes

```bash
git add .
git commit -m "type: description

Optional longer explanation of changes.
- Bullet point 1
- Bullet point 2"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation update
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Build/configuration changes

### 5. Creating Pull Request

```bash
git push origin your-branch-name
```

Then open a PR on GitHub with:
- Clear description of changes
- Link to related issues
- Screenshots (for UI changes)
- Test results

## Adding New Test Modules

### Step 1: Create Module Directory

```bash
mkdir mobscan/modules/your_module
touch mobscan/modules/your_module/__init__.py
```

### Step 2: Implement Module

Create `mobscan/modules/your_module/runner.py`:

```python
from mobscan.models.finding import Finding
from typing import List

class YourModuleRunner:
    """Implementation of your test module"""

    def __init__(self, config):
        self.config = config

    def run(self, app_path: str) -> List[Finding]:
        """Execute tests and return findings"""
        findings = []

        # Your implementation here
        finding = Finding(
            id="FINDING-001",
            title="Your Finding",
            description="Description",
            severity=Severity.HIGH,
            cvss=CVSSScore(7.5, "..."),
            cwe=["CWE-XXX"],
            owasp_category="A01:2021",
            test_name="Your Test",
            module="your_module",
            mastg_category="MASTG-CODE-1",
            masvs_category="MSTG-CODE-1",
            affected_component="Component"
        )
        findings.append(finding)

        return findings
```

### Step 3: Register Module

Update `mobscan/core/engine.py` to load and execute your module:

```python
def _run_your_module_tests(self):
    """Execute your module tests"""
    from mobscan.modules.your_module.runner import YourModuleRunner

    runner = YourModuleRunner(self.config)
    findings = runner.run(self.scan_result.app_info.app_name)

    for finding in findings:
        self.scan_result.add_finding(finding)
```

### Step 4: Write Tests

Create `tests/unit/test_your_module.py`:

```python
import pytest
from mobscan.modules.your_module.runner import YourModuleRunner

class TestYourModule:
    def test_finding_creation(self):
        runner = YourModuleRunner({})
        findings = runner.run("test_app")
        assert len(findings) > 0

    def test_finding_severity(self):
        runner = YourModuleRunner({})
        findings = runner.run("test_app")
        assert findings[0].severity in [Severity.CRITICAL, Severity.HIGH]
```

## Adding Tool Integration

### Step 1: Create Adapter

Create `mobscan/modules/integration/tools/your_tool.py`:

```python
class YourToolAdapter:
    def __init__(self, config):
        self.config = config

    def initialize(self) -> bool:
        """Initialize tool"""
        return True

    def execute(self, app_path: str) -> dict:
        """Execute tool and return raw output"""
        pass

    def cleanup(self):
        """Clean up resources"""
        pass
```

### Step 2: Parse Results

Create converter to transform tool output to `Finding` objects:

```python
def parse_results(tool_output: dict) -> List[Finding]:
    """Convert tool output to findings"""
    findings = []
    # Parse and convert
    return findings
```

### Step 3: Register Tool

Update configuration to enable tool:

```yaml
tools:
  your_tool:
    enabled: true
    version: "1.0.0"
    docker_image: "your_tool:latest"
```

## Database Schema (if using PostgreSQL)

```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    app_name VARCHAR(255),
    package_name VARCHAR(255),
    platform VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
    id VARCHAR(255) PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(50),
    cvss_score FLOAT,
    mastg_category VARCHAR(100),
    masvs_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing Guidelines

### Unit Tests

```python
# tests/unit/test_example.py
import pytest
from mobscan.models.finding import Finding

def test_finding_creation():
    """Test Finding model creation"""
    finding = Finding(...)
    assert finding.title == "Test"
```

### Integration Tests

```python
# tests/integration/test_scan.py
def test_full_scan_workflow():
    """Test complete scan workflow"""
    engine = TestEngine(config)
    result = engine.initialize_scan("app.apk")
    result = engine.execute_tests()
    assert result.findings
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/unit/test_models.py -v

# Run with coverage
pytest tests/ --cov=mobscan --cov-report=html

# Run slow tests only
pytest tests/ -m slow
```

## Documentation Standards

### Code Comments

```python
def complex_function(param1: str, param2: int) -> bool:
    """
    Brief description in one line.

    Longer explanation if needed, describing what the function does,
    parameters, and return value.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        bool: Description of return value

    Raises:
        ValueError: If something is wrong

    Example:
        >>> complex_function("test", 42)
        True
    """
```

### Module Documentation

Every module should have a docstring:

```python
"""
Module title - Brief description

Longer description of what this module does,
its responsibilities, and how it integrates
with other components.

Example:
    Usage example here
"""
```

## Performance Optimization

### Profiling

```bash
# Run with profiler
python -m cProfile -s cumulative mobscan/cli.py scan app.apk

# Memory profiling
pip install memory-profiler
python -m memory_profiler examples/example_usage.py
```

### Optimization Tips

- Cache MASTG reference data
- Use generator expressions for large datasets
- Profile before optimizing
- Document performance decisions

## Security Considerations

- Never commit secrets or credentials
- Validate all user inputs
- Use parameterized queries (if using SQL)
- Keep dependencies updated
- Review OWASP Top 10

## Release Process

1. Update version in `mobscan/__init__.py` and `setup.py`
2. Update CHANGELOG.md
3. Create git tag: `git tag -a v1.0.0 -m "Release 1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. GitHub Actions will build and deploy

## Debugging

### Enable Debug Logging

```bash
mobscan scan app.apk --verbose
# or
export MOBSCAN_LOG_LEVEL=DEBUG
```

### Debug with IDE

VS Code `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Scan",
            "type": "python",
            "request": "launch",
            "module": "mobscan.cli",
            "args": ["scan", "app.apk"],
            "justMyCode": true
        }
    ]
}
```

## Common Tasks

### Adding a new MASTG test

1. Create test implementation in `mobscan/mastg/`
2. Add test case definition
3. Integrate with appropriate module
4. Add unit tests
5. Update documentation

### Updating dependencies

```bash
pip list --outdated
pip install --upgrade package_name
pip freeze > requirements.txt
```

### Building Docker image

```bash
docker build -t mobscan:dev .
docker run -it mobscan:dev bash
```

## Getting Help

- Check existing issues and discussions
- Review similar implementations
- Ask in project discussions
- Refer to OWASP documentation

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Test your changes thoroughly
- Document your changes
- Follow existing code style

---

Happy coding! 🎉
