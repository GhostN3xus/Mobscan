# Contributing to Mobscan

Thank you for your interest in contributing to Mobscan! We welcome contributions from everyone and appreciate your effort to make mobile application security testing better.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please be kind and professional in all interactions.

## Ways to Contribute

### 1. Report Bugs

Found a bug? Please report it by creating an issue with:
- Clear title describing the problem
- Steps to reproduce
- Expected vs. actual behavior
- Screenshots/logs if applicable
- Your environment (OS, Python version, etc.)

### 2. Suggest Features

Have an idea for improvement? Open a feature request with:
- Clear description of the feature
- Use case and why it's valuable
- Proposed implementation (optional)
- Examples of similar tools (optional)

### 3. Improve Documentation

Documentation improvements are always welcome:
- Fix typos and grammar
- Clarify confusing sections
- Add examples
- Update outdated information
- Translate documentation

### 4. Write Code

Contributing code is the most direct way to help:
- Fix bugs
- Implement features
- Add tests
- Optimize performance
- Refactor code

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- Docker (optional)
- Basic understanding of mobile security concepts

### Setup Development Environment

```bash
# Fork and clone repository
git clone https://github.com/YOUR_USERNAME/Mobscan.git
cd Mobscan

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Verify setup
pytest tests/ -v
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
# or
git checkout -b docs/documentation-update
```

Branch naming conventions:
- `feature/` for new features
- `fix/` for bug fixes
- `docs/` for documentation
- `refactor/` for code refactoring
- `test/` for test additions

### 2. Make Changes

Follow these guidelines:

#### Code Style
- Follow PEP 8
- Use type hints
- Maximum line length: 120 characters
- Use meaningful variable names
- Add docstrings to all functions and classes

#### Commit Messages
```
type: Brief description (50 chars max)

Longer explanation if needed (72 chars max per line)
- Bullet point 1
- Bullet point 2

Closes #ISSUE_NUMBER
```

Types:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Tests
- `chore:` Build/dependencies

#### Testing
- Write tests for all new code
- Maintain or improve code coverage
- All tests must pass locally

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=mobscan --cov-report=html

# Specific test
pytest tests/unit/test_models.py::TestFinding -v
```

#### Code Quality
```bash
# Format code
black mobscan/ tests/

# Check style
flake8 mobscan/ tests/

# Type checking
mypy mobscan/ --ignore-missing-imports

# All checks
pre-commit run --all-files
```

### 3. Test Your Changes

```bash
# Run unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run all tests with coverage
pytest tests/ --cov=mobscan --cov-report=term-missing

# Test with Docker
docker build -t mobscan:test .
docker run mobscan:test pytest tests/
```

### 4. Submit a Pull Request

1. Push your branch to your fork:
```bash
git push origin your-branch-name
```

2. Open a PR on GitHub with:
   - Clear title and description
   - Reference to related issues
   - Summary of changes
   - Testing performed
   - Checklist items completed

3. PR Checklist:
   - [ ] Tests pass locally
   - [ ] Code follows style guide
   - [ ] Documentation updated
   - [ ] No breaking changes (or documented)
   - [ ] Commit messages are clear

### 5. Address Review Feedback

- Review comments promptly
- Make requested changes
- Push updates to the same branch
- Re-request review

## Code Guidelines

### Python Style

```python
# Good: Type hints, docstring, clear purpose
def analyze_finding(finding: Finding, confidence_threshold: float = 0.8) -> bool:
    """
    Analyze a finding and determine if it meets confidence threshold.

    Args:
        finding: The security finding to analyze
        confidence_threshold: Minimum confidence required (0-1)

    Returns:
        bool: True if finding meets threshold, False otherwise

    Raises:
        ValueError: If confidence_threshold is out of bounds
    """
    if not 0 <= confidence_threshold <= 1:
        raise ValueError("Confidence threshold must be between 0 and 1")

    return finding.confidence >= confidence_threshold


# Bad: No type hints, unclear purpose, no docstring
def analyze_finding(finding, threshold=0.8):
    if threshold < 0 or threshold > 1:
        raise ValueError("Invalid threshold")
    return finding.confidence >= threshold
```

### Testing

```python
# Good: Clear test name, one assertion, proper setup
def test_finding_with_critical_severity_returns_true():
    """Test that critical findings are properly identified."""
    finding = Finding(
        id="TEST-001",
        title="Critical Vulnerability",
        severity=Severity.CRITICAL,
        # ... other required fields
    )

    assert finding.severity == Severity.CRITICAL


# Bad: Multiple assertions, unclear what's being tested
def test_finding():
    finding = Finding(...)
    assert finding.severity == Severity.CRITICAL
    assert finding.title == "Vulnerability"
    assert len(finding.evidence) == 0
```

### Documentation

```python
# Good: Comprehensive docstring with examples
def deduplicate_findings(self) -> int:
    """
    Remove duplicate findings from scan results.

    Duplicates are identified by finding hash (title + component + category).
    The first occurrence of each unique finding is retained.

    Returns:
        int: Number of duplicate findings removed

    Example:
        >>> result = ScanResult()
        >>> result.add_finding(dup_finding_1)
        >>> result.add_finding(dup_finding_1)  # Duplicate
        >>> removed = result.deduplicate_findings()
        >>> assert removed == 1
    """
```

## Adding New Features

### For MASTG Test Category

1. Create test implementation in `mobscan/mastg/`
2. Add to appropriate module (SAST, DAST, etc.)
3. Write unit tests
4. Update documentation
5. Add example findings
6. Update roadmap if major feature

### For New Module

1. Create `mobscan/modules/your_module/`
2. Implement `BaseModule` interface
3. Add tool adapters as needed
4. Write comprehensive tests (unit + integration)
5. Document usage and configuration
6. Add to CLI if needed

### For Tool Integration

1. Create adapter in `mobscan/modules/integration/tools/`
2. Implement tool initialization and execution
3. Create result parser
4. Write tests
5. Document tool configuration
6. Update README with tool info

## Documentation Guidelines

- Write in English
- Use Markdown for formatting
- Include code examples
- Add links to related sections
- Keep examples current
- Update table of contents

## Review Process

### What Reviewers Look For

1. **Code Quality**
   - Follows style guide
   - Has proper tests
   - Clear and maintainable
   - No unnecessary complexity

2. **Functionality**
   - Solves stated problem
   - Works as intended
   - Handles edge cases
   - Includes error handling

3. **Documentation**
   - Code is commented
   - Functions have docstrings
   - User-facing changes are documented
   - Examples are provided

4. **Tests**
   - All tests pass
   - New code has tests
   - Edge cases covered
   - Coverage maintained

### Expected Response Time

- Initial review: Within 2 business days
- Follow-up reviews: Within 1 business day
- For critical issues: Priority review

## Release Process

### Version Numbering

Follows semantic versioning: `MAJOR.MINOR.PATCH`

- `MAJOR`: Breaking changes
- `MINOR`: New features
- `PATCH`: Bug fixes

### Release Cycle

- Major releases: Every 6 months
- Minor releases: Every month
- Patch releases: As needed
- Security patches: Within 48 hours

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- GitHub contributors page
- Release notes
- Project documentation

## Getting Help

- **Questions**: Open a discussion
- **Technical Help**: Ask in issues
- **General Help**: Email security@mobscan.dev
- **Discord**: Join our community server

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Additional Resources

- [DEVELOPMENT.md](./docs/DEVELOPMENT.md) - Detailed development guide
- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) - System architecture
- [OWASP MASTG](https://github.com/OWASP/owasp-mastg) - Security testing guide
- [OWASP MASVS](https://github.com/OWASP/owasp-masvs) - Security verification

---

**Thank you for contributing to Mobscan!** 🙏

Your efforts help make mobile application security testing more accessible and effective for everyone.
