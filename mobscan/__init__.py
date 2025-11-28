"""
Mobscan - OWASP MASTG Automated Mobile Security Testing Framework

A comprehensive, production-grade mobile application security testing platform
that automates and orchestrates security tests against OWASP MASTG standards.
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__license__ = "MIT"

from .core.engine import TestEngine
from .models.finding import Finding
from .models.scan_result import ScanResult

__all__ = [
    "TestEngine",
    "Finding",
    "ScanResult",
]
