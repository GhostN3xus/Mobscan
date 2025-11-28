"""
SAST (Static Application Security Testing) Module

Performs static analysis of mobile applications including:
- Secrets detection (API keys, hardcoded credentials)
- Dependency vulnerability checking
- Code analysis for common vulnerabilities
- Manifest/plist analysis
"""

from .sast_engine import SASTEngine

__all__ = ['SASTEngine']
