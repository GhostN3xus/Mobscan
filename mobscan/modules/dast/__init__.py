"""
DAST (Dynamic Application Security Testing) Module

Performs dynamic analysis of mobile applications including:
- Network communication testing
- Certificate validation testing
- API endpoint testing
- Authentication/authorization testing
"""

from .dast_engine import DASTEngine

__all__ = ['DASTEngine']
