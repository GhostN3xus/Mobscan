"""
API Routes Module

Organized route modules:
- scans: Scan management endpoints
- results: Scan results and findings endpoints
- reports: Report generation endpoints
- health: Health check endpoints
"""

from .scans import router as scans_router
from .results import router as results_router
from .reports import router as reports_router

__all__ = ['scans_router', 'results_router', 'reports_router']
