"""
Scan Results API Routes

Endpoints for retrieving and managing scan results:
- GET /api/v1/scans/{scan_id}/result - Get complete scan result
- GET /api/v1/scans/{scan_id}/findings - Get findings
- GET /api/v1/scans/{scan_id}/statistics - Get statistics
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Optional

router = APIRouter(prefix="/api/v1", tags=["results"])

# Reference to scan storage from scans module
# In production, would use actual database
results_storage = {}


@router.get("/scans/{scan_id}/result")
async def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """
    Get the complete scan result.

    Args:
        scan_id: Scan ID

    Returns:
        Complete scan result with all findings
    """
    # In production, would query database
    if scan_id not in results_storage:
        raise HTTPException(status_code=404, detail="Scan result not found")

    return results_storage[scan_id]


@router.get("/scans/{scan_id}/findings")
async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """
    Get findings from a scan with optional filtering.

    Args:
        scan_id: Scan ID
        severity: Filter by severity (critical, high, medium, low, info)
        limit: Maximum results
        offset: Number to skip

    Returns:
        List of findings
    """
    if scan_id not in results_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = results_storage[scan_id]
    findings = result.get("findings", [])

    # Filter by severity if provided
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]

    # Apply pagination
    total = len(findings)
    findings = findings[offset:offset + limit]

    return {
        "scan_id": scan_id,
        "findings": findings,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/scans/{scan_id}/findings/critical")
async def get_critical_findings(scan_id: str) -> Dict[str, Any]:
    """
    Get only critical severity findings.

    Args:
        scan_id: Scan ID

    Returns:
        Critical findings
    """
    if scan_id not in results_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = results_storage[scan_id]
    critical = [f for f in result.get("findings", []) if f.get("severity") == "critical"]

    return {
        "scan_id": scan_id,
        "count": len(critical),
        "findings": critical,
    }


@router.get("/scans/{scan_id}/statistics")
async def get_scan_statistics(scan_id: str) -> Dict[str, Any]:
    """
    Get scan statistics and metrics.

    Args:
        scan_id: Scan ID

    Returns:
        Statistics including risk metrics
    """
    if scan_id not in results_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = results_storage[scan_id]
    findings = result.get("findings", [])

    # Calculate severity counts
    severity_counts = {
        "critical": len([f for f in findings if f.get("severity") == "critical"]),
        "high": len([f for f in findings if f.get("severity") == "high"]),
        "medium": len([f for f in findings if f.get("severity") == "medium"]),
        "low": len([f for f in findings if f.get("severity") == "low"]),
        "info": len([f for f in findings if f.get("severity") == "info"]),
    }

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "severity_breakdown": severity_counts,
        "risk_score": result.get("risk_metrics", {}).get("risk_score", 0),
        "duration_seconds": result.get("duration_seconds", 0),
        "scan_date": result.get("started_at"),
    }


@router.get("/scans/{scan_id}/masvs-compliance")
async def get_masvs_compliance(scan_id: str) -> Dict[str, Any]:
    """
    Get MASVS compliance assessment.

    Args:
        scan_id: Scan ID

    Returns:
        MASVS compliance levels (L1, L2, R)
    """
    if scan_id not in results_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = results_storage[scan_id]

    return {
        "scan_id": scan_id,
        "masvs_compliance": result.get("masvs_compliance", {}),
    }
