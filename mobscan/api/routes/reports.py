"""
Report Generation API Routes

Endpoints for generating reports:
- GET /api/v1/reports/{scan_id}?format=json|pdf|docx|markdown
- POST /api/v1/reports/{scan_id}/generate
- GET /api/v1/reports/{scan_id}/download
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from typing import Dict, Any, Optional
import json
from pathlib import Path

router = APIRouter(prefix="/api/v1", tags=["reports"])

# Reference to reports storage
reports_storage = {}


@router.get("/reports/{scan_id}")
async def get_report(
    scan_id: str,
    format: str = Query("json", regex="^(json|pdf|docx|markdown)$")
) -> Dict[str, Any] | FileResponse:
    """
    Get a report in the specified format.

    Args:
        scan_id: Scan ID
        format: Report format (json, pdf, docx, markdown)

    Returns:
        Report content or file
    """
    if scan_id not in reports_storage:
        raise HTTPException(status_code=404, detail="Report not found")

    report_data = reports_storage[scan_id]

    if format == "json":
        return report_data

    elif format == "pdf":
        pdf_path = Path(f"mobscan_report_{scan_id}.pdf")
        if pdf_path.exists():
            return FileResponse(pdf_path, filename=str(pdf_path))
        else:
            raise HTTPException(status_code=404, detail="PDF report not found")

    elif format == "docx":
        docx_path = Path(f"mobscan_report_{scan_id}.docx")
        if docx_path.exists():
            return FileResponse(docx_path, filename=str(docx_path))
        else:
            raise HTTPException(status_code=404, detail="DOCX report not found")

    elif format == "markdown":
        return {
            "scan_id": scan_id,
            "content": report_data.get("markdown_content", ""),
            "format": "markdown"
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@router.post("/reports/{scan_id}/generate")
async def generate_report(
    scan_id: str,
    format: str = Query("json", regex="^(json|pdf|docx|markdown)$")
) -> Dict[str, Any]:
    """
    Generate a report in the specified format.

    Args:
        scan_id: Scan ID
        format: Report format

    Returns:
        Generation status
    """
    if scan_id not in reports_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    # In production, would trigger report generation task
    return {
        "scan_id": scan_id,
        "format": format,
        "status": "generating",
        "message": f"Report generation started for format: {format}"
    }


@router.get("/reports/{scan_id}/download")
async def download_report(
    scan_id: str,
    format: str = Query("pdf", regex="^(pdf|docx)$")
) -> FileResponse:
    """
    Download a generated report file.

    Args:
        scan_id: Scan ID
        format: Report format (pdf or docx)

    Returns:
        File for download
    """
    if format == "pdf":
        filepath = Path(f"mobscan_report_{scan_id}.pdf")
        filename = f"mobscan_report_{scan_id}.pdf"
    elif format == "docx":
        filepath = Path(f"mobscan_report_{scan_id}.docx")
        filename = f"mobscan_report_{scan_id}.docx"
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(filepath, filename=filename)


@router.get("/reports")
async def list_reports(
    status: Optional[str] = None,
    limit: int = 10,
    offset: int = 0
) -> Dict[str, Any]:
    """
    List generated reports.

    Args:
        status: Filter by status (pending, generating, completed, failed)
        limit: Maximum results
        offset: Number to skip

    Returns:
        List of reports
    """
    reports = list(reports_storage.values())

    # Filter by status if provided
    if status:
        reports = [r for r in reports if r.get("status") == status]

    # Apply pagination
    total = len(reports)
    reports = reports[offset:offset + limit]

    return {
        "reports": reports,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/reports/{scan_id}/export")
async def export_report(
    scan_id: str,
    format: str = Query("json"),
    include_details: bool = True
) -> Dict[str, Any]:
    """
    Export report data.

    Args:
        scan_id: Scan ID
        format: Export format
        include_details: Include detailed findings

    Returns:
        Export data
    """
    if scan_id not in reports_storage:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = reports_storage[scan_id]

    export_data = {
        "scan_id": scan_id,
        "exported_at": report.get("created_at"),
        "format": format,
    }

    if include_details:
        export_data["findings"] = report.get("findings", [])
        export_data["statistics"] = report.get("statistics", {})

    return export_data
