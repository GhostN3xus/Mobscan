"""
FastAPI Application - REST API for Mobscan

Provides comprehensive REST API endpoints for managing scans,
retrieving results, and generating reports.
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import logging
from typing import List, Optional
from pathlib import Path
import json
import uuid
from datetime import datetime

from ..core.engine import TestEngine
from ..core.config import MobscanConfig
from ..models.scan_result import ScanResult


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title="Mobscan API",
        description="OWASP MASTG Automated Mobile Security Testing Framework API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-memory scan storage (for demo)
    # In production, use a proper database
    scan_storage: dict = {}

    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        """Root endpoint"""
        return {
            "name": "Mobscan API",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "docs": "/api/docs",
                "scans": "/api/v1/scans",
                "results": "/api/v1/results",
            }
        }

    # Health check
    @app.get("/health", tags=["health"])
    async def health():
        """Health check endpoint"""
        return {"status": "healthy"}

    # ===== SCAN ENDPOINTS =====

    @app.post("/api/v1/scans", tags=["scans"])
    async def create_scan(
        file: UploadFile = File(...),
        intensity: str = Query("full", description="Scan intensity"),
        platforms: str = Query("android", description="Target platform"),
        formats: str = Query("json", description="Output formats"),
        background_tasks: BackgroundTasks = BackgroundTasks()
    ):
        """
        Create and start a new scan.

        **Parameters:**
        - file: APK/IPA file to scan
        - intensity: Scan intensity (quick, standard, full, comprehensive)
        - platforms: Target platform (android, ios)
        - formats: Report formats (json, pdf, docx, markdown)
        """
        try:
            if not file.filename.endswith((".apk", ".ipa")):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid file format. Only APK and IPA files are supported."
                )

            # Save uploaded file
            upload_dir = Path("./.uploads")
            upload_dir.mkdir(exist_ok=True)

            file_path = upload_dir / file.filename
            with open(file_path, "wb") as f:
                f.write(await file.read())

            # Create scan
            scan_id = str(uuid.uuid4())
            config = MobscanConfig.default_config()
            config.scan_intensity = intensity
            config.parallel_workers = 4

            scan_storage[scan_id] = {
                "id": scan_id,
                "status": "running",
                "created_at": datetime.utcnow().isoformat(),
                "file_path": str(file_path),
                "intensity": intensity,
                "platforms": platforms,
                "formats": formats.split(","),
            }

            # Run scan in background
            background_tasks.add_task(
                run_scan_background,
                scan_id,
                str(file_path),
                config,
                scan_storage
            )

            return {
                "scan_id": scan_id,
                "status": "queued",
                "message": "Scan queued successfully",
                "polling_url": f"/api/v1/scans/{scan_id}/status"
            }

        except Exception as e:
            logger.error(f"Error creating scan: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/v1/scans/{scan_id}/status", tags=["scans"])
    async def get_scan_status(scan_id: str):
        """Get the status of a scan"""
        if scan_id not in scan_storage:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = scan_storage[scan_id]
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "created_at": scan["created_at"],
            "progress": scan.get("progress", 0),
        }

    @app.get("/api/v1/scans/{scan_id}/result", tags=["scans"])
    async def get_scan_result(scan_id: str):
        """Get the full result of a completed scan"""
        if scan_id not in scan_storage:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = scan_storage[scan_id]
        if scan["status"] != "completed":
            raise HTTPException(
                status_code=400,
                detail=f"Scan is still {scan['status']}"
            )

        result_path = Path(scan.get("result_path"))
        if result_path.exists():
            with open(result_path, "r") as f:
                return json.load(f)
        else:
            raise HTTPException(status_code=404, detail="Result not found")

    @app.get("/api/v1/scans", tags=["scans"])
    async def list_scans(
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0)
    ):
        """List all scans"""
        scans = list(scan_storage.values())[offset:offset + limit]
        return {
            "total": len(scan_storage),
            "limit": limit,
            "offset": offset,
            "scans": scans
        }

    # ===== REPORT ENDPOINTS =====

    @app.get("/api/v1/reports/{scan_id}", tags=["reports"])
    async def get_report(
        scan_id: str,
        format: str = Query("json", description="Report format")
    ):
        """
        Get report for a scan.

        **Parameters:**
        - format: Report format (json, pdf, docx, markdown)
        """
        if scan_id not in scan_storage:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = scan_storage[scan_id]
        if scan["status"] != "completed":
            raise HTTPException(
                status_code=400,
                detail="Scan must be completed before generating report"
            )

        report_path = Path(f"./reports/{scan_id}/report.{format}")
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report not found")

        return FileResponse(report_path)

    # ===== CONFIGURATION ENDPOINTS =====

    @app.get("/api/v1/config", tags=["config"])
    async def get_config():
        """Get current configuration"""
        config = MobscanConfig.default_config()
        return {
            "scan_intensity_options": ["quick", "standard", "full", "comprehensive"],
            "platforms": ["android", "ios"],
            "output_formats": ["json", "pdf", "docx", "markdown"],
            "masvs_levels": ["L1", "L2", "R"],
        }

    # ===== TOOL STATUS ENDPOINTS =====

    @app.get("/api/v1/tools", tags=["tools"])
    async def get_tools():
        """Get available tools and their status"""
        config = MobscanConfig.default_config()
        tools = []
        for name, tool in config.tools.items():
            tools.append({
                "name": name,
                "enabled": tool.enabled,
                "version": tool.version,
                "status": "installed" if tool.enabled else "disabled"
            })
        return {"tools": tools}

    # ===== STATISTICS ENDPOINTS =====

    @app.get("/api/v1/stats", tags=["statistics"])
    async def get_statistics():
        """Get overall statistics"""
        completed_scans = [s for s in scan_storage.values() if s["status"] == "completed"]
        return {
            "total_scans": len(scan_storage),
            "completed_scans": len(completed_scans),
            "running_scans": len([s for s in scan_storage.values() if s["status"] == "running"]),
            "queued_scans": len([s for s in scan_storage.values() if s["status"] == "queued"]),
        }

    return app


async def run_scan_background(scan_id: str, file_path: str, config: MobscanConfig, scan_storage: dict):
    """Background task to run a scan"""
    try:
        scan_storage[scan_id]["status"] = "running"
        scan_storage[scan_id]["progress"] = 0

        # Initialize engine
        engine = TestEngine(config)
        result = engine.initialize_scan(file_path, Path(file_path).stem)

        # Execute tests
        scan_storage[scan_id]["progress"] = 50
        result = engine.execute_tests()

        # Save results
        output_dir = Path(f"./reports/{scan_id}")
        output_dir.mkdir(parents=True, exist_ok=True)

        result_path = output_dir / "result.json"
        engine.save_scan_result(str(result_path))

        scan_storage[scan_id]["result_path"] = str(result_path)
        scan_storage[scan_id]["progress"] = 100
        scan_storage[scan_id]["status"] = "completed"
        scan_storage[scan_id]["completed_at"] = datetime.utcnow().isoformat()

        logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {str(e)}")
        scan_storage[scan_id]["status"] = "failed"
        scan_storage[scan_id]["error"] = str(e)
