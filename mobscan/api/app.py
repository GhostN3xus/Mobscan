"""
FastAPI Application - REST API for Mobscan

Provides comprehensive REST API endpoints for managing scans,
retrieving results, and generating reports.
"""

from fastapi import (
    FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Query,
    Depends, Security, status
)
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
import logging
from typing import List, Optional
from pathlib import Path
import json
import uuid
from datetime import datetime

from ..core.engine import TestEngine
from ..core.config import MobscanConfig
from ..models.scan_result import ScanResult
from ..database import init_db, get_db
from ..models.db_models import Scan, Finding, User, ScanStatus
from .schemas import (
    ScanCreate, ScanResponse, FindingResponse, HealthResponse,
    UserCreate, UserLogin, Token, ErrorResponse, APIKeyCreate
)
from .auth import (
    authenticate_user, create_user, create_access_token,
    verify_token, validate_api_key, create_api_key
)

logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title="Mobscan API",
        description="OWASP MASTG Automated Mobile Security Testing Framework API",
        version="1.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )

    # Initialize database
    try:
        init_db()
    except Exception as e:
        logger.warning(f"Database initialization: {e}")

    # CORS middleware - Secure configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:8080"],  # Specific origins
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Dependency for getting current user from token
    async def get_current_user(
        credentials: HTTPAuthCredentials = Security(security),
        db: Session = Depends(get_db)
    ) -> User:
        """Get current user from JWT token"""
        token = credentials.credentials
        token_data = verify_token(token)

        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )

        user = db.query(User).filter(User.username == token_data.sub).first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )

        return user

    # Alternative authentication via API key
    async def get_user_by_api_key(
        api_key: str = Query(None),
        db: Session = Depends(get_db)
    ) -> Optional[User]:
        """Get user by API key"""
        if api_key:
            return validate_api_key(db, api_key)
        return None

    # ===== AUTHENTICATION ENDPOINTS =====

    @app.post("/api/v1/auth/register", response_model=dict, tags=["auth"])
    @limiter.limit("5/minute")
    async def register(
        user_data: UserCreate,
        request,
        db: Session = Depends(get_db)
    ):
        """Register a new user"""
        try:
            user = create_user(
                db,
                user_data.username,
                user_data.email,
                user_data.password
            )

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists or registration failed"
                )

            return {
                "message": "User created successfully",
                "user_id": user.id,
                "username": user.username
            }

        except Exception as e:
            logger.error(f"Registration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Registration failed"
            )

    @app.post("/api/v1/auth/login", response_model=Token, tags=["auth"])
    @limiter.limit("10/minute")
    async def login(
        login_data: UserLogin,
        request,
        db: Session = Depends(get_db)
    ):
        """Login and get JWT token"""
        try:
            user = authenticate_user(db, login_data.username, login_data.password)

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password"
                )

            access_token = create_access_token(
                data={"sub": user.username, "scopes": ["read", "write"]}
            )

            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 1800
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Login error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Login failed"
            )

    @app.post("/api/v1/auth/api-keys", tags=["auth"])
    async def generate_api_key(
        key_data: APIKeyCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Generate a new API key for authenticated user"""
        try:
            api_key = create_api_key(db, current_user.id, key_data.name)

            if not api_key:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create API key"
                )

            return {
                "api_key": api_key,
                "message": "API key created successfully. Store it safely!",
                "name": key_data.name
            }

        except Exception as e:
            logger.error(f"API key creation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API key creation failed"
            )

    # ===== ROOT & HEALTH ENDPOINTS =====

    @app.get("/", tags=["root"])
    async def root():
        """Root endpoint"""
        return {
            "name": "Mobscan API",
            "version": "1.1.0",
            "status": "running",
            "endpoints": {
                "docs": "/api/docs",
                "auth": "/api/v1/auth",
                "scans": "/api/v1/scans",
                "reports": "/api/v1/reports",
            }
        }

    @app.get("/health", response_model=HealthResponse, tags=["health"])
    async def health(db: Session = Depends(get_db)):
        """Health check endpoint"""
        try:
            # Test database connection
            db.execute("SELECT 1")
            db_status = "connected"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_status = "disconnected"

        return HealthResponse(
            status="healthy" if db_status == "connected" else "degraded",
            message="API is operational",
            database=db_status,
            api_version="1.1.0",
            timestamp=datetime.utcnow()
        )

    # ===== SCAN ENDPOINTS =====

    @app.post("/api/v1/scans", response_model=dict, tags=["scans"])
    @limiter.limit("30/minute")
    async def create_scan(
        file: UploadFile = File(...),
        scan_name: str = Query(..., min_length=1),
        scan_type: str = Query("full", description="Scan type: full, sast, dast, frida, sca"),
        background_tasks: BackgroundTasks = BackgroundTasks(),
        request=None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Create and start a new scan"""
        try:
            # Validate file
            if not file.filename.endswith((".apk", ".ipa")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid file format. Only APK and IPA files are supported."
                )

            # Save uploaded file
            upload_dir = Path("./.uploads")
            upload_dir.mkdir(exist_ok=True)

            file_path = upload_dir / file.filename
            with open(file_path, "wb") as f:
                f.write(await file.read())

            # Create scan record in database
            app_name = file.filename.rsplit(".", 1)[0]

            new_scan = Scan(
                user_id=current_user.id,
                scan_name=scan_name,
                app_name=app_name,
                app_path=str(file_path),
                status=ScanStatus.PENDING,
                scan_type=scan_type
            )

            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            # Run scan in background
            background_tasks.add_task(
                run_scan_background,
                new_scan.id,
                str(file_path),
                scan_type,
                db
            )

            return {
                "scan_id": new_scan.id,
                "status": "queued",
                "message": "Scan queued successfully",
                "polling_url": f"/api/v1/scans/{new_scan.id}/status"
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating scan: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Scan creation failed: {str(e)}"
            )

    @app.get("/api/v1/scans/{scan_id}/status", tags=["scans"])
    async def get_scan_status(
        scan_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get the status of a scan"""
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        return {
            "scan_id": scan.id,
            "status": scan.status,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
            "findings_count": scan.findings_count,
            "risk_score": scan.risk_score
        }

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
    async def get_scan_details(
        scan_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get detailed scan information"""
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        return scan

    @app.get("/api/v1/scans", tags=["scans"])
    async def list_scans(
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """List user's scans"""
        scans = db.query(Scan).filter(
            Scan.user_id == current_user.id
        ).offset(offset).limit(limit).all()

        total = db.query(Scan).filter(Scan.user_id == current_user.id).count()

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "scans": scans
        }

    # ===== FINDINGS ENDPOINTS =====

    @app.get("/api/v1/scans/{scan_id}/findings", tags=["findings"])
    async def get_findings(
        scan_id: int,
        severity: Optional[str] = Query(None),
        status: Optional[str] = Query(None),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get findings for a scan"""
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        query = db.query(Finding).filter(Finding.scan_id == scan_id)

        if severity:
            query = query.filter(Finding.severity == severity)

        if status:
            query = query.filter(Finding.status == status)

        findings = query.all()
        return {"findings": findings}

    # ===== REPORT ENDPOINTS =====

    @app.get("/api/v1/reports/{scan_id}", tags=["reports"])
    async def get_report(
        scan_id: int,
        format: str = Query("json", description="Report format"),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get report for a scan"""
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )

        if scan.status != ScanStatus.COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan must be completed before generating report"
            )

        report_path = Path(f"./reports/{scan_id}/report.{format}")
        if not report_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )

        return FileResponse(report_path)

    # ===== CONFIGURATION ENDPOINTS =====

    @app.get("/api/v1/config", tags=["config"])
    async def get_config():
        """Get current configuration"""
        return {
            "scan_types": ["full", "sast", "dast", "frida", "sca"],
            "platforms": ["android", "ios"],
            "output_formats": ["json", "pdf", "docx", "markdown"],
            "severity_levels": ["critical", "high", "medium", "low", "info"],
        }

    # ===== TOOL STATUS ENDPOINTS =====

    @app.get("/api/v1/tools", tags=["tools"])
    async def get_tools():
        """Get available tools and their status"""
        return {
            "tools": [
                {"name": "SAST", "enabled": True, "status": "active"},
                {"name": "DAST", "enabled": True, "status": "active"},
                {"name": "Frida", "enabled": True, "status": "active"},
                {"name": "SCA", "enabled": True, "status": "active"},
            ]
        }

    # ===== STATISTICS ENDPOINTS =====

    @app.get("/api/v1/stats", tags=["statistics"])
    async def get_statistics(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get user's statistics"""
        total_scans = db.query(Scan).filter(Scan.user_id == current_user.id).count()
        completed_scans = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED
        ).count()
        running_scans = db.query(Scan).filter(
            Scan.user_id == current_user.id,
            Scan.status == ScanStatus.IN_PROGRESS
        ).count()

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "average_findings": 0  # Calculate if needed
        }

    return app


async def run_scan_background(scan_id: int, file_path: str, scan_type: str, db: Session):
    """Background task to run a scan"""
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = ScanStatus.IN_PROGRESS
        scan.started_at = datetime.utcnow()
        db.commit()

        # Initialize engine
        config = MobscanConfig.default_config()
        engine = TestEngine(config)
        result = engine.initialize_scan(file_path, Path(file_path).stem)

        # Execute tests
        result = engine.execute_tests()

        # Save results
        output_dir = Path(f"./reports/{scan_id}")
        output_dir.mkdir(parents=True, exist_ok=True)

        result_path = output_dir / "result.json"
        engine.save_scan_result(str(result_path))

        # Update scan record
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.findings_count = len(result.findings) if result else 0
        db.commit()

        logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {str(e)}")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            db.commit()
