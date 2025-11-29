"""
Pydantic schemas for API request/response validation.

These schemas define the structure of data being sent to and received from the API.
"""

from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Status enumeration for scans."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# User Schemas
class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)


class UserLogin(BaseModel):
    """Schema for user login."""
    username: str
    password: str


class UserResponse(BaseModel):
    """Schema for user response."""
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# API Key Schemas
class APIKeyCreate(BaseModel):
    """Schema for creating API keys."""
    name: str = Field(..., min_length=3, max_length=100)


class APIKeyResponse(BaseModel):
    """Schema for API key response."""
    id: int
    name: str
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# Finding Schemas
class FindingBase(BaseModel):
    """Base schema for findings."""
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    category: str
    severity: SeverityLevel
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    mastg_id: Optional[str] = None
    masvs_id: Optional[str] = None
    owasp_id: Optional[str] = None
    recommendation: Optional[str] = None
    remediation_effort: Optional[str] = None


class FindingCreate(FindingBase):
    """Schema for creating findings."""
    evidence: Optional[Dict[str, Any]] = None
    code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None


class FindingUpdate(BaseModel):
    """Schema for updating findings."""
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class FindingResponse(FindingBase):
    """Schema for finding response."""
    id: int
    scan_id: int
    status: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Scan Schemas
class ScanCreate(BaseModel):
    """Schema for creating a scan."""
    scan_name: str = Field(..., max_length=255)
    app_name: str = Field(..., max_length=255)
    app_version: Optional[str] = Field(None, max_length=100)
    app_path: str
    scan_type: str = Field(..., description="full, sast, dast, frida, or sca")
    config: Optional[Dict[str, Any]] = None


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""
    status: Optional[ScanStatus] = None
    findings_count: Optional[int] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    medium_count: Optional[int] = None
    low_count: Optional[int] = None
    info_count: Optional[int] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    duration_seconds: Optional[int] = None


class ScanResponse(BaseModel):
    """Schema for scan response."""
    id: int
    scan_name: str
    app_name: str
    app_version: Optional[str]
    app_path: str
    status: ScanStatus
    scan_type: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    duration_seconds: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanDetailedResponse(ScanResponse):
    """Detailed scan response with findings."""
    findings: List[FindingResponse] = []


# Report Schemas
class ReportCreate(BaseModel):
    """Schema for creating reports."""
    report_type: str = Field(..., description="json, pdf, html, docx, or markdown")


class ReportResponse(BaseModel):
    """Schema for report response."""
    id: int
    scan_id: int
    name: str
    report_type: str
    file_size: Optional[int]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Token Schemas
class Token(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Schema for JWT token data."""
    sub: str
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    scopes: List[str] = []


# Health Check Schemas
class HealthResponse(BaseModel):
    """Schema for health check response."""
    status: str
    message: str
    database: str
    api_version: str
    timestamp: datetime


# Error Schemas
class ErrorResponse(BaseModel):
    """Schema for error responses."""
    error: str
    detail: str
    status_code: int
    timestamp: datetime
