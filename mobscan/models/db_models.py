"""
SQLAlchemy ORM models for Mobscan database.

This module defines the database models for storing scan results,
findings, users, and other persistent data.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from mobscan.database import Base
import enum


class ScanStatus(str, enum.Enum):
    """Status enumeration for scans."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, enum.Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"


class APIKey(Base):
    """API Key model for authentication."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key_hash = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey(id={self.id}, user_id={self.user_id}, name={self.name})>"


class Scan(Base):
    """Scan model to store scan sessions."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_name = Column(String(255), nullable=False)
    app_name = Column(String(255), nullable=False)
    app_version = Column(String(100), nullable=True)
    app_path = Column(Text, nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    scan_type = Column(String(50), nullable=False)  # full, sast, dast, frida, sca

    # Configuration
    config = Column(JSON, nullable=True)

    # Results
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Risk score
    risk_score = Column(Float, default=0.0)

    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, app_name={self.app_name}, status={self.status})>"


class Finding(Base):
    """Finding model to store identified vulnerabilities/issues."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    cvss_score = Column(Float, nullable=True)

    # MASTG/MASVS mapping
    mastg_id = Column(String(50), nullable=True)
    masvs_id = Column(String(50), nullable=True)
    owasp_id = Column(String(50), nullable=True)

    # Evidence
    evidence = Column(JSON, nullable=True)  # Additional details/proof
    code_snippet = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)

    # Remediation
    recommendation = Column(Text, nullable=True)
    remediation_effort = Column(String(20), nullable=True)  # easy, medium, hard

    # Status
    status = Column(String(50), default="open")  # open, fixed, false_positive
    assigned_to = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"


class Report(Base):
    """Report model for generated reports."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # json, pdf, html, docx, markdown
    file_path = Column(Text, nullable=True)
    file_size = Column(Integer, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="reports")

    def __repr__(self):
        return f"<Report(id={self.id}, scan_id={self.scan_id}, type={self.report_type})>"


class ScanLog(Base):
    """Scan logs for tracking scan execution."""
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    level = Column(String(20), nullable=False)  # DEBUG, INFO, WARNING, ERROR
    module = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanLog(id={self.id}, level={self.level}, module={self.module})>"
