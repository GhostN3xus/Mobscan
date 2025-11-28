"""
Finding Model - Represents a security finding/vulnerability

This module defines the data structure for security findings identified
during mobile application security testing.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import json


class Severity(Enum):
    """CVSS-based severity levels"""
    CRITICAL = "Critical"  # CVSS >= 9.0
    HIGH = "High"          # CVSS 7.0-8.9
    MEDIUM = "Medium"      # CVSS 4.0-6.9
    LOW = "Low"            # CVSS 0.1-3.9
    INFO = "Info"          # Informational


class FindingStatus(Enum):
    """Finding status throughout the assessment"""
    OPEN = "Open"
    CONFIRMED = "Confirmed"
    MITIGATED = "Mitigated"
    FALSE_POSITIVE = "False Positive"
    ACCEPTED_RISK = "Accepted Risk"


@dataclass
class CVSSScore:
    """CVSS v3.1 Score Details"""
    score: float  # 0.0 - 10.0
    vector: str   # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    severity: Severity = field(init=False)

    def __post_init__(self):
        if self.score >= 9.0:
            self.severity = Severity.CRITICAL
        elif self.score >= 7.0:
            self.severity = Severity.HIGH
        elif self.score >= 4.0:
            self.severity = Severity.MEDIUM
        elif self.score >= 0.1:
            self.severity = Severity.LOW
        else:
            self.severity = Severity.INFO


@dataclass
class Evidence:
    """Evidence for a finding"""
    type: str  # "log", "screenshot", "code", "network_traffic", "frida_output"
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class Remediation:
    """Remediation guidance for a finding"""
    short_description: str
    detailed_steps: List[str]
    code_example: Optional[str] = None
    references: List[str] = field(default_factory=list)
    effort: str = "Medium"  # Low, Medium, High

    def to_dict(self) -> Dict:
        return {
            "short_description": self.short_description,
            "detailed_steps": self.detailed_steps,
            "code_example": self.code_example,
            "references": self.references,
            "effort": self.effort
        }


@dataclass
class Finding:
    """
    Represents a security finding/vulnerability discovered during testing.
    Compliant with OWASP MASTG and MASVS standards.
    """

    # Basic Information
    id: str
    title: str
    description: str

    # Classification
    severity: Severity
    cvss: CVSSScore
    cwe: List[str]  # e.g., ["CWE-78", "CWE-89"]
    owasp_category: str  # e.g., "A02:2021 - Cryptographic Failures"

    # Testing Information
    test_name: str  # Name of the test that found this
    module: str  # Module: sast, dast, frida, etc
    mastg_category: str  # e.g., "MASTG-STORAGE-1"
    masvs_category: str  # e.g., "MSTG-STORAGE-1"

    # Location Information
    affected_component: str  # Activity, Library, API endpoint, etc
    affected_code_location: Optional[str] = None  # File:line format

    # Status & Timeline
    status: FindingStatus = FindingStatus.OPEN
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None

    # Evidence & Remediation
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[Remediation] = None

    # Additional Details
    impact_description: str = ""
    exploitation_complexity: str = "Unknown"  # Low, Medium, High
    reproducibility: float = 1.0  # 0.0 to 1.0

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Detection Method
    detection_method: str = "automated"  # automated, manual, hybrid
    confidence: float = 1.0  # 0.0 to 1.0

    def to_dict(self) -> Dict:
        """Convert finding to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": {
                "score": self.cvss.score,
                "vector": self.cvss.vector,
                "severity": self.cvss.severity.value
            },
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "test_name": self.test_name,
            "module": self.module,
            "mastg_category": self.mastg_category,
            "masvs_category": self.masvs_category,
            "affected_component": self.affected_component,
            "affected_code_location": self.affected_code_location,
            "status": self.status.value,
            "discovered_at": self.discovered_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "impact_description": self.impact_description,
            "exploitation_complexity": self.exploitation_complexity,
            "reproducibility": self.reproducibility,
            "tags": self.tags,
            "metadata": self.metadata,
            "detection_method": self.detection_method,
            "confidence": self.confidence
        }

    def to_json(self) -> str:
        """Convert finding to JSON string"""
        return json.dumps(self.to_dict(), default=str, indent=2)

    def add_evidence(self, evidence: Evidence):
        """Add evidence to this finding"""
        self.evidence.append(evidence)

    def set_remediation(self, remediation: Remediation):
        """Set remediation for this finding"""
        self.remediation = remediation

    def __hash__(self):
        """Make finding hashable for deduplication"""
        return hash((
            self.title,
            self.affected_component,
            self.mastg_category
        ))

    def __eq__(self, other):
        """Check equality with another finding"""
        if not isinstance(other, Finding):
            return False
        return (
            self.title == other.title and
            self.affected_component == other.affected_component and
            self.mastg_category == other.mastg_category
        )
