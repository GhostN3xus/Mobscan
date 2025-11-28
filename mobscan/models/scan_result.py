"""
ScanResult Model - Represents the results of a complete mobile security scan

Aggregates findings, metadata, and statistics from all test modules.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import json
import uuid

from .finding import Finding, Severity


class ComplianceLevel(Enum):
    """MASVS Compliance Levels"""
    L1 = "Level 1"  # Standard security requirements
    L2 = "Level 2"  # Enhanced security requirements
    R = "Resilience"  # Reverse engineering and resilience


@dataclass
class RiskMetrics:
    """Risk metrics and statistics"""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    @property
    def total_count(self) -> int:
        return sum([
            self.critical_count,
            self.high_count,
            self.medium_count,
            self.low_count,
            self.info_count
        ])

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-10)"""
        if self.total_count == 0:
            return 0.0
        score = (
            (self.critical_count * 10) +
            (self.high_count * 7) +
            (self.medium_count * 4) +
            (self.low_count * 1)
        ) / self.total_count
        return min(score, 10.0)

    def to_dict(self) -> Dict:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "total": self.total_count,
            "risk_score": self.risk_score
        }


@dataclass
class MAVSCompliance:
    """MASVS Compliance assessment"""
    level: ComplianceLevel
    requirements_total: int = 0
    requirements_met: int = 0
    requirements_failed: int = 0

    @property
    def compliance_percentage(self) -> float:
        if self.requirements_total == 0:
            return 0.0
        return (self.requirements_met / self.requirements_total) * 100

    def to_dict(self) -> Dict:
        return {
            "level": self.level.value,
            "total_requirements": self.requirements_total,
            "requirements_met": self.requirements_met,
            "requirements_failed": self.requirements_failed,
            "compliance_percentage": self.compliance_percentage
        }


@dataclass
class ApplicationInfo:
    """Information about the scanned application"""
    app_name: str
    package_name: str
    version: str
    platform: str  # android, ios
    min_api_level: Optional[int] = None
    target_api_level: Optional[int] = None
    file_size: int = 0  # in bytes
    file_hash: str = ""  # SHA256
    signing_cert: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "app_name": self.app_name,
            "package_name": self.package_name,
            "version": self.version,
            "platform": self.platform,
            "min_api_level": self.min_api_level,
            "target_api_level": self.target_api_level,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "signing_cert": self.signing_cert,
            "additional_info": self.additional_info
        }


@dataclass
class TestCoverage:
    """Coverage information for tests executed"""
    modules_executed: List[str] = field(default_factory=list)
    tests_executed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    mastg_tests_performed: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        if self.tests_executed == 0:
            return 0.0
        return (self.tests_passed / self.tests_executed) * 100

    def to_dict(self) -> Dict:
        return {
            "modules_executed": self.modules_executed,
            "tests_executed": self.tests_executed,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_skipped": self.tests_skipped,
            "pass_rate": self.pass_rate,
            "mastg_tests_performed": self.mastg_tests_performed,
            "tools_used": self.tools_used
        }


@dataclass
class ScanResult:
    """
    Complete result of a mobile application security scan.
    Contains all findings, metrics, and metadata.
    """

    # Identifiers
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_name: str = ""

    # Application Information
    app_info: ApplicationInfo = field(default_factory=lambda: ApplicationInfo(
        app_name="", package_name="", version="", platform=""
    ))

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: int = 0

    # Findings
    findings: List[Finding] = field(default_factory=list)

    # Metrics
    risk_metrics: RiskMetrics = field(default_factory=RiskMetrics)
    test_coverage: TestCoverage = field(default_factory=TestCoverage)

    # Compliance
    masvs_l1: Optional[MAVSCompliance] = None
    masvs_l2: Optional[MAVSCompliance] = None
    masvs_r: Optional[MAVSCompliance] = None

    # Configuration
    scan_intensity: str = "full"  # quick, standard, full, comprehensive
    scan_modules: List[str] = field(default_factory=list)

    # Notes & Metadata
    tester_name: str = ""
    assessment_type: str = "Automated"  # Automated, Manual, Hybrid
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        """Add a finding to the scan results"""
        self.findings.append(finding)
        self._update_risk_metrics()

    def _update_risk_metrics(self):
        """Update risk metrics based on current findings"""
        self.risk_metrics = RiskMetrics()
        for finding in self.findings:
            severity = finding.severity
            if severity == Severity.CRITICAL:
                self.risk_metrics.critical_count += 1
            elif severity == Severity.HIGH:
                self.risk_metrics.high_count += 1
            elif severity == Severity.MEDIUM:
                self.risk_metrics.medium_count += 1
            elif severity == Severity.LOW:
                self.risk_metrics.low_count += 1
            else:  # INFO
                self.risk_metrics.info_count += 1

    def deduplicate_findings(self) -> int:
        """
        Remove duplicate findings and return count of duplicates removed.
        Uses finding hash for deduplication.
        """
        original_count = len(self.findings)
        unique_findings = {}
        for finding in self.findings:
            finding_hash = hash(finding)
            if finding_hash not in unique_findings:
                unique_findings[finding_hash] = finding
        self.findings = list(unique_findings.values())
        duplicates_removed = original_count - len(self.findings)
        self._update_risk_metrics()
        return duplicates_removed

    def finalize(self):
        """Mark scan as complete and calculate final metrics"""
        self.completed_at = datetime.utcnow()
        self.duration_seconds = int(
            (self.completed_at - self.started_at).total_seconds()
        )

    def to_dict(self) -> Dict:
        """Convert scan result to dictionary"""
        return {
            "scan_id": self.scan_id,
            "scan_name": self.scan_name,
            "app_info": self.app_info.to_dict(),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "risk_metrics": self.risk_metrics.to_dict(),
            "test_coverage": self.test_coverage.to_dict(),
            "masvs_l1": self.masvs_l1.to_dict() if self.masvs_l1 else None,
            "masvs_l2": self.masvs_l2.to_dict() if self.masvs_l2 else None,
            "masvs_r": self.masvs_r.to_dict() if self.masvs_r else None,
            "scan_intensity": self.scan_intensity,
            "scan_modules": self.scan_modules,
            "tester_name": self.tester_name,
            "assessment_type": self.assessment_type,
            "notes": self.notes,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), default=str, indent=2)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity"""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_mastg(self, mastg_category: str) -> List[Finding]:
        """Get findings by MASTG category"""
        return [f for f in self.findings if f.mastg_category == mastg_category]

    def export_to_json(self, filepath: str):
        """Export scan result to JSON file"""
        with open(filepath, 'w') as f:
            f.write(self.to_json())

    @classmethod
    def from_json(cls, json_data: str) -> 'ScanResult':
        """Create ScanResult from JSON string"""
        data = json.loads(json_data)
        # This is a simplified implementation
        # In production, implement full deserialization
        return cls(**data)
