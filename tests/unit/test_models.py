"""Unit tests for data models"""

import pytest
from datetime import datetime

from mobscan.models.finding import Finding, Severity, CVSSScore, Evidence, Remediation
from mobscan.models.scan_result import ScanResult, ApplicationInfo, RiskMetrics
from mobscan.models.masvs_mapping import MAVSMapping, MAVSLevel


class TestCVSSScore:
    """Test CVSS Score calculation"""

    def test_cvss_critical_severity(self):
        score = CVSSScore(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score.severity == Severity.CRITICAL

    def test_cvss_high_severity(self):
        score = CVSSScore(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert score.severity == Severity.HIGH

    def test_cvss_medium_severity(self):
        score = CVSSScore(5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
        assert score.severity == Severity.MEDIUM


class TestFinding:
    """Test Finding model"""

    def test_finding_creation(self):
        finding = Finding(
            id="TEST-001",
            title="Test Vulnerability",
            description="Test description",
            severity=Severity.HIGH,
            cvss=CVSSScore(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            cwe=["CWE-78"],
            owasp_category="A02:2021",
            test_name="Test Case",
            module="sast",
            mastg_category="MASTG-CODE-1",
            masvs_category="MSTG-CODE-1",
            affected_component="TestComponent"
        )

        assert finding.id == "TEST-001"
        assert finding.title == "Test Vulnerability"
        assert finding.severity == Severity.HIGH

    def test_finding_add_evidence(self):
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            cvss=CVSSScore(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            cwe=[],
            owasp_category="",
            test_name="",
            module="test",
            mastg_category="MASTG-CODE-1",
            masvs_category="MSTG-CODE-1",
            affected_component="Test"
        )

        evidence = Evidence(
            type="code",
            content="sensitive_data = 'hardcoded_value'"
        )
        finding.add_evidence(evidence)

        assert len(finding.evidence) == 1
        assert finding.evidence[0].type == "code"

    def test_finding_to_dict(self):
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            cvss=CVSSScore(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            cwe=["CWE-78"],
            owasp_category="A02:2021",
            test_name="Test",
            module="sast",
            mastg_category="MASTG-CODE-1",
            masvs_category="MSTG-CODE-1",
            affected_component="Test"
        )

        finding_dict = finding.to_dict()
        assert finding_dict["id"] == "TEST-001"
        assert finding_dict["severity"] == "High"
        assert finding_dict["cvss_score"]["score"] == 7.5


class TestScanResult:
    """Test ScanResult model"""

    def test_scan_result_creation(self):
        result = ScanResult(
            scan_name="TestScan",
            app_info=ApplicationInfo(
                app_name="TestApp",
                package_name="com.test.app",
                version="1.0.0",
                platform="android"
            )
        )

        assert result.scan_name == "TestScan"
        assert result.app_info.app_name == "TestApp"

    def test_scan_result_add_finding(self):
        result = ScanResult()
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.CRITICAL,
            cvss=CVSSScore(9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            cwe=[],
            owasp_category="",
            test_name="",
            module="test",
            mastg_category="MASTG-CODE-1",
            masvs_category="MSTG-CODE-1",
            affected_component="Test"
        )

        result.add_finding(finding)

        assert len(result.findings) == 1
        assert result.risk_metrics.critical_count == 1

    def test_risk_metrics_calculation(self):
        metrics = RiskMetrics(
            critical_count=1,
            high_count=2,
            medium_count=3,
            low_count=4
        )

        assert metrics.total_count == 10
        assert metrics.risk_score > 0
        assert metrics.risk_score <= 10.0

    def test_scan_result_finalize(self):
        result = ScanResult()
        result.finalize()

        assert result.completed_at is not None
        assert result.duration_seconds >= 0


class TestMAVSMapping:
    """Test MASVS mapping"""

    def test_get_requirement(self):
        req = MAVSMapping.get_requirement("MSTG-STORAGE-1")
        assert req is not None
        assert req.id == "MSTG-STORAGE-1"

    def test_get_requirements_by_level(self):
        reqs_l1 = MAVSMapping.get_requirements_by_level(MAVSLevel.L1)
        assert len(reqs_l1) > 0

        reqs_l2 = MAVSMapping.get_requirements_by_level(MAVSLevel.L2)
        assert len(reqs_l2) > 0

    def test_map_mastg_to_masvs(self):
        reqs = MAVSMapping.map_mastg_to_masvs("MASTG-STORAGE-1")
        # Should return requirements that reference this MASTG test
        assert isinstance(reqs, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
