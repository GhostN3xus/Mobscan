"""
Comprehensive Tests for AnalysisManager and Core Modules
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from mobscan.core.analysis_manager import (
    AnalysisManager, AnalysisConfig, BaseAnalysisModule, AnalysisModule,
    Finding, FindingSeverity, EvidenceItem
)


class MockSASTModule(BaseAnalysisModule):
    """Mock SAST Module for testing"""

    def __init__(self):
        super().__init__(AnalysisModule.SAST, "Mock SAST")

    def execute(self, app_path: str, config: dict) -> list:
        """Returns mock findings"""
        return [
            Finding(
                id="TEST-001",
                title="Test Finding",
                description="A test finding",
                severity=FindingSeverity.HIGH.value,
                category="A02:2021 - Cryptographic Failures",
                module=AnalysisModule.SAST.value,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe=["CWE-327"],
                masvs_mapping=["MSTG-CRYPTO-1"],
            )
        ]


class TestAnalysisManager:
    """Tests for AnalysisManager class"""

    def test_initialization(self):
        """Test AnalysisManager initialization"""
        manager = AnalysisManager()
        assert manager is not None
        assert len(manager.modules) == 0
        assert manager.scan_id is not None

    def test_register_module(self):
        """Test module registration"""
        manager = AnalysisManager()
        module = MockSASTModule()

        manager.register_module(module)
        assert AnalysisModule.SAST in manager.modules
        assert manager.modules[AnalysisModule.SAST] == module

    def test_enable_disable_module(self):
        """Test enable/disable module"""
        manager = AnalysisManager()
        module = MockSASTModule()
        manager.register_module(module)

        manager.disable_module(AnalysisModule.SAST)
        assert not manager.modules[AnalysisModule.SAST].is_enabled

        manager.enable_module(AnalysisModule.SAST)
        assert manager.modules[AnalysisModule.SAST].is_enabled

    def test_run_analysis(self):
        """Test complete analysis pipeline"""
        manager = AnalysisManager()
        module = MockSASTModule()
        manager.register_module(module)

        # Create mock app file
        with patch('pathlib.Path.exists', return_value=True):
            result = manager.run_analysis("mock_app.apk")

            assert "scan_id" in result
            assert "total_findings" in result
            assert "findings" in result
            assert result["total_findings"] >= 0

    def test_findings_validation(self):
        """Test findings validation"""
        manager = AnalysisManager()

        # Add invalid finding
        invalid_finding = Finding(
            id="",  # Invalid - empty id
            title="Test",
            description="Test",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        )

        manager.findings.append(invalid_finding)
        manager._validate_findings()

        # Invalid finding should be removed
        assert len(manager.findings) == 0

    def test_findings_deduplication(self):
        """Test findings deduplication"""
        manager = AnalysisManager()

        # Create two identical findings
        finding1 = Finding(
            id="TEST-001",
            title="Duplicate Finding",
            description="Duplicate",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            location="file.txt",
            affected_component="Component"
        )

        finding2 = Finding(
            id="TEST-002",
            title="Duplicate Finding",
            description="Duplicate",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            location="file.txt",
            affected_component="Component"
        )

        manager.findings = [finding1, finding2]
        manager._correlate_findings()

        # Should have only one after deduplication
        assert len(manager.findings) == 1

    def test_severity_scoring(self):
        """Test severity scoring"""
        manager = AnalysisManager()

        # Add findings with different severities
        findings = [
            Finding(
                id=f"TEST-{i:03d}",
                title=f"Finding {i}",
                description="Test",
                severity=severity,
                category="Test",
                module="sast",
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            )
            for i, (severity, cvss) in enumerate([
                (FindingSeverity.CRITICAL.value, 9.8),
                (FindingSeverity.HIGH.value, 7.5),
                (FindingSeverity.MEDIUM.value, 5.3),
                (FindingSeverity.LOW.value, 2.0),
            ])
        ]

        manager.findings = findings
        manager._apply_scoring()

        # Risk score should be calculated
        risk_score = manager._calculate_risk_score()
        assert 0 <= risk_score <= 10

    def test_export_findings_json(self):
        """Test JSON export"""
        manager = AnalysisManager()
        manager.findings = [
            Finding(
                id="TEST-001",
                title="Test",
                description="Test",
                severity=FindingSeverity.HIGH.value,
                category="Test",
                module="sast",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            )
        ]

        json_export = manager.export_findings("json")
        parsed = json.loads(json_export)

        assert isinstance(parsed, list)
        assert len(parsed) > 0
        assert parsed[0]["title"] == "Test"

    def test_export_findings_csv(self):
        """Test CSV export"""
        manager = AnalysisManager()
        manager.findings = [
            Finding(
                id="TEST-001",
                title="Test Finding",
                description="Test",
                severity=FindingSeverity.HIGH.value,
                category="Test",
                module="sast",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                affected_component="TestComponent"
            )
        ]

        csv_export = manager.export_findings("csv")

        assert "id,title" in csv_export
        assert "TEST-001" in csv_export
        assert "Test Finding" in csv_export

    def test_get_statistics(self):
        """Test statistics generation"""
        manager = AnalysisManager()
        manager.findings = [
            Finding(
                id="TEST-001",
                title="Test",
                description="Test",
                severity=FindingSeverity.HIGH.value,
                category="Test",
                module="sast",
                cvss_score=5.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            )
        ]

        stats = manager.get_statistics()

        assert "scan_id" in stats
        assert "total_findings" in stats
        assert "risk_score" in stats
        assert stats["total_findings"] == 1


class TestFinding:
    """Tests for Finding class"""

    def test_finding_creation(self):
        """Test Finding creation"""
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            description="A test finding",
            severity=FindingSeverity.HIGH.value,
            category="A02:2021",
            module="sast",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )

        assert finding.id == "TEST-001"
        assert finding.title == "Test Finding"
        assert finding.severity == FindingSeverity.HIGH.value

    def test_finding_hash_calculation(self):
        """Test Finding hash calculation for deduplication"""
        finding1 = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            location="file.txt",
            affected_component="Component"
        )

        finding2 = Finding(
            id="TEST-002",
            title="Test",
            description="Test",
            severity=FindingSeverity.MEDIUM.value,
            category="Test",
            module="sast",
            cvss_score=3.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            location="file.txt",
            affected_component="Component"
        )

        hash1 = finding1.calculate_hash()
        hash2 = finding2.calculate_hash()

        # Same location and component = same hash
        assert hash1 == hash2

    def test_finding_to_dict(self):
        """Test Finding to dictionary conversion"""
        evidence = EvidenceItem(
            type="code",
            location="test.java",
            content="test content"
        )

        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            evidence=[evidence]
        )

        finding_dict = finding.to_dict()

        assert isinstance(finding_dict, dict)
        assert finding_dict["id"] == "TEST-001"
        assert len(finding_dict["evidence"]) == 1

    def test_finding_to_json(self):
        """Test Finding to JSON conversion"""
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=FindingSeverity.HIGH.value,
            category="Test",
            module="sast",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        )

        json_str = finding.to_json()
        parsed = json.loads(json_str)

        assert parsed["title"] == "Test"
        assert parsed["severity"] == "high"


class TestEvidenceItem:
    """Tests for EvidenceItem class"""

    def test_evidence_creation(self):
        """Test EvidenceItem creation"""
        evidence = EvidenceItem(
            type="code",
            location="test.java",
            content="test content",
            line_number=42
        )

        assert evidence.type == "code"
        assert evidence.location == "test.java"
        assert evidence.line_number == 42


class TestAnalysisConfig:
    """Tests for AnalysisConfig"""

    def test_config_defaults(self):
        """Test AnalysisConfig defaults"""
        config = AnalysisConfig()

        assert config.timeout_per_module == 300
        assert config.parallel_execution is True
        assert config.enable_deduplication is True
        assert config.enable_correlation is True

    def test_config_custom_values(self):
        """Test custom AnalysisConfig values"""
        config = AnalysisConfig(
            timeout_per_module=500,
            parallel_execution=False,
            max_workers=2
        )

        assert config.timeout_per_module == 500
        assert config.parallel_execution is False
        assert config.max_workers == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
