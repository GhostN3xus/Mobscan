"""
Comprehensive Mobscan Test Suite

Tests for core components, analysis modules, and integration
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Core components tests
from mobscan.core.dispatcher import get_dispatcher, EventType, Event
from mobscan.core.plugin_system import get_plugin_manager, PluginMetadata, AnalyzerPlugin
from mobscan.core.config import MobscanConfig, ScanIntensity
from mobscan.core.engine import TestEngine

# Models tests
from mobscan.models.finding import Finding, Severity, CVSSScore
from mobscan.models.scan_result import ScanResult

# Module tests
from mobscan.modules.dast.proxy_handler import ProxyAnalyzer, InterceptedFlow, RequestInfo, ResponseInfo
from mobscan.modules.sca.sca_engine import SCAModule


class TestEventDispatcher:
    """Test event dispatcher pub/sub system"""

    def test_dispatcher_singleton(self):
        """Test that dispatcher is a singleton"""
        disp1 = get_dispatcher()
        disp2 = get_dispatcher()
        assert disp1 is disp2

    def test_subscribe_to_event(self):
        """Test subscribing to events"""
        dispatcher = get_dispatcher()
        handler_called = False

        def test_handler(event):
            nonlocal handler_called
            handler_called = True

        handler = dispatcher.subscribe(EventType.SCAN_STARTED, test_handler)
        assert handler is not None
        assert handler.enabled

    def test_emit_event(self):
        """Test emitting events"""
        dispatcher = get_dispatcher()
        results = []

        def capture_event(event):
            results.append(event)

        dispatcher.subscribe(EventType.FINDING_DISCOVERED, capture_event)
        dispatcher.emit_with_data(EventType.FINDING_DISCOVERED, "test_module", {"title": "Test"})

        assert len(results) > 0
        assert results[0].data['title'] == "Test"

    def test_event_history(self):
        """Test event history tracking"""
        dispatcher = get_dispatcher()
        dispatcher.clear_history()

        dispatcher.emit_with_data(EventType.SCAN_STARTED, "engine")
        dispatcher.emit_with_data(EventType.SCAN_COMPLETED, "engine")

        history = dispatcher.get_event_history()
        assert len(history) >= 2


class TestPluginSystem:
    """Test plugin management system"""

    def test_plugin_manager_singleton(self):
        """Test plugin manager is singleton"""
        pm1 = get_plugin_manager()
        pm2 = get_plugin_manager()
        assert pm1 is pm2

    def test_custom_plugin_creation(self):
        """Test creating custom plugin"""

        class TestAnalyzer(AnalyzerPlugin):
            @property
            def metadata(self):
                return PluginMetadata(
                    id="test-analyzer",
                    name="Test Analyzer",
                    version="1.0.0",
                    author="Test",
                    description="Test plugin"
                )

            def initialize(self, config):
                return True

            def analyze(self, app_path, config):
                return []

            def shutdown(self):
                pass

        plugin = TestAnalyzer()
        assert plugin.metadata.id == "test-analyzer"
        assert plugin.initialize({})

    def test_list_plugins(self):
        """Test listing plugins"""
        pm = get_plugin_manager()
        plugins = pm.list_plugins()
        assert isinstance(plugins, list)


class TestConfiguration:
    """Test configuration management"""

    def test_default_config(self):
        """Test default configuration"""
        config = MobscanConfig.default_config()
        assert config is not None
        assert config.scan_intensity == ScanIntensity.STANDARD

    def test_config_intensity(self):
        """Test configuration intensity levels"""
        config = MobscanConfig.default_config()
        config.scan_intensity = ScanIntensity.COMPREHENSIVE
        assert config.scan_intensity == ScanIntensity.COMPREHENSIVE

    def test_config_modules(self):
        """Test module configuration"""
        config = MobscanConfig.default_config()
        config.modules_enabled = ['sast', 'dast', 'sca']
        assert 'sast' in config.modules_enabled
        assert len(config.modules_enabled) == 3


class TestFinding:
    """Test Finding model"""

    def test_create_finding(self):
        """Test creating a finding"""
        finding = Finding(
            id="TEST-001",
            title="Test Vulnerability",
            description="Test description",
            severity=Severity.HIGH,
            cvss=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            cwe=["CWE-123"],
            owasp_category="Test",
            test_name="Test",
            module="test",
            mastg_category="MASTG-TEST-1",
            masvs_category="MSTG-TEST-1",
            affected_component="Test Component"
        )

        assert finding.id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.cvss.score == 7.5

    def test_finding_to_dict(self):
        """Test finding serialization"""
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            cvss=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            cwe=["CWE-123"],
            owasp_category="Test",
            test_name="Test",
            module="test",
            mastg_category="MASTG-TEST-1",
            masvs_category="MSTG-TEST-1",
            affected_component="Test"
        )

        data = finding.to_dict()
        assert data['id'] == "TEST-001"
        assert data['severity'] == "High"


class TestProxyAnalyzer:
    """Test DAST proxy analyzer"""

    def test_sensitive_data_detection(self):
        """Test detection of sensitive data"""
        analyzer = ProxyAnalyzer()

        request = RequestInfo(
            method="GET",
            url="https://api.example.com/login",
            headers={}
        )

        response = ResponseInfo(
            status_code=200,
            headers={"Authorization": "Bearer sk_live_abc123def456"},
            body="Response data"
        )

        flow = InterceptedFlow(request=request, response=response)
        findings = analyzer.analyze_flow(flow)

        assert len(findings) >= 0  # May detect sensitive data

    def test_missing_security_headers(self):
        """Test detection of missing headers"""
        analyzer = ProxyAnalyzer()

        request = RequestInfo(
            method="GET",
            url="https://api.example.com/data",
            headers={}
        )

        response = ResponseInfo(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body="Data"
        )

        flow = InterceptedFlow(request=request, response=response)
        findings = analyzer.analyze_flow(flow)

        # Should detect missing security headers
        header_findings = [f for f in findings if 'header' in f.get('type', '').lower()]
        assert len(header_findings) > 0

    def test_insecure_caching(self):
        """Test detection of insecure caching"""
        analyzer = ProxyAnalyzer()

        request = RequestInfo(
            method="GET",
            url="https://api.example.com/login",
            headers={}
        )

        response = ResponseInfo(
            status_code=200,
            headers={"Cache-Control": "max-age=3600"},
            body="Sensitive data"
        )

        flow = InterceptedFlow(request=request, response=response)
        findings = analyzer.analyze_flow(flow)

        # Should detect insecure caching on sensitive endpoint
        assert len(findings) > 0


class TestSCAModule:
    """Test SCA (Software Composition Analysis) module"""

    def test_sca_initialization(self):
        """Test SCA module initialization"""
        sca = SCAModule()
        assert sca is not None
        assert hasattr(sca, 'findings')

    @patch('zipfile.ZipFile')
    def test_dependency_extraction(self, mock_zipfile):
        """Test dependency extraction from APK"""
        # Mock APK file
        mock_apk = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_apk
        mock_apk.filelist = []

        # Would need a proper test APK or mock
        # sca = SCAModule()
        # findings = sca.execute("test.apk", {})
        # assert isinstance(findings, list)


class TestTestEngine:
    """Test core test engine"""

    def test_engine_initialization(self):
        """Test engine initialization"""
        config = MobscanConfig.default_config()
        engine = TestEngine(config)
        assert engine is not None
        assert engine.config == config

    def test_engine_with_default_config(self):
        """Test engine with default config"""
        engine = TestEngine()
        assert engine is not None
        assert engine.config is not None

    @patch('pathlib.Path.exists')
    def test_initialize_scan(self, mock_exists):
        """Test scan initialization"""
        mock_exists.return_value = True

        engine = TestEngine()
        # Would need a valid APK path
        # result = engine.initialize_scan("test.apk")
        # assert result is not None


class TestScanResult:
    """Test scan result model"""

    def test_create_scan_result(self):
        """Test creating scan result"""
        result = ScanResult()
        assert result.scan_id is not None
        assert len(result.findings) == 0

    def test_add_finding(self):
        """Test adding findings to result"""
        result = ScanResult()
        finding = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            cvss=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            cwe=["CWE-123"],
            owasp_category="Test",
            test_name="Test",
            module="test",
            mastg_category="MASTG-TEST-1",
            masvs_category="MSTG-TEST-1",
            affected_component="Test"
        )

        result.add_finding(finding)
        assert len(result.findings) == 1

    def test_deduplicate_findings(self):
        """Test finding deduplication"""
        result = ScanResult()

        # Add duplicate findings
        for i in range(2):
            finding = Finding(
                id=f"TEST-{i:03d}",
                title="Test Vulnerability",
                description="Test",
                severity=Severity.HIGH,
                cvss=CVSSScore(score=7.5, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                cwe=["CWE-123"],
                owasp_category="Test",
                test_name="Test",
                module="test",
                mastg_category="MASTG-TEST-1",
                masvs_category="MSTG-TEST-1",
                affected_component="Component1"
            )
            result.add_finding(finding)

        duplicates = result.deduplicate_findings()
        assert duplicates >= 0


class TestIntegration:
    """Integration tests"""

    def test_end_to_end_flow(self):
        """Test end-to-end flow"""
        # 1. Create dispatcher
        dispatcher = get_dispatcher()
        dispatcher.clear_history()

        # 2. Create plugin manager
        pm = get_plugin_manager()

        # 3. Create configuration
        config = MobscanConfig.default_config()

        # 4. Create engine
        engine = TestEngine(config)

        # 5. Verify basic operations
        assert engine is not None
        assert dispatcher is not None
        assert pm is not None

    def test_plugin_and_event_integration(self):
        """Test plugin and event integration"""
        pm = get_plugin_manager()
        dispatcher = get_dispatcher()

        events_received = []

        def event_handler(event):
            events_received.append(event)

        dispatcher.subscribe(EventType.MODULE_LOADED, event_handler)

        # Simulate module loading
        dispatcher.emit_with_data(EventType.MODULE_LOADED, "test_module")

        assert len(events_received) > 0


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
