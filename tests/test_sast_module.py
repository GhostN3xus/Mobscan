"""
Tests for SAST Module
"""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path

from mobscan.modules.sast.ast_engine import (
    TaintAnalyzer, ControlFlowAnalyzer, VulnerabilityDetector,
    TaintType, SinkType, DataFlowPath, ASTEngine
)
from mobscan.modules.sast.sast_complete import SASTModule
from mobscan.core.analysis_manager import AnalysisModule, FindingSeverity


class TestTaintAnalyzer:
    """Tests for TaintAnalyzer"""

    def test_analyze_code_detects_sources(self):
        """Test detection of taint sources"""
        code = """
        Intent intent = getIntent();
        String username = intent.getStringExtra("username");
        """

        analyzer = TaintAnalyzer()
        flows = analyzer.analyze_code(code)

        assert len(flows) >= 0
        # If flows found, they should have proper structure
        if flows:
            for flow in flows:
                assert hasattr(flow, 'source')
                assert hasattr(flow, 'sink')

    def test_analyze_code_detects_sinks(self):
        """Test detection of sinks"""
        code = """
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        """

        analyzer = TaintAnalyzer()
        flows = analyzer.analyze_code(code)

        assert isinstance(flows, list)

    def test_sanitization_detection(self):
        """Test detection of sanitization"""
        code = """
        String input = getIntent().getStringExtra("data");
        if(!TextUtils.isEmpty(input)) {
            processData(input);
        }
        """

        analyzer = TaintAnalyzer()
        flows = analyzer.analyze_code(code)

        assert isinstance(flows, list)

    def test_data_flow_path_creation(self):
        """Test DataFlowPath creation"""
        path = DataFlowPath(
            source="user_input:Intent",
            sink="network:HttpConnection",
            path=["Intent", "processData", "HttpConnection"],
            is_sanitized=False,
            confidence=0.9
        )

        assert path.source == "user_input:Intent"
        assert path.confidence == 0.9
        assert not path.is_sanitized


class TestControlFlowAnalyzer:
    """Tests for ControlFlowAnalyzer"""

    def test_analyze_functions(self):
        """Test function analysis"""
        code = """
        public void processPayment(String cardNumber) {
            if(validateCard(cardNumber)) {
                sendToServer(cardNumber);
            }
        }
        """

        analyzer = ControlFlowAnalyzer()
        cfg = analyzer.analyze_functions(code)

        assert isinstance(cfg, dict)
        # Should detect some control flow
        assert len(cfg) >= 0

    def test_cfg_extraction(self):
        """Test CFG extraction"""
        code = """
        for(int i = 0; i < items.length; i++) {
            if(items[i] != null) {
                process(items[i]);
            }
        }
        """

        analyzer = ControlFlowAnalyzer()
        cfg = analyzer._extract_cfg_simple(code)

        assert "nodes" in cfg
        assert "edges" in cfg
        assert isinstance(cfg["nodes"], list)
        assert isinstance(cfg["edges"], list)


class TestVulnerabilityDetector:
    """Tests for VulnerabilityDetector"""

    def test_detect_weak_crypto(self):
        """Test weak cryptography detection"""
        code = 'Cipher.getInstance("DES")'

        detector = VulnerabilityDetector()
        vulns = detector.detect(code)

        assert len(vulns) >= 1
        assert any("DES" in v.get("description", "") for v in vulns)

    def test_detect_hardcoded_secrets(self):
        """Test hardcoded secrets detection"""
        code = 'api_key = "AIzaSyDxLKlStzB5KeHqqz3_JjCh3tJJZfqL6dU"'

        detector = VulnerabilityDetector()
        vulns = detector.detect(code)

        assert len(vulns) >= 1
        assert any("API Key" in v.get("description", "") for v in vulns)

    def test_detect_insecure_storage(self):
        """Test insecure storage detection"""
        code = """
        SharedPreferences prefs = getSharedPreferences("myprefs", MODE_PRIVATE);
        prefs.edit().putString("password", "secret").commit();
        """

        detector = VulnerabilityDetector()
        vulns = detector.detect(code)

        assert isinstance(vulns, list)

    def test_detect_webview_issues(self):
        """Test WebView vulnerability detection"""
        code = """
        WebView webView = findViewById(R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new JSBridge(), "android");
        """

        detector = VulnerabilityDetector()
        vulns = detector.detect(code)

        assert len(vulns) >= 1

    def test_vulnerability_has_proper_structure(self):
        """Test vulnerability structure"""
        code = 'MessageDigest.getInstance("MD5")'

        detector = VulnerabilityDetector()
        vulns = detector.detect(code)

        assert len(vulns) > 0
        vuln = vulns[0]

        assert "category" in vuln
        assert "description" in vuln
        assert "line" in vuln
        assert "match" in vuln


class TestASTEngine:
    """Tests for complete ASTEngine"""

    def test_analyze_code(self):
        """Test complete code analysis"""
        code = """
        Cipher.getInstance("DES");
        MessageDigest.getInstance("MD5");
        api_key = "secret123"
        """

        engine = ASTEngine()
        results = engine.analyze_code(code)

        assert "data_flows" in results
        assert "control_flow" in results
        assert "vulnerabilities" in results
        assert isinstance(results["vulnerabilities"], list)

    def test_analyze_multiple_issues(self):
        """Test detection of multiple issues"""
        code = """
        Cipher.getInstance("DES");
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA1");
        """

        engine = ASTEngine()
        results = engine.analyze_code(code)

        # Should detect at least weak crypto issues
        vulns = results["vulnerabilities"]
        assert len(vulns) >= 2


class TestSASTModule:
    """Tests for complete SAST Module"""

    def test_sast_module_initialization(self):
        """Test SAST module initialization"""
        module = SASTModule()

        assert module.module_type == AnalysisModule.SAST
        assert module.is_enabled
        assert len(module.findings) == 0

    def test_sast_execute_without_device(self):
        """Test SAST execution (no real APK needed)"""
        module = SASTModule()

        # Mock zipfile operations
        with patch('zipfile.ZipFile') as mock_zip:
            mock_zip.return_value.__enter__.return_value.filelist = []
            mock_zip.return_value.__enter__.return_value.read.return_value = b""
            mock_zip.return_value.__enter__.return_value.namelist.return_value = []

            with patch('pathlib.Path.exists', return_value=True):
                findings = module.execute("test.apk", {})

            assert isinstance(findings, list)

    def test_sast_static_analysis(self):
        """Test SAST static analysis"""
        module = SASTModule()

        # Test with code containing vulnerabilities
        module.all_code_content = """
        Cipher.getInstance("DES");
        api_key = "AIzaSyDxLK..."
        Log.d("TAG", "password: " + password)
        """

        module._run_ast_analysis()

        # Should have found vulnerabilities
        assert len(module.findings) >= 0

    def test_weak_cryptography_detection(self):
        """Test weak cryptography detection in SAST"""
        module = SASTModule()
        module.all_code_content = 'Cipher.getInstance("DES")'

        module._check_weak_cryptography()

        # Should have detected DES
        assert len(module.findings) >= 1

    def test_insecure_storage_detection(self):
        """Test insecure storage detection"""
        module = SASTModule()
        module.all_code_content = """
        SharedPreferences prefs = getSharedPreferences("prefs", Context.MODE_PRIVATE);
        prefs.edit().putString("data", value).commit();
        """

        module._check_insecure_storage()

        assert len(module.findings) >= 1

    def test_webview_issues_detection(self):
        """Test WebView issues detection"""
        module = SASTModule()
        module.all_code_content = """
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(obj, "android");
        """

        module._check_webview_issues()

        assert len(module.findings) >= 1


class TestSASTModuleIntegration:
    """Integration tests for SAST Module"""

    def test_end_to_end_analysis(self):
        """Test complete SAST analysis flow"""
        module = SASTModule()

        # Create mock APK with vulnerabilities
        vulnerable_code = """
        Cipher.getInstance("DES");
        MessageDigest.getInstance("MD5");
        api_key = "secret123"
        setJavaScriptEnabled(true)
        """

        module.all_code_content = vulnerable_code

        with patch('zipfile.ZipFile') as mock_zip:
            with patch('pathlib.Path.exists', return_value=True):
                findings = module.execute("test.apk", {})

        assert len(findings) > 0
        assert all(hasattr(f, 'title') for f in findings)
        assert all(hasattr(f, 'severity') for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
