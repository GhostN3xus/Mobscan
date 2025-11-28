"""
Test Engine - Core orchestration engine

Manages the execution of security tests, coordinates between modules,
aggregates findings, and produces reports.
"""

import asyncio
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
import concurrent.futures
import json

from ..models.scan_result import ScanResult, ApplicationInfo, TestCoverage, RiskMetrics
from ..models.finding import Finding, Severity
from ..models.masvs_mapping import MAVSMapping, MAVSLevel
from .config import MobscanConfig


logger = logging.getLogger(__name__)


class TestEngine:
    """
    Main orchestration engine for mobile security testing.

    Responsibilities:
    - Load and validate configuration
    - Coordinate between test modules
    - Manage test execution workflow
    - Aggregate findings and results
    - Generate reports
    """

    def __init__(self, config: Optional[MobscanConfig] = None):
        """
        Initialize the test engine.

        Args:
            config: MobscanConfig instance. If None, uses default config.
        """
        self.config = config or MobscanConfig.default_config()
        self.logger = self._setup_logging()
        self.scan_result: Optional[ScanResult] = None
        self.test_modules: Dict[str, Any] = {}

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("mobscan.engine")
        logger.setLevel(getattr(logging, self.config.log_level))

        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def initialize_scan(self, app_path: str, app_name: str = "") -> ScanResult:
        """
        Initialize a new scan and create ScanResult object.

        Args:
            app_path: Path to the APK/IPA file
            app_name: Display name for the application

        Returns:
            ScanResult: Initialized scan result object
        """
        self.logger.info(f"Initializing scan for {app_path}")

        # Validate app file
        if not Path(app_path).exists():
            raise FileNotFoundError(f"Application file not found: {app_path}")

        # Create scan result
        self.scan_result = ScanResult()
        self.scan_result.scan_name = app_name or Path(app_path).stem
        self.scan_result.scan_intensity = self.config.scan_intensity.value
        self.scan_result.scan_modules = self.config.modules_enabled
        self.scan_result.assessment_type = "Automated"

        # Extract app information
        self.scan_result.app_info = self._extract_app_info(app_path)

        # Initialize test coverage
        self.scan_result.test_coverage = TestCoverage(
            modules_executed=self.config.modules_enabled
        )

        self.logger.info(f"Scan initialized: {self.scan_result.scan_id}")
        return self.scan_result

    def _extract_app_info(self, app_path: str) -> ApplicationInfo:
        """
        Extract application information from APK/IPA.

        This is a placeholder - in production, integrate with real parsers.
        """
        app_file = Path(app_path)

        return ApplicationInfo(
            app_name=app_file.stem,
            package_name="com.example.app",  # Would extract from manifest
            version="1.0.0",                 # Would extract from manifest
            platform="android" if app_file.suffix == ".apk" else "ios",
            file_size=app_file.stat().st_size,
            file_hash="",  # Would calculate SHA256
        )

    def load_test_modules(self):
        """Load and register all test modules"""
        self.logger.info("Loading test modules...")

        # Module loading logic would go here
        # For now, this is a placeholder

        if self.config.is_module_enabled("sast"):
            self.logger.info("  - SAST module loaded")
            self.test_modules["sast"] = {}

        if self.config.is_module_enabled("dast"):
            self.logger.info("  - DAST module loaded")
            self.test_modules["dast"] = {}

        if self.config.is_module_enabled("frida"):
            self.logger.info("  - Frida module loaded")
            self.test_modules["frida"] = {}

        self.logger.info(f"Total modules loaded: {len(self.test_modules)}")

    def execute_tests(self) -> ScanResult:
        """
        Execute all configured tests.

        Returns:
            ScanResult: Completed scan result with all findings
        """
        if not self.scan_result:
            raise RuntimeError("Scan not initialized. Call initialize_scan first.")

        self.logger.info("Starting test execution...")
        self.load_test_modules()

        try:
            # Execute tests in parallel
            self._execute_parallel_tests()

            # Deduplicate findings
            duplicates = self.scan_result.deduplicate_findings()
            self.logger.info(f"Removed {duplicates} duplicate findings")

            # Map findings to MASVS
            self._map_findings_to_masvs()

            # Calculate final metrics
            self.scan_result.finalize()
            self.logger.info(f"Scan completed. Total findings: {len(self.scan_result.findings)}")

        except Exception as e:
            self.logger.error(f"Error during test execution: {str(e)}", exc_info=True)
            raise

        return self.scan_result

    def _execute_parallel_tests(self):
        """Execute tests in parallel using thread pool"""
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.parallel_workers
        )

        futures = []

        # Submit SAST tests
        if "sast" in self.test_modules:
            self.logger.info("Submitting SAST tests...")
            futures.append(executor.submit(self._run_sast_tests))

        # Submit DAST tests
        if "dast" in self.test_modules:
            self.logger.info("Submitting DAST tests...")
            futures.append(executor.submit(self._run_dast_tests))

        # Submit Frida tests
        if "frida" in self.test_modules:
            self.logger.info("Submitting Frida instrumentation tests...")
            futures.append(executor.submit(self._run_frida_tests))

        # Wait for all tests to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result(timeout=self.config.timeout_global)
            except Exception as e:
                self.logger.error(f"Test execution failed: {str(e)}")

        executor.shutdown(wait=True)

    def _run_sast_tests(self):
        """Execute static analysis tests"""
        self.logger.info("Running SAST tests...")

        # Sample findings for demonstration
        # In production, integrate with MobSF, JADX, etc.

        finding = Finding(
            id="FINDING-001",
            title="Hardcoded API Credentials",
            description="API credentials found hardcoded in source code",
            severity=Severity.CRITICAL,
            cvss=self._create_cvss_score(9.8),
            cwe=["CWE-798"],
            owasp_category="A02:2021 - Cryptographic Failures",
            test_name="Hardcoded Secrets Detection",
            module="sast",
            mastg_category="MASTG-STORAGE-1",
            masvs_category="MSTG-STORAGE-1",
            affected_component="NetworkManager.java"
        )

        self.scan_result.add_finding(finding)
        self.logger.info("SAST tests completed")

    def _run_dast_tests(self):
        """Execute dynamic analysis tests"""
        self.logger.info("Running DAST tests...")

        # Sample findings
        finding = Finding(
            id="FINDING-002",
            title="Insecure Certificate Pinning",
            description="Certificate pinning not implemented or incorrectly implemented",
            severity=Severity.HIGH,
            cvss=self._create_cvss_score(7.5),
            cwe=["CWE-295"],
            owasp_category="A04:2021 - Insecure Design",
            test_name="Certificate Pinning Validation",
            module="dast",
            mastg_category="MASTG-NET-2",
            masvs_category="MSTG-NET-2",
            affected_component="API Communication Layer"
        )

        self.scan_result.add_finding(finding)
        self.logger.info("DAST tests completed")

    def _run_frida_tests(self):
        """Execute instrumentation tests with Frida"""
        self.logger.info("Running Frida instrumentation tests...")

        # Sample findings
        finding = Finding(
            id="FINDING-003",
            title="Root Detection Bypass",
            description="Root detection mechanism can be bypassed",
            severity=Severity.MEDIUM,
            cvss=self._create_cvss_score(5.5),
            cwe=["CWE-656"],
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
            test_name="Root Detection Bypass",
            module="frida",
            mastg_category="MASTG-RESILIENCE-1",
            masvs_category="MSTG-RESILIENCE-1",
            affected_component="Security Check Method"
        )

        self.scan_result.add_finding(finding)
        self.logger.info("Frida tests completed")

    def _create_cvss_score(self, score: float) -> Dict:
        """Create CVSS score object"""
        vectors = {
            9.8: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            7.5: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            5.5: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        }
        return {
            "score": score,
            "vector": vectors.get(score, f"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        }

    def _map_findings_to_masvs(self):
        """Map findings to MASVS requirements"""
        self.logger.info("Mapping findings to MASVS requirements...")

        for finding in self.scan_result.findings:
            # Find related MASVS requirements
            masvs_reqs = MAVSMapping.map_mastg_to_masvs(finding.mastg_category)

            if masvs_reqs:
                finding.masvs_category = masvs_reqs[0].id

        # Calculate MASVS compliance
        self._calculate_masvs_compliance()

    def _calculate_masvs_compliance(self):
        """Calculate MASVS compliance levels"""
        # This would calculate L1, L2, and R compliance
        # Implementation would check if requirements are met/failed
        pass

    def generate_report(self, format: str = "json") -> str:
        """
        Generate report in specified format.

        Args:
            format: Report format (json, pdf, docx, markdown)

        Returns:
            str: Report content or filepath
        """
        if not self.scan_result:
            raise RuntimeError("No scan result available")

        self.logger.info(f"Generating {format} report...")

        if format == "json":
            return self.scan_result.to_json()
        elif format == "pdf":
            return self._generate_pdf_report()
        elif format == "docx":
            return self._generate_docx_report()
        elif format == "markdown":
            return self._generate_markdown_report()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_pdf_report(self) -> str:
        """Generate PDF report"""
        self.logger.info("Generating PDF report...")
        # Implementation would use reportlab or similar
        return "report.pdf"

    def _generate_docx_report(self) -> str:
        """Generate DOCX report"""
        self.logger.info("Generating DOCX report...")
        # Implementation would use python-docx
        return "report.docx"

    def _generate_markdown_report(self) -> str:
        """Generate Markdown report"""
        self.logger.info("Generating Markdown report...")

        md = f"""# Security Assessment Report

## Executive Summary

**App**: {self.scan_result.app_info.app_name}
**Package**: {self.scan_result.app_info.package_name}
**Platform**: {self.scan_result.app_info.platform.upper()}
**Scan Date**: {self.scan_result.started_at.isoformat()}
**Risk Score**: {self.scan_result.risk_metrics.risk_score}/10

### Findings Summary

- **Critical**: {self.scan_result.risk_metrics.critical_count}
- **High**: {self.scan_result.risk_metrics.high_count}
- **Medium**: {self.scan_result.risk_metrics.medium_count}
- **Low**: {self.scan_result.risk_metrics.low_count}
- **Info**: {self.scan_result.risk_metrics.info_count}

## Detailed Findings

"""

        for finding in self.scan_result.findings:
            md += f"""### {finding.title}

**Severity**: {finding.severity.value}
**CVSS Score**: {finding.cvss.get('score', 'N/A')}
**Component**: {finding.affected_component}
**MASTG Reference**: {finding.mastg_category}

{finding.description}

"""

        return md

    def save_scan_result(self, filepath: str):
        """Save scan result to file"""
        if not self.scan_result:
            raise RuntimeError("No scan result to save")

        self.scan_result.export_to_json(filepath)
        self.logger.info(f"Scan result saved to {filepath}")

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        if not self.scan_result:
            return {}

        return {
            "scan_id": self.scan_result.scan_id,
            "duration_seconds": self.scan_result.duration_seconds,
            "total_findings": len(self.scan_result.findings),
            "risk_metrics": self.scan_result.risk_metrics.to_dict(),
            "test_coverage": self.scan_result.test_coverage.to_dict(),
        }
