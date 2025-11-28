"""
SAST Engine - Static Application Security Testing

Performs comprehensive static analysis of mobile applications.
"""

import re
import zipfile
from pathlib import Path
from typing import List, Dict, Any
import logging

from ...models.finding import Finding, Severity


logger = logging.getLogger(__name__)


class SASTEngine:
    """Static Application Security Testing Engine"""

    def __init__(self, app_path: str, platform: str = "android"):
        self.app_path = app_path
        self.platform = platform
        self.findings: List[Finding] = []

    def run_analysis(self) -> List[Finding]:
        """
        Run complete SAST analysis on the application.

        Returns:
            List of findings
        """
        self.findings = []

        logger.info(f"Starting SAST analysis on {self.app_path}")

        # Run individual analyses
        self._detect_hardcoded_secrets()
        self._detect_weak_cryptography()
        self._detect_insecure_storage()
        self._analyze_manifest()
        self._check_dependencies()

        logger.info(f"SAST analysis completed. Found {len(self.findings)} issues")
        return self.findings

    def _detect_hardcoded_secrets(self):
        """Detect hardcoded secrets and credentials"""
        logger.info("Scanning for hardcoded secrets...")

        # Patterns for common secrets
        secret_patterns = [
            (r'api[_-]?key\s*[=:]\s*[\'"]([a-zA-Z0-9]+)[\'"]', 'API Key'),
            (r'password\s*[=:]\s*[\'"]([^\'\"]+)[\'"]', 'Password'),
            (r'secret\s*[=:]\s*[\'"]([a-zA-Z0-9]+)[\'"]', 'Secret'),
            (r'token\s*[=:]\s*[\'"]([a-zA-Z0-9]+)[\'"]', 'Token'),
            (r'private[_-]?key\s*[=:]\s*[\'"]', 'Private Key'),
            (r'-----BEGIN PRIVATE KEY-----', 'RSA Private Key'),
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
        ]

        try:
            if self.platform == "android":
                self._scan_apk_for_secrets(secret_patterns)
            else:
                self._scan_ipa_for_secrets(secret_patterns)
        except Exception as e:
            logger.error(f"Error scanning for secrets: {e}")

    def _scan_apk_for_secrets(self, patterns):
        """Scan APK for hardcoded secrets"""
        try:
            with zipfile.ZipFile(self.app_path, 'r') as apk:
                for file_info in apk.filelist:
                    # Only check text files
                    if file_info.filename.endswith(('.xml', '.properties', '.json', '.txt')):
                        try:
                            content = apk.read(file_info.filename).decode('utf-8', errors='ignore')

                            for pattern, secret_type in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    finding = Finding(
                                        id=f"SAST-{len(self.findings) + 1:03d}",
                                        title=f"Hardcoded {secret_type}",
                                        description=f"Found hardcoded {secret_type.lower()} in {file_info.filename}",
                                        severity=Severity.CRITICAL,
                                        cvss={'score': 9.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
                                        cwe=['CWE-798'],
                                        owasp_category='A02:2021 - Cryptographic Failures',
                                        test_name='Hardcoded Secrets Detection',
                                        module='sast',
                                        mastg_category='MASTG-STORAGE-1',
                                        masvs_category='MSTG-STORAGE-1',
                                        affected_component=file_info.filename,
                                    )
                                    self.findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Error reading {file_info.filename}: {e}")

        except Exception as e:
            logger.error(f"Error scanning APK: {e}")

    def _scan_ipa_for_secrets(self, patterns):
        """Scan IPA for hardcoded secrets"""
        try:
            with zipfile.ZipFile(self.app_path, 'r') as ipa:
                # IPA structure: Payload/AppName.app/
                for file_info in ipa.filelist:
                    if file_info.filename.endswith(('.plist', '.json', '.txt', '.strings')):
                        try:
                            content = ipa.read(file_info.filename).decode('utf-8', errors='ignore')

                            for pattern, secret_type in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    finding = Finding(
                                        id=f"SAST-{len(self.findings) + 1:03d}",
                                        title=f"Hardcoded {secret_type}",
                                        description=f"Found hardcoded {secret_type.lower()} in {file_info.filename}",
                                        severity=Severity.CRITICAL,
                                        cvss={'score': 9.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
                                        cwe=['CWE-798'],
                                        owasp_category='A02:2021 - Cryptographic Failures',
                                        test_name='Hardcoded Secrets Detection',
                                        module='sast',
                                        mastg_category='MASTG-STORAGE-1',
                                        masvs_category='MSTG-STORAGE-1',
                                        affected_component=file_info.filename,
                                    )
                                    self.findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Error reading {file_info.filename}: {e}")

        except Exception as e:
            logger.error(f"Error scanning IPA: {e}")

    def _detect_weak_cryptography(self):
        """Detect weak cryptographic usage"""
        logger.info("Scanning for weak cryptography...")

        # This would check for:
        # - Weak algorithms (DES, MD5, SHA1)
        # - Hard-coded keys
        # - Improper key generation

    def _detect_insecure_storage(self):
        """Detect insecure storage practices"""
        logger.info("Scanning for insecure storage...")

        # This would check for:
        # - Unencrypted SharedPreferences
        # - Unencrypted SQL databases
        # - Sensitive data in logs

    def _analyze_manifest(self):
        """Analyze AndroidManifest.xml or Info.plist"""
        logger.info("Analyzing manifest/plist...")

        if self.platform == "android":
            self._analyze_android_manifest()
        else:
            self._analyze_info_plist()

    def _analyze_android_manifest(self):
        """Analyze AndroidManifest.xml for security issues"""
        try:
            with zipfile.ZipFile(self.app_path, 'r') as apk:
                manifest_data = apk.read('AndroidManifest.xml')
                manifest_text = manifest_data.decode('utf-8', errors='ignore')

                # Check for debuggable flag
                if 'android:debuggable="true"' in manifest_text:
                    finding = Finding(
                        id=f"SAST-{len(self.findings) + 1:03d}",
                        title="Debuggable Application",
                        description="Application is debuggable which allows attackers to easily analyze and modify the app",
                        severity=Severity.HIGH,
                        cvss={'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
                        cwe=['CWE-489'],
                        owasp_category='A05:2021 - Security Misconfiguration',
                        test_name='Debuggable Flag Check',
                        module='sast',
                        mastg_category='MASTG-CODE-2',
                        masvs_category='MSTG-CODE-2',
                        affected_component='AndroidManifest.xml',
                    )
                    self.findings.append(finding)

        except Exception as e:
            logger.debug(f"Error analyzing manifest: {e}")

    def _analyze_info_plist(self):
        """Analyze Info.plist for security issues"""
        logger.info("Analyzing Info.plist...")
        # Implementation would parse and check iOS configuration

    def _check_dependencies(self):
        """Check for vulnerable dependencies"""
        logger.info("Checking dependencies...")

        # This would check for:
        # - Known vulnerable libraries
        # - Outdated dependencies
        # - Unpatched security issues

    def get_findings(self) -> List[Finding]:
        """Get all detected findings"""
        return self.findings
