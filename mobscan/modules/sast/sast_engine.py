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

        weak_crypto_patterns = {
            'md5': (r'\bMD5\b|MessageDigest.getInstance\("MD5"\)', 'MD5 Hash Function (Weak)'),
            'sha1': (r'\bSHA1\b|SHA-1|MessageDigest.getInstance\("SHA-1"\)', 'SHA-1 Hash Function (Weak)'),
            'des': (r'\bDES\b|Cipher.getInstance\("DES', 'DES Encryption (Weak)'),
            'rc4': (r'\bRC4\b|Cipher.getInstance\("RC4', 'RC4 Encryption (Weak)'),
            'hardcoded_key': (r'SecretKey.*=.*new.*byte\[|key\s*=\s*["\'].*["\']', 'Hardcoded Cryptographic Key'),
            'weak_random': (r'new\s+Random\(\)|Math\.random\(\)', 'Weak Random Generation'),
            'ecb_mode': (r'Cipher.getInstance\(".*ECB', 'ECB Mode (Weak)'),
        }

        try:
            with zipfile.ZipFile(self.app_path, 'r') as apk:
                for file_info in apk.filelist:
                    if file_info.filename.endswith(('.java', '.kt', '.xml', '.smali')):
                        try:
                            content = apk.read(file_info.filename).decode('utf-8', errors='ignore')
                            for crypto_type, (pattern, description) in weak_crypto_patterns.items():
                                if re.search(pattern, content, re.IGNORECASE):
                                    finding = Finding(
                                        id=f"SAST-{len(self.findings) + 1:03d}",
                                        title=description,
                                        description=f"Weak cryptography detected: {description}",
                                        severity=Severity.HIGH,
                                        cvss={'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
                                        cwe=['CWE-327'],
                                        owasp_category='A02:2021 - Cryptographic Failures',
                                        test_name='Weak Cryptography Detection',
                                        module='sast',
                                        mastg_category='MASTG-CRYPTO-1',
                                        masvs_category='MSTG-CRYPTO-1',
                                        affected_component=file_info.filename,
                                    )
                                    self.findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Error reading {file_info.filename}: {e}")
        except Exception as e:
            logger.error(f"Error scanning for weak crypto: {e}")

    def _detect_insecure_storage(self):
        """Detect insecure storage practices"""
        logger.info("Scanning for insecure storage...")

        insecure_storage_patterns = {
            'sharedpref': (r'SharedPreferences|getSharedPreferences', 'SharedPreferences Usage (Review for Encryption)'),
            'sqlite': (r'SQLiteDatabase|android.database.sqlite', 'SQLite Database (Review for Encryption)'),
            'files': (r'getFilesDir|openFileOutput', 'File Storage (Review for Encryption)'),
            'logs': (r'Log\.(d|v|i)\(|System\.out\.println|System\.err\.println', 'Sensitive Data in Logs'),
            'realm': (r'import io.realm|Realm.getInstance', 'Realm Database (Review Security)'),
            'cache': (r'getCacheDir|getExternalCacheDir', 'Cache Directory Usage'),
        }

        try:
            with zipfile.ZipFile(self.app_path, 'r') as apk:
                for file_info in apk.filelist:
                    if file_info.filename.endswith(('.java', '.kt', '.xml')):
                        try:
                            content = apk.read(file_info.filename).decode('utf-8', errors='ignore')
                            for storage_type, (pattern, description) in insecure_storage_patterns.items():
                                if re.search(pattern, content, re.IGNORECASE):
                                    finding = Finding(
                                        id=f"SAST-{len(self.findings) + 1:03d}",
                                        title=description,
                                        description=f"Storage mechanism detected. Review for secure encryption: {description}",
                                        severity=Severity.MEDIUM,
                                        cvss={'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'},
                                        cwe=['CWE-922'],
                                        owasp_category='A02:2021 - Cryptographic Failures',
                                        test_name='Insecure Storage Detection',
                                        module='sast',
                                        mastg_category='MASTG-STORAGE-1',
                                        masvs_category='MSTG-STORAGE-1',
                                        affected_component=file_info.filename,
                                    )
                                    if storage_type not in self.findings:  # Avoid duplicates
                                        self.findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Error reading {file_info.filename}: {e}")
        except Exception as e:
            logger.error(f"Error scanning for insecure storage: {e}")

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

                # Check for exported components
                if 'android:exported="true"' in manifest_text:
                    finding = Finding(
                        id=f"SAST-{len(self.findings) + 1:03d}",
                        title="Exported Components Detected",
                        description="Application has exported components that could be accessed by other apps",
                        severity=Severity.MEDIUM,
                        cvss={'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
                        cwe=['CWE-927'],
                        owasp_category='A05:2021 - Security Misconfiguration',
                        test_name='Exported Components Check',
                        module='sast',
                        mastg_category='MASTG-PLATFORM-1',
                        masvs_category='MSTG-PLATFORM-1',
                        affected_component='AndroidManifest.xml',
                    )
                    self.findings.append(finding)

                # Check for dangerous permissions
                dangerous_perms = ['READ_CONTACTS', 'READ_CALENDAR', 'CAMERA', 'RECORD_AUDIO',
                                 'ACCESS_FINE_LOCATION', 'READ_PHONE_STATE', 'READ_SMS']
                for perm in dangerous_perms:
                    if f'android.permission.{perm}' in manifest_text:
                        finding = Finding(
                            id=f"SAST-{len(self.findings) + 1:03d}",
                            title=f"Dangerous Permission: {perm}",
                            description=f"Application requests dangerous permission: {perm}",
                            severity=Severity.LOW,
                            cvss={'score': 3.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'},
                            cwe=['CWE-250'],
                            owasp_category='A01:2021 - Broken Access Control',
                            test_name='Dangerous Permissions Check',
                            module='sast',
                            mastg_category='MASTG-PLATFORM-1',
                            masvs_category='MSTG-PLATFORM-1',
                            affected_component=f'Permission: {perm}',
                        )
                        self.findings.append(finding)

        except Exception as e:
            logger.debug(f"Error analyzing manifest: {e}")

    def _analyze_info_plist(self):
        """Analyze Info.plist for security issues"""
        logger.info("Analyzing Info.plist...")
        try:
            with zipfile.ZipFile(self.app_path, 'r') as ipa:
                for file_info in ipa.filelist:
                    if 'Info.plist' in file_info.filename:
                        try:
                            content = ipa.read(file_info.filename).decode('utf-8', errors='ignore')
                            # Check for insecure app transport settings
                            if 'NSAppTransportSecurity' in content or 'NSAllowsArbitraryLoads' in content:
                                finding = Finding(
                                    id=f"SAST-{len(self.findings) + 1:03d}",
                                    title="Insecure App Transport Security",
                                    description="Application allows arbitrary HTTP loads which allows MITM attacks",
                                    severity=Severity.HIGH,
                                    cvss={'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
                                    cwe=['CWE-295'],
                                    owasp_category='A04:2021 - Insecure Design',
                                    test_name='App Transport Security Check',
                                    module='sast',
                                    mastg_category='MASTG-NET-1',
                                    masvs_category='MSTG-NET-1',
                                    affected_component='Info.plist',
                                )
                                self.findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Error reading plist: {e}")
        except Exception as e:
            logger.debug(f"Error analyzing Info.plist: {e}")

    def _check_dependencies(self):
        """Check for vulnerable dependencies"""
        logger.info("Checking dependencies...")

        # Check for known vulnerable libraries
        vulnerable_libs = {
            'org.apache.commons:commons-collections': ['3.1', '3.2', '3.2.1'],
            'com.squareup.okhttp:okhttp': ['2.0.0', '2.1.0'],
            'com.google.gson:gson': ['2.8.5', '2.8.6'],
        }

        try:
            with zipfile.ZipFile(self.app_path, 'r') as apk:
                for lib, versions in vulnerable_libs.items():
                    lib_name = lib.split(':')[-1]
                    for file_info in apk.filelist:
                        if lib_name in file_info.filename.lower():
                            finding = Finding(
                                id=f"SAST-{len(self.findings) + 1:03d}",
                                title=f"Known Vulnerable Library: {lib_name}",
                                description=f"Application uses known vulnerable library: {lib}",
                                severity=Severity.HIGH,
                                cvss={'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
                                cwe=['CWE-1104'],
                                owasp_category='A06:2021 - Vulnerable and Outdated Components',
                                test_name='Vulnerable Library Detection',
                                module='sast',
                                mastg_category='MASTG-CODE-1',
                                masvs_category='MSTG-CODE-1',
                                affected_component=file_info.filename,
                            )
                            self.findings.append(finding)
        except Exception as e:
            logger.error(f"Error checking dependencies: {e}")

    def get_findings(self) -> List[Finding]:
        """Get all detected findings"""
        return self.findings
