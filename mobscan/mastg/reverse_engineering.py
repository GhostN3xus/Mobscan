"""
MASTG-REVERSE-ENGINEERING: Anti-Reversing Techniques Tests

Tests for preventing reverse engineering and tampering:
- Integrity checks
- Tampering detection
- Anti-debugging
- Code obfuscation verification
"""

from typing import List
from ..models.finding import Finding, Severity


class ReverseEngineeringTests:
    """Tests for reverse engineering prevention"""

    def __init__(self, app_path: str, platform: str = "android"):
        self.app_path = app_path
        self.platform = platform

    def test_integrity_checks(self) -> List[Finding]:
        """
        Test MASTG-RE-1: Verify application integrity checks

        Checks for implementation of integrity verification mechanisms that
        detect unauthorized modifications to the application package.

        Returns:
            List of findings related to missing or weak integrity checks
        """
        findings = []

        if self.platform == "android":
            # Check for signature verification implementation
            import zipfile
            import os

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    # Check for signature files
                    has_signature = any(
                        'META-INF' in f and f.endswith(('.RSA', '.DSA', '.EC'))
                        for f in apk.namelist()
                    )

                    if not has_signature:
                        findings.append(Finding(
                            title="Missing APK Signature",
                            description="Application package is not properly signed. This prevents integrity verification.",
                            severity=Severity.HIGH,
                            category="MASTG-RE-1",
                            recommendation="Ensure the APK is properly signed using Android signing tools."
                        ))

                    # Check for PackageManager integrity check patterns
                    # This would require decompilation - simplified check for now
                    manifest_present = 'AndroidManifest.xml' in apk.namelist()
                    if manifest_present:
                        # Application has basic structure for integrity checks
                        pass
                    else:
                        findings.append(Finding(
                            title="Malformed APK Structure",
                            description="APK missing critical files needed for integrity verification.",
                            severity=Severity.CRITICAL,
                            category="MASTG-RE-1",
                            recommendation="Rebuild the APK with proper structure and integrity mechanisms."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Unable to Verify Integrity Mechanisms",
                    description=f"Failed to analyze APK integrity: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="MASTG-RE-1",
                    recommendation="Ensure the APK is valid and accessible for analysis."
                ))

        elif self.platform == "ios":
            # Check for code signature in IPA
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    # Look for _CodeSignature directory
                    has_codesign = any('_CodeSignature' in f for f in ipa.namelist())

                    if not has_codesign:
                        findings.append(Finding(
                            title="Missing Code Signature",
                            description="IPA does not contain code signature. Integrity cannot be verified.",
                            severity=Severity.HIGH,
                            category="MASTG-RE-1",
                            recommendation="Sign the IPA with a valid Apple certificate."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Unable to Verify IPA Integrity",
                    description=f"Failed to analyze IPA: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="MASTG-RE-1",
                    recommendation="Ensure the IPA file is valid and accessible."
                ))

        return findings

    def test_tampering_detection(self) -> List[Finding]:
        """
        Test MASTG-RE-2: Verify tampering detection

        Analyzes the application for runtime and static tampering detection mechanisms.

        Returns:
            List of findings related to tampering detection weaknesses
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    # Check for common anti-tampering patterns in smali/dex
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

                    if not dex_files:
                        findings.append(Finding(
                            title="Missing DEX Files",
                            description="No DEX files found - cannot verify tampering detection implementation.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RE-2",
                            recommendation="Ensure DEX files are present and implement tampering detection."
                        ))

                    # Check for native libraries that might contain anti-tampering
                    native_libs = [f for f in apk.namelist() if f.endswith('.so')]

                    # Note: Full implementation would require decompilation and code analysis
                    # This is a structural check
                    if len(native_libs) == 0:
                        findings.append(Finding(
                            title="No Native Anti-Tampering Detected",
                            description="Application lacks native libraries that typically implement tampering detection.",
                            severity=Severity.INFO,
                            category="MASTG-RE-2",
                            recommendation="Consider implementing native-level tampering detection for stronger protection."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Tampering Detection Analysis Failed",
                    description=f"Unable to analyze tampering detection: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-2",
                    recommendation="Verify APK integrity and accessibility."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    # Check for frameworks that might implement tampering detection
                    frameworks = [f for f in ipa.namelist() if 'Frameworks' in f]

                    # Check for common security frameworks
                    security_frameworks = [
                        f for f in frameworks
                        if any(sec in f for sec in ['Security', 'CryptoKit', 'CommonCrypto'])
                    ]

                    if not security_frameworks:
                        findings.append(Finding(
                            title="Limited Security Frameworks",
                            description="Application does not appear to use security frameworks for tampering detection.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RE-2",
                            recommendation="Implement tampering detection using iOS security frameworks."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="IPA Tampering Analysis Failed",
                    description=f"Unable to analyze IPA: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-2",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def test_anti_debugging(self) -> List[Finding]:
        """
        Test MASTG-RE-3: Verify anti-debugging mechanisms

        Checks for implementation of anti-debugging techniques to prevent
        dynamic analysis and runtime manipulation.

        Returns:
            List of findings related to missing or weak anti-debugging protections
        """
        findings = []

        if self.platform == "android":
            import zipfile
            import re

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    # Check AndroidManifest.xml for debuggable flag
                    if 'AndroidManifest.xml' in apk.namelist():
                        manifest_data = apk.read('AndroidManifest.xml')

                        # Note: AndroidManifest.xml is binary, would need proper parsing
                        # This is a simplified check
                        if b'debuggable' in manifest_data and b'true' in manifest_data:
                            findings.append(Finding(
                                title="Debuggable Flag Enabled",
                                description="Application has android:debuggable='true' in manifest. This allows easy debugging and reverse engineering.",
                                severity=Severity.HIGH,
                                category="MASTG-RE-3",
                                recommendation="Set android:debuggable='false' in production builds."
                            ))

                    # Check for native libraries with anti-debug
                    native_libs = [f for f in apk.namelist() if f.endswith('.so')]

                    if native_libs:
                        # Presence of native libs suggests possible anti-debug implementation
                        # Full analysis would require disassembly
                        pass
                    else:
                        findings.append(Finding(
                            title="No Native Anti-Debug Protection",
                            description="Application lacks native libraries. Consider implementing ptrace protection and anti-debug checks at native level.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RE-3",
                            recommendation="Implement anti-debugging mechanisms like ptrace protection in native code."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Anti-Debug Analysis Failed",
                    description=f"Unable to analyze anti-debugging mechanisms: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-3",
                    recommendation="Verify APK accessibility."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    # Look for Info.plist
                    plist_files = [f for f in ipa.namelist() if f.endswith('Info.plist')]

                    if plist_files:
                        # Check for UIFileSharingEnabled and other debug-related keys
                        # Full implementation would parse plist
                        pass

                    # Check for executable that might have PT_DENY_ATTACH
                    executables = [
                        f for f in ipa.namelist()
                        if not '.' in f.split('/')[-1] and 'Payload' in f
                    ]

                    if not executables:
                        findings.append(Finding(
                            title="Cannot Verify Anti-Debug Implementation",
                            description="Unable to locate executable binary for anti-debug analysis.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RE-3",
                            recommendation="Ensure IPA contains proper executable and implements PT_DENY_ATTACH."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="IPA Anti-Debug Analysis Failed",
                    description=f"Unable to analyze IPA anti-debugging: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-3",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def test_obfuscation_effectiveness(self) -> List[Finding]:
        """
        Test MASTG-RE-4: Verify obfuscation effectiveness

        Analyzes code obfuscation quality to assess reverse engineering difficulty.
        Checks for ProGuard/R8 (Android), symbol stripping (iOS), and string encryption.

        Returns:
            List of findings related to weak or missing obfuscation
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    # Check for ProGuard/R8 mapping file indicator
                    has_mapping = 'META-INF/proguard' in ' '.join(apk.namelist()).lower()

                    # Check class names in DEX for obfuscation patterns
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

                    if not dex_files:
                        findings.append(Finding(
                            title="Cannot Verify Obfuscation",
                            description="No DEX files found to analyze obfuscation.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RE-4",
                            recommendation="Ensure application is properly compiled and obfuscated."
                        ))
                    else:
                        # Check for resources.arsc (contains string resources)
                        if 'resources.arsc' in apk.namelist():
                            resources_data = apk.read('resources.arsc')

                            # Simple heuristic: look for readable strings
                            readable_strings = [
                                word for word in resources_data.split(b'\x00')
                                if len(word) > 10 and word.isalpha()
                            ]

                            if len(readable_strings) > 100:
                                findings.append(Finding(
                                    title="Unobfuscated String Resources",
                                    description=f"Found {len(readable_strings)} readable strings in resources. Consider string encryption.",
                                    severity=Severity.MEDIUM,
                                    category="MASTG-RE-4",
                                    recommendation="Implement string encryption to protect sensitive strings from static analysis."
                                ))

                        # Check for common package names that indicate no obfuscation
                        classes_dex = apk.read(dex_files[0])[:1000]  # Read header

                        if b'com/example/' in classes_dex or b'com/test/' in classes_dex:
                            findings.append(Finding(
                                title="Development Package Names Detected",
                                description="Application contains development/example package names, suggesting lack of obfuscation.",
                                severity=Severity.LOW,
                                category="MASTG-RE-4",
                                recommendation="Apply ProGuard/R8 obfuscation with proper rules for production builds."
                            ))

            except Exception as e:
                findings.append(Finding(
                    title="Obfuscation Analysis Failed",
                    description=f"Unable to analyze code obfuscation: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-4",
                    recommendation="Verify APK integrity."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    # Check for symbol stripping in executable
                    executables = [
                        f for f in ipa.namelist()
                        if 'Payload' in f and not '.' in f.split('/')[-1] and f.split('/')[-1]
                    ]

                    if executables:
                        # Check binary for symbols (simplified)
                        binary_data = ipa.read(executables[0])

                        # Look for common function name patterns
                        if b'_main' in binary_data or b'_init' in binary_data:
                            # Has some symbols
                            findings.append(Finding(
                                title="Symbols Not Fully Stripped",
                                description="Binary contains debug symbols. This aids reverse engineering.",
                                severity=Severity.MEDIUM,
                                category="MASTG-RE-4",
                                recommendation="Strip symbols from production builds using Xcode settings or strip command."
                            ))
                    else:
                        findings.append(Finding(
                            title="Cannot Verify Symbol Stripping",
                            description="Unable to locate executable binary for symbol analysis.",
                            severity=Severity.LOW,
                            category="MASTG-RE-4",
                            recommendation="Ensure IPA structure is correct."
                        ))

                    # Check for unencrypted strings in binary
                    # This is a simplified check

            except Exception as e:
                findings.append(Finding(
                    title="IPA Obfuscation Analysis Failed",
                    description=f"Unable to analyze obfuscation: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RE-4",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def run_all_tests(self) -> List[Finding]:
        """Run all reverse engineering prevention tests"""
        findings = []
        findings.extend(self.test_integrity_checks())
        findings.extend(self.test_tampering_detection())
        findings.extend(self.test_anti_debugging())
        findings.extend(self.test_obfuscation_effectiveness())
        return findings
