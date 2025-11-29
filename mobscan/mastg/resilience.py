"""
MASTG-RESILIENCE: Reverse Engineering Protection Tests

Tests for protection against reverse engineering:
- Root/jailbreak detection
- Debugger detection
- Emulator detection
- Code obfuscation
"""

from typing import List
from ..models.finding import Finding, Severity


class ResilienceTests:
    """Tests for reverse engineering protection"""

    def __init__(self, app_path: str, platform: str = "android"):
        self.app_path = app_path
        self.platform = platform

    def test_root_jailbreak_detection(self) -> List[Finding]:
        """
        Test MASTG-RESILIENCE-1: Verify root/jailbreak detection

        Checks for implementation of root (Android) or jailbreak (iOS) detection
        mechanisms to prevent execution in compromised environments.

        Returns:
            List of findings related to missing or weak root/jailbreak detection
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

                    if not dex_files:
                        findings.append(Finding(
                            title="Cannot Verify Root Detection",
                            description="No DEX files found for root detection analysis.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-1",
                            recommendation="Ensure application is properly compiled with root detection."
                        ))
                        return findings

                    # Check for common root detection strings/patterns
                    root_indicators_found = False
                    for dex_file in dex_files:
                        dex_data = apk.read(dex_file)

                        # Common root detection patterns
                        root_patterns = [
                            b'/system/bin/su',
                            b'/system/xbin/su',
                            b'Superuser.apk',
                            b'eu.chainfire.supersu',
                            b'com.noshufou.android.su',
                            b'com.topjohnwu.magisk',
                            b'RootTools',
                        ]

                        for pattern in root_patterns:
                            if pattern in dex_data:
                                root_indicators_found = True
                                break

                        if root_indicators_found:
                            break

                    if not root_indicators_found:
                        findings.append(Finding(
                            title="No Root Detection Implemented",
                            description="Application does not appear to check for rooted devices. This allows execution in compromised environments.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-1",
                            recommendation="Implement root detection using RootBeer, SafetyNet, or custom checks for su binaries and known root management apps."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Root Detection Analysis Failed",
                    description=f"Unable to analyze root detection: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-1",
                    recommendation="Verify APK integrity."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    # Look for executable binary
                    executables = [
                        f for f in ipa.namelist()
                        if 'Payload' in f and not '.' in f.split('/')[-1] and f.split('/')[-1]
                    ]

                    if not executables:
                        findings.append(Finding(
                            title="Cannot Verify Jailbreak Detection",
                            description="Unable to locate executable for jailbreak detection analysis.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-1",
                            recommendation="Ensure IPA structure is valid."
                        ))
                        return findings

                    binary_data = ipa.read(executables[0])

                    # Common jailbreak detection patterns
                    jailbreak_patterns = [
                        b'/Applications/Cydia.app',
                        b'/Library/MobileSubstrate',
                        b'/bin/bash',
                        b'/usr/sbin/sshd',
                        b'/etc/apt',
                        b'cydia://',
                    ]

                    jailbreak_detected = any(pattern in binary_data for pattern in jailbreak_patterns)

                    if not jailbreak_detected:
                        findings.append(Finding(
                            title="No Jailbreak Detection Implemented",
                            description="Application does not check for jailbroken devices, allowing execution in compromised environments.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-1",
                            recommendation="Implement jailbreak detection by checking for Cydia, suspicious file paths, and forked processes."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Jailbreak Detection Analysis Failed",
                    description=f"Unable to analyze jailbreak detection: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-1",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def test_debugger_detection(self) -> List[Finding]:
        """
        Test MASTG-RESILIENCE-2: Verify debugger detection

        Checks for implementation of debugger detection mechanisms to prevent
        dynamic analysis and runtime inspection.

        Returns:
            List of findings related to missing or weak debugger detection
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    # Check manifest for debuggable flag
                    if 'AndroidManifest.xml' in apk.namelist():
                        manifest_data = apk.read('AndroidManifest.xml')

                        if b'debuggable' in manifest_data and b'true' in manifest_data:
                            findings.append(Finding(
                                title="Application is Debuggable",
                                description="android:debuggable=true allows debuggers to attach easily.",
                                severity=Severity.HIGH,
                                category="MASTG-RESILIENCE-2",
                                recommendation="Set android:debuggable=false in production AndroidManifest.xml."
                            ))

                    # Check for Debug class usage
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
                    debugger_check_found = False

                    for dex_file in dex_files:
                        dex_data = apk.read(dex_file)

                        # Look for Debug.isDebuggerConnected() calls
                        if b'isDebuggerConnected' in dex_data:
                            debugger_check_found = True
                            break

                    if not debugger_check_found:
                        findings.append(Finding(
                            title="No Debugger Detection",
                            description="Application does not check for attached debuggers at runtime.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-2",
                            recommendation="Implement Debug.isDebuggerConnected() checks and anti-ptrace in native code."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Debugger Detection Analysis Failed",
                    description=f"Unable to analyze debugger detection: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-2",
                    recommendation="Verify APK integrity."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    executables = [
                        f for f in ipa.namelist()
                        if 'Payload' in f and not '.' in f.split('/')[-1] and f.split('/')[-1]
                    ]

                    if executables:
                        binary_data = ipa.read(executables[0])

                        # Look for sysctl and ptrace patterns
                        debug_patterns = [
                            b'sysctl',
                            b'PT_DENY_ATTACH',
                            b'kinfo_proc',
                            b'p_flag',
                        ]

                        has_debug_detection = any(pattern in binary_data for pattern in debug_patterns)

                        if not has_debug_detection:
                            findings.append(Finding(
                                title="No Debugger Detection",
                                description="Application lacks debugger detection mechanisms.",
                                severity=Severity.MEDIUM,
                                category="MASTG-RESILIENCE-2",
                                recommendation="Implement PT_DENY_ATTACH and sysctl-based debugger detection."
                            ))
                    else:
                        findings.append(Finding(
                            title="Cannot Verify Debugger Detection",
                            description="Unable to locate executable binary.",
                            severity=Severity.LOW,
                            category="MASTG-RESILIENCE-2",
                            recommendation="Ensure IPA structure is valid."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Debugger Detection Analysis Failed",
                    description=f"Unable to analyze IPA: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-2",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def test_emulator_detection(self) -> List[Finding]:
        """
        Test MASTG-RESILIENCE-3: Verify emulator detection

        Checks for implementation of emulator/simulator detection to prevent
        analysis in virtualized environments.

        Returns:
            List of findings related to missing or weak emulator detection
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

                    emulator_check_found = False

                    for dex_file in dex_files:
                        dex_data = apk.read(dex_file)

                        # Common emulator detection patterns
                        emulator_patterns = [
                            b'ro.kernel.qemu',
                            b'ro.hardware',
                            b'ro.product.model',
                            b'goldfish',
                            b'generic',
                            b'Build.FINGERPRINT',
                            b'Build.MODEL',
                            b'Build.MANUFACTURER',
                            b'telephony',  # Check for TelephonyManager (emulators lack proper IMEI)
                        ]

                        emulator_check_found = any(pattern in dex_data for pattern in emulator_patterns)

                        if emulator_check_found:
                            break

                    if not emulator_check_found:
                        findings.append(Finding(
                            title="No Emulator Detection",
                            description="Application does not check if running on an emulator, allowing easy dynamic analysis.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-3",
                            recommendation="Implement emulator detection by checking Build properties (ro.kernel.qemu, Build.FINGERPRINT) and device characteristics."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Emulator Detection Analysis Failed",
                    description=f"Unable to analyze emulator detection: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-3",
                    recommendation="Verify APK integrity."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    executables = [
                        f for f in ipa.namelist()
                        if 'Payload' in f and not '.' in f.split('/')[-1] and f.split('/')[-1]
                    ]

                    if executables:
                        binary_data = ipa.read(executables[0])

                        # Simulator detection patterns
                        simulator_patterns = [
                            b'TARGET_IPHONE_SIMULATOR',
                            b'x86_64',  # Simulator architecture
                            b'i386',    # Older simulator architecture
                        ]

                        has_simulator_check = any(pattern in binary_data for pattern in simulator_patterns)

                        # Note: Presence of these strings could indicate simulator build OR detection
                        # More sophisticated analysis would be needed for definitive answer

                        # For now, we'll warn if no explicit detection seems implemented
                        findings.append(Finding(
                            title="Emulator/Simulator Detection Recommended",
                            description="Implement runtime checks to detect iOS Simulator execution.",
                            severity=Severity.LOW,
                            category="MASTG-RESILIENCE-3",
                            recommendation="Add runtime checks for TARGET_IPHONE_SIMULATOR and device model verification."
                        ))

                    else:
                        findings.append(Finding(
                            title="Cannot Verify Simulator Detection",
                            description="Unable to locate executable binary.",
                            severity=Severity.LOW,
                            category="MASTG-RESILIENCE-3",
                            recommendation="Ensure IPA structure is valid."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Simulator Detection Analysis Failed",
                    description=f"Unable to analyze IPA: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-3",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def test_code_obfuscation(self) -> List[Finding]:
        """
        Test MASTG-RESILIENCE-4: Verify code obfuscation

        Checks for implementation of code obfuscation techniques to increase
        reverse engineering difficulty.

        Returns:
            List of findings related to weak or missing code obfuscation
        """
        findings = []

        if self.platform == "android":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as apk:
                    dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

                    if not dex_files:
                        findings.append(Finding(
                            title="Cannot Verify Obfuscation",
                            description="No DEX files found for obfuscation analysis.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Ensure application is properly compiled with obfuscation."
                        ))
                        return findings

                    # Read first DEX file to check for obfuscation indicators
                    dex_data = apk.read(dex_files[0])

                    # Check for non-obfuscated package names
                    unobfuscated_patterns = [
                        b'com/example/',
                        b'com/test/',
                        b'com/demo/',
                        b'com/sample/',
                    ]

                    has_unobfuscated = any(pattern in dex_data for pattern in unobfuscated_patterns)

                    if has_unobfuscated:
                        findings.append(Finding(
                            title="Unobfuscated Package Names",
                            description="Application contains clearly readable package names suggesting no obfuscation.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Apply ProGuard or R8 obfuscation to production builds."
                        ))

                    # Check for ProGuard/R8 configuration presence
                    has_proguard_cfg = any('proguard' in f.lower() for f in apk.namelist())

                    if not has_proguard_cfg:
                        findings.append(Finding(
                            title="No Obfuscation Configuration Detected",
                            description="No ProGuard/R8 configuration files found in APK.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Enable and configure ProGuard/R8 obfuscation with minifyEnabled=true."
                        ))

                    # Check for string resources (unencrypted strings)
                    if 'resources.arsc' in apk.namelist():
                        resources = apk.read('resources.arsc')

                        # Count readable strings
                        readable_count = len([s for s in resources.split(b'\x00') if len(s) > 15 and s.isalpha()])

                        if readable_count > 150:
                            findings.append(Finding(
                                title="Unencrypted String Resources",
                                description=f"Found {readable_count} readable strings. Consider string encryption.",
                                severity=Severity.LOW,
                                category="MASTG-RESILIENCE-4",
                                recommendation="Encrypt sensitive strings and implement runtime decryption."
                            ))

            except Exception as e:
                findings.append(Finding(
                    title="Obfuscation Analysis Failed",
                    description=f"Unable to analyze code obfuscation: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-4",
                    recommendation="Verify APK integrity."
                ))

        elif self.platform == "ios":
            import zipfile

            try:
                with zipfile.ZipFile(self.app_path, 'r') as ipa:
                    executables = [
                        f for f in ipa.namelist()
                        if 'Payload' in f and not '.' in f.split('/')[-1] and f.split('/')[-1]
                    ]

                    if not executables:
                        findings.append(Finding(
                            title="Cannot Verify Symbol Stripping",
                            description="Unable to locate executable binary.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Ensure IPA structure is valid and symbols are stripped."
                        ))
                        return findings

                    binary_data = ipa.read(executables[0])

                    # Check for debug symbols
                    symbol_patterns = [
                        b'_OBJC_CLASS_$_',
                        b'_OBJC_IVAR_$_',
                        b'__swift_',
                        b'_main',
                        b'_init',
                    ]

                    has_symbols = any(pattern in binary_data for pattern in symbol_patterns)

                    if has_symbols:
                        findings.append(Finding(
                            title="Debug Symbols Present",
                            description="Binary contains debug symbols, making reverse engineering easier.",
                            severity=Severity.MEDIUM,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Strip symbols using Xcode's STRIP_INSTALLED_PRODUCT setting or the strip command."
                        ))

                    # Check for readable strings
                    readable_strings = [s for s in binary_data.split(b'\x00') if len(s) > 20 and s.isalnum()]

                    if len(readable_strings) > 100:
                        findings.append(Finding(
                            title="Unencrypted Strings in Binary",
                            description=f"Found {len(readable_strings)} readable strings in binary.",
                            severity=Severity.LOW,
                            category="MASTG-RESILIENCE-4",
                            recommendation="Encrypt sensitive strings and implement runtime decryption."
                        ))

            except Exception as e:
                findings.append(Finding(
                    title="Symbol Stripping Analysis Failed",
                    description=f"Unable to analyze IPA: {str(e)}",
                    severity=Severity.LOW,
                    category="MASTG-RESILIENCE-4",
                    recommendation="Ensure IPA file is valid."
                ))

        return findings

    def run_all_tests(self) -> List[Finding]:
        """Run all resilience tests"""
        findings = []
        findings.extend(self.test_root_jailbreak_detection())
        findings.extend(self.test_debugger_detection())
        findings.extend(self.test_emulator_detection())
        findings.extend(self.test_code_obfuscation())
        return findings
