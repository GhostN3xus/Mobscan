"""
Complete SAST Module - Static Application Security Testing

Implementa análise completa de código usando AST, CFG e taint analysis.
Integrado com AnalysisManager para análise corporativa.
"""

import zipfile
import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import xml.etree.ElementTree as ET

from ...core.analysis_manager import BaseAnalysisModule, AnalysisModule, Finding, FindingSeverity, EvidenceItem
from .ast_engine import ASTEngine, TaintAnalyzer, ControlFlowAnalyzer, VulnerabilityDetector

logger = logging.getLogger(__name__)


@dataclass
class APKMetadata:
    """Metadados extraídos de APK"""
    package_name: str
    version: str
    target_sdk: int
    min_sdk: int
    debuggable: bool
    permissions: List[str]
    activities: List[str]
    services: List[str]
    broadcast_receivers: List[str]


class SASTModule(BaseAnalysisModule):
    """
    Módulo SAST Profissional

    Detecta:
    - Criptografia fraca
    - Dados com hardcode
    - Armazenamento inseguro
    - WebView inseguro
    - Atividades exportadas
    - Desserialização insegura
    - Logging de dados sensíveis
    - Fluxos de dados sensíveis
    """

    def __init__(self):
        super().__init__(AnalysisModule.SAST, "SAST Engine")
        self.ast_engine = ASTEngine()
        self.apk_metadata: Optional[APKMetadata] = None
        self.all_code_content = ""

    def execute(self, app_path: str, config: Dict[str, Any]) -> List[Finding]:
        """Executa análise SAST completa"""
        self.findings = []

        try:
            self.logger.info(f"Starting SAST analysis for {app_path}")

            # Extrair metadados
            self._extract_metadata(app_path)

            # Análise de arquivos
            self._analyze_application(app_path)

            # AST Analysis
            self._run_ast_analysis()

            # Análise específica
            self._check_manifest_security()
            self._check_code_vulnerabilities()
            self._check_data_flows()

            self.logger.info(f"SAST analysis completed: {len(self.findings)} findings")

        except Exception as e:
            self.logger.error(f"SAST analysis error: {str(e)}", exc_info=True)

        return self.findings

    def _extract_metadata(self, app_path: str) -> None:
        """Extrai metadados da aplicação"""
        try:
            with zipfile.ZipFile(app_path, 'r') as apk:
                # Ler AndroidManifest.xml
                manifest_data = apk.read('AndroidManifest.xml')
                self._parse_android_manifest(manifest_data)

        except Exception as e:
            self.logger.warning(f"Failed to extract metadata: {str(e)}")

    def _parse_android_manifest(self, manifest_data: bytes) -> None:
        """Parse simplificado do AndroidManifest"""
        # Em produção, usaria androguard para parser binário correto
        manifest_text = manifest_data.decode('utf-8', errors='ignore')

        # Extração simples
        try:
            package_match = manifest_text.find('package=')
            if package_match >= 0:
                start = manifest_text.find('"', package_match) + 1
                end = manifest_text.find('"', start)
                package_name = manifest_text[start:end]
            else:
                package_name = "unknown"

            debuggable = 'android:debuggable="true"' in manifest_text

            self.apk_metadata = APKMetadata(
                package_name=package_name,
                version="1.0.0",
                target_sdk=31,
                min_sdk=21,
                debuggable=debuggable,
                permissions=[],
                activities=[],
                services=[],
                broadcast_receivers=[],
            )

        except Exception as e:
            self.logger.warning(f"Error parsing manifest: {str(e)}")

    def _analyze_application(self, app_path: str) -> None:
        """Analisa arquivos da aplicação"""
        try:
            with zipfile.ZipFile(app_path, 'r') as apk:
                for file_info in apk.filelist:
                    # Analisar arquivos de código
                    if file_info.filename.endswith(('.smali', '.java', '.kt', '.xml', '.json', '.properties')):
                        try:
                            content = apk.read(file_info.filename).decode('utf-8', errors='ignore')
                            self.all_code_content += f"\n# File: {file_info.filename}\n{content}"

                            # Análise por arquivo
                            self._analyze_file(file_info.filename, content)

                        except Exception as e:
                            self.logger.debug(f"Error analyzing {file_info.filename}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error analyzing application: {str(e)}")

    def _analyze_file(self, filename: str, content: str) -> None:
        """Analisa um arquivo específico"""
        # Detecção de vulnerabilidades
        detector = VulnerabilityDetector()
        vulnerabilities = detector.detect(content, filename)

        for vuln in vulnerabilities:
            finding = self._create_finding_from_vulnerability(vuln)
            if finding:
                self.findings.append(finding)

    def _run_ast_analysis(self) -> None:
        """Executa análise AST no código completo"""
        if not self.all_code_content:
            return

        ast_results = self.ast_engine.analyze_code(self.all_code_content)

        # Processar resultados de vulnerabilidades
        for vuln in ast_results.get('vulnerabilities', []):
            finding = self._create_finding_from_vulnerability(vuln)
            if finding:
                # Verificar duplicação
                if not any(f.hash == finding.hash for f in self.findings):
                    self.findings.append(finding)

    def _check_manifest_security(self) -> None:
        """Verifica segurança do manifest"""
        if not self.apk_metadata:
            return

        # Verificar debuggable
        if self.apk_metadata.debuggable:
            finding = Finding(
                id=f"SAST-{len(self.findings) + 1:04d}",
                title="Debuggable Application",
                description="Application is marked as debuggable, allowing attackers to easily analyze and modify the app",
                severity=FindingSeverity.HIGH.value,
                category="A05:2021 - Security Misconfiguration",
                module=AnalysisModule.SAST.value,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe=["CWE-489"],
                masvs_mapping=["MSTG-RESILIENCE-2"],
                mastg_mapping=["MASTG-RESILIENCE-2"],
                evidence=[
                    EvidenceItem(
                        type="manifest",
                        location="AndroidManifest.xml",
                        content='android:debuggable="true"'
                    )
                ],
                affected_component="AndroidManifest.xml",
                remediation="Set android:debuggable to false in production builds",
            )
            self.findings.append(finding)

    def _check_code_vulnerabilities(self) -> None:
        """Verifica vulnerabilidades de código específicas"""
        # Verificações adicionais
        self._check_weak_cryptography()
        self._check_insecure_storage()
        self._check_webview_issues()
        self._check_exported_components()

    def _check_weak_cryptography(self) -> None:
        """Verifica criptografia fraca"""
        weak_patterns = [
            (r'Cipher\.getInstance\(["\']DES["\']', "DES", 9.0, "CRITICAL"),
            (r'MessageDigest\.getInstance\(["\']MD5["\']', "MD5", 7.5, "HIGH"),
            (r'MessageDigest\.getInstance\(["\']SHA1["\']', "SHA-1", 7.5, "HIGH"),
            (r'SecureRandom\(\)', "Potential SecureRandom misuse", 5.0, "MEDIUM"),
        ]

        for pattern, algo, cvss, severity in weak_patterns:
            if pattern in self.all_code_content:
                finding = Finding(
                    id=f"SAST-{len(self.findings) + 1:04d}",
                    title=f"Weak Cryptographic Algorithm: {algo}",
                    description=f"Usage of weak cryptographic algorithm {algo} detected",
                    severity=severity.lower(),
                    category="A02:2021 - Cryptographic Failures",
                    module=AnalysisModule.SAST.value,
                    cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe=["CWE-327", "CWE-326"],
                    masvs_mapping=["MSTG-CRYPTO-1", "MSTG-CRYPTO-2"],
                    mastg_mapping=["MASTG-CRYPTO-1"],
                    affected_component="Cryptography Module",
                    remediation=f"Replace {algo} with AES or other strong algorithms",
                )
                self.findings.append(finding)

    def _check_insecure_storage(self) -> None:
        """Verifica armazenamento inseguro"""
        if 'SharedPreferences' in self.all_code_content and 'putString' in self.all_code_content:
            finding = Finding(
                id=f"SAST-{len(self.findings) + 1:04d}",
                title="Insecure Data Storage",
                description="Sensitive data stored in SharedPreferences without encryption",
                severity=FindingSeverity.HIGH.value,
                category="A01:2021 - Broken Access Control",
                module=AnalysisModule.SAST.value,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                cwe=["CWE-312", "CWE-313"],
                masvs_mapping=["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
                mastg_mapping=["MASTG-STORAGE-1"],
                affected_component="SharedPreferences",
                remediation="Use EncryptedSharedPreferences from Security library",
            )
            self.findings.append(finding)

    def _check_webview_issues(self) -> None:
        """Verifica problemas de WebView"""
        if 'WebView' in self.all_code_content:
            if 'setJavaScriptEnabled(true)' in self.all_code_content:
                finding = Finding(
                    id=f"SAST-{len(self.findings) + 1:04d}",
                    title="WebView with JavaScript Enabled",
                    description="JavaScript is enabled in WebView without proper protection",
                    severity=FindingSeverity.HIGH.value,
                    category="A03:2021 - Injection",
                    module=AnalysisModule.SAST.value,
                    cvss_score=7.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    cwe=["CWE-95"],
                    masvs_mapping=["MSTG-PLATFORM-2"],
                    mastg_mapping=["MASTG-PLATFORM-2"],
                    affected_component="WebView",
                    remediation="Disable JavaScript or use WebViewCompat with proper security",
                )
                self.findings.append(finding)

            if 'addJavascriptInterface' in self.all_code_content:
                finding = Finding(
                    id=f"SAST-{len(self.findings) + 1:04d}",
                    title="WebView JavaScript Interface Exposed",
                    description="JavaScript interface is exposed to WebView content",
                    severity=FindingSeverity.CRITICAL.value,
                    category="A03:2021 - Injection",
                    module=AnalysisModule.SAST.value,
                    cvss_score=9.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/I:H/A:H",
                    cwe=["CWE-95"],
                    masvs_mapping=["MSTG-PLATFORM-2"],
                    mastg_mapping=["MASTG-PLATFORM-2"],
                    affected_component="WebView",
                    remediation="Remove addJavascriptInterface or use proper security measures",
                )
                self.findings.append(finding)

    def _check_exported_components(self) -> None:
        """Verifica componentes exportados"""
        if 'android:exported="true"' in self.all_code_content:
            finding = Finding(
                id=f"SAST-{len(self.findings) + 1:04d}",
                title="Exported Components",
                description="Application components are exported without protection",
                severity=FindingSeverity.HIGH.value,
                category="A01:2021 - Broken Access Control",
                module=AnalysisModule.SAST.value,
                cvss_score=7.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe=["CWE-927"],
                masvs_mapping=["MSTG-PLATFORM-1"],
                mastg_mapping=["MASTG-PLATFORM-1"],
                affected_component="AndroidManifest.xml",
                remediation="Implement proper permission checks or set exported to false",
            )
            self.findings.append(finding)

    def _check_data_flows(self) -> None:
        """Verifica fluxos de dados sensíveis"""
        taint_analyzer = TaintAnalyzer()
        data_flows = taint_analyzer.analyze_code(self.all_code_content)

        for flow in data_flows:
            if not flow.is_sanitized and flow.confidence > 0.7:
                finding = Finding(
                    id=f"SAST-{len(self.findings) + 1:04d}",
                    title="Potential Data Flow Vulnerability",
                    description=f"Unsanitized data flow from {flow.source} to {flow.sink}",
                    severity=FindingSeverity.MEDIUM.value,
                    category="A03:2021 - Injection",
                    module=AnalysisModule.SAST.value,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe=["CWE-22", "CWE-89"],
                    masvs_mapping=["MSTG-STORAGE-1"],
                    mastg_mapping=["MASTG-STORAGE-1"],
                    confidence=f"{flow.confidence:.2f}",
                    affected_component="Data Flow",
                    remediation="Implement proper input validation and sanitization",
                )
                self.findings.append(finding)

    def _create_finding_from_vulnerability(self, vuln: Dict[str, Any]) -> Optional[Finding]:
        """Cria Finding a partir de uma vulnerabilidade detectada"""
        category_mappings = {
            "weak_crypto": {
                "severity": FindingSeverity.HIGH.value,
                "cvss": 7.5,
                "category": "A02:2021 - Cryptographic Failures",
                "cwe": ["CWE-327"],
                "masvs": ["MSTG-CRYPTO-1"],
            },
            "hardcoded_secrets": {
                "severity": FindingSeverity.CRITICAL.value,
                "cvss": 9.0,
                "category": "A02:2021 - Cryptographic Failures",
                "cwe": ["CWE-798"],
                "masvs": ["MSTG-STORAGE-1"],
            },
            "insecure_storage": {
                "severity": FindingSeverity.HIGH.value,
                "cvss": 7.5,
                "category": "A01:2021 - Broken Access Control",
                "cwe": ["CWE-312"],
                "masvs": ["MSTG-STORAGE-1"],
            },
            "insecure_logging": {
                "severity": FindingSeverity.MEDIUM.value,
                "cvss": 5.3,
                "category": "A09:2021 - Security Logging and Monitoring Failures",
                "cwe": ["CWE-532"],
                "masvs": ["MSTG-STORAGE-3"],
            },
            "webview_issues": {
                "severity": FindingSeverity.HIGH.value,
                "cvss": 7.3,
                "category": "A03:2021 - Injection",
                "cwe": ["CWE-95"],
                "masvs": ["MSTG-PLATFORM-2"],
            },
            "insecure_deserialization": {
                "severity": FindingSeverity.CRITICAL.value,
                "cvss": 8.1,
                "category": "A08:2021 - Software and Data Integrity Failures",
                "cwe": ["CWE-502"],
                "masvs": ["MSTG-CODE-7"],
            },
        }

        mapping = category_mappings.get(vuln['category'], {
            "severity": FindingSeverity.MEDIUM.value,
            "cvss": 5.0,
            "category": "A06:2021 - Vulnerable and Outdated Components",
            "cwe": ["CWE-1104"],
            "masvs": ["MSTG-CODE-1"],
        })

        finding = Finding(
            id=f"SAST-{len(self.findings) + 1:04d}",
            title=vuln['description'],
            description=f"Vulnerability detected: {vuln['description']} in {vuln.get('file', 'unknown')}",
            severity=mapping['severity'],
            category=mapping['category'],
            module=AnalysisModule.SAST.value,
            cvss_score=mapping['cvss'],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe=mapping['cwe'],
            masvs_mapping=mapping['masvs'],
            mastg_mapping=mapping['masvs'],
            evidence=[
                EvidenceItem(
                    type="code",
                    location=vuln.get('file', 'unknown'),
                    content=vuln.get('match', ''),
                    line_number=vuln.get('line', 0),
                )
            ],
            affected_component=vuln.get('file', 'unknown'),
            remediation=f"Fix {vuln['category']} vulnerability",
        )

        return finding
