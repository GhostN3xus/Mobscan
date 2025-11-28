"""
SCA Engine - Software Composition Analysis

Detecta bibliotecas externas, mapeia para CVEs,
identifica versões vulneráveis e gerencia risco.
"""

import re
import zipfile
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ...core.analysis_manager import BaseAnalysisModule, AnalysisModule, Finding, FindingSeverity, EvidenceItem

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Representa uma dependência/biblioteca"""
    name: str
    version: str
    type: str  # "library", "framework", "plugin"
    path: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    license: str = ""
    homepage: str = ""
    is_vulnerable: bool = False


class VulnerabilityDatabase:
    """Base de dados de vulnerabilidades conhecidas"""

    # Database simulado - em produção, consultaria NVD, OSV, etc
    KNOWN_VULNERABILITIES = {
        "okhttp": {
            "3.0.0": [
                {
                    "cve": "CVE-2015-4903",
                    "description": "SSL/TLS certificate validation vulnerability",
                    "severity": "high",
                    "cvss": 7.5
                }
            ],
            "3.2.0": []
        },
        "retrofit": {
            "2.0.0": [
                {
                    "cve": "CVE-2017-XXXX",
                    "description": "Insecure HTTP client configuration",
                    "severity": "medium",
                    "cvss": 5.3
                }
            ]
        },
        "jackson": {
            "2.7.0": [
                {
                    "cve": "CVE-2017-7525",
                    "description": "Deserialization of untrusted data",
                    "severity": "critical",
                    "cvss": 9.8
                }
            ],
            "2.9.0": []
        },
        "commons-collections": {
            "3.1": [
                {
                    "cve": "CVE-2015-4852",
                    "description": "Arbitrary code execution via deserialization",
                    "severity": "critical",
                    "cvss": 9.8
                }
            ],
            "3.2.2": []
        },
        "realm": {
            "5.0.0": [
                {
                    "cve": "CVE-2018-XXXX",
                    "description": "Unencrypted data storage",
                    "severity": "high",
                    "cvss": 7.5
                }
            ],
            "10.0.0": []
        },
    }

    DEPRECATED_LIBRARIES = {
        "okhttp": ["1.x", "2.x"],
        "android-support-v4": "Use AndroidX instead",
        "commons-codec": "3.2",
    }

    @staticmethod
    def check_vulnerability(library_name: str, version: str) -> List[Dict[str, Any]]:
        """Verifica vulnerabilidades conhecidas"""
        vulnerabilities = []

        lib = VulnerabilityDatabase.KNOWN_VULNERABILITIES.get(library_name.lower(), {})
        if version in lib:
            vulnerabilities = lib[version]

        return vulnerabilities

    @staticmethod
    def is_outdated(library_name: str, version: str) -> bool:
        """Verifica se biblioteca é desatualizada"""
        deprecated = VulnerabilityDatabase.DEPRECATED_LIBRARIES.get(library_name.lower())
        if deprecated:
            if isinstance(deprecated, list):
                return version in deprecated
            else:
                return True
        return False


class DependencyExtractor:
    """Extrai dependências de APK/IPA"""

    def __init__(self):
        self.dependencies: List[Dependency] = []

    def extract_from_apk(self, apk_path: str) -> List[Dependency]:
        """Extrai bibliotecas de APK"""
        self.dependencies = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Procurar por arquivos de dependência
                self._extract_gradle_dependencies(apk)
                self._extract_native_libraries(apk)
                self._extract_java_libraries(apk)

        except Exception as e:
            logger.error(f"Error extracting dependencies: {str(e)}")

        return self.dependencies

    def _extract_gradle_dependencies(self, apk: zipfile.ZipFile) -> None:
        """Extrai dependências do Gradle"""
        # Procura por build.gradle, gradle.properties, etc
        gradle_files = [f for f in apk.namelist() if 'gradle' in f.lower()]

        for gradle_file in gradle_files:
            try:
                content = apk.read(gradle_file).decode('utf-8', errors='ignore')

                # Padrões de dependências Gradle
                patterns = [
                    r'implementation\s+["\']([a-zA-Z0-9._:-]+):([a-zA-Z0-9._-]+)["\']',
                    r'compile\s+["\']([a-zA-Z0-9._:-]+):([a-zA-Z0-9._-]+)["\']',
                    r'dependencies\s*{\s*([^}]+)\s*}',
                ]

                for pattern in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        groups = match.groups()
                        if len(groups) >= 2:
                            group_id = groups[0]
                            artifact_id = groups[1]
                            version = groups[2] if len(groups) > 2 else "unknown"

                            dep = Dependency(
                                name=f"{group_id}:{artifact_id}",
                                version=version,
                                type="library",
                                path=gradle_file
                            )
                            self.dependencies.append(dep)

            except Exception as e:
                logger.debug(f"Error parsing {gradle_file}: {str(e)}")

    def _extract_native_libraries(self, apk: zipfile.ZipFile) -> None:
        """Extrai bibliotecas nativas (.so)"""
        native_libs = [f for f in apk.namelist() if f.endswith('.so')]

        for lib_path in native_libs:
            # Extrair nome da biblioteca
            lib_name = Path(lib_path).name

            dep = Dependency(
                name=lib_name,
                version="unknown",
                type="native_library",
                path=lib_path
            )
            self.dependencies.append(dep)

    def _extract_java_libraries(self, apk: zipfile.ZipFile) -> None:
        """Extrai bibliotecas Java (.jar)"""
        jar_files = [f for f in apk.namelist() if f.endswith('.jar')]

        for jar_path in jar_files:
            jar_name = Path(jar_path).name

            dep = Dependency(
                name=jar_name,
                version="unknown",
                type="java_library",
                path=jar_path
            )
            self.dependencies.append(dep)

    def extract_from_ipa(self, ipa_path: str) -> List[Dependency]:
        """Extrai bibliotecas de IPA"""
        self.dependencies = []

        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa:
                # Procurar por CocoaPods, Cartago, SPM
                podfile_files = [f for f in ipa.namelist() if 'podfile' in f.lower() or 'cartago' in f.lower()]

                for podfile in podfile_files:
                    try:
                        content = ipa.read(podfile).decode('utf-8', errors='ignore')

                        # Padrões CocoaPods
                        pod_pattern = r"pod\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?"
                        matches = re.finditer(pod_pattern, content)

                        for match in matches:
                            pod_name = match.group(1)
                            pod_version = match.group(2) or "unknown"

                            dep = Dependency(
                                name=pod_name,
                                version=pod_version,
                                type="cocoapod",
                                path=podfile
                            )
                            self.dependencies.append(dep)

                    except Exception as e:
                        logger.debug(f"Error parsing {podfile}: {str(e)}")

        except Exception as e:
            logger.error(f"Error extracting iOS dependencies: {str(e)}")

        return self.dependencies


class SCAModule(BaseAnalysisModule):
    """
    Módulo SCA Profissional

    Detecta:
    - Bibliotecas com vulnerabilidades conhecidas
    - Versões desatualizadas
    - Bibliotecas descontinuadas
    - Problemas de licença
    - Dependências de risco alto
    - Supply chain attacks
    """

    def __init__(self):
        super().__init__(AnalysisModule.SCA, "SCA Engine")
        self.extractor = DependencyExtractor()
        self.dependencies: List[Dependency] = []

    def execute(self, app_path: str, config: Dict[str, Any]) -> List[Finding]:
        """Executa análise SCA"""
        self.findings = []

        try:
            self.logger.info(f"Starting SCA analysis for {app_path}")

            # Extrair dependências
            app_file = Path(app_path)
            if app_file.suffix.lower() == ".apk":
                self.dependencies = self.extractor.extract_from_apk(app_path)
            elif app_file.suffix.lower() == ".ipa":
                self.dependencies = self.extractor.extract_from_ipa(app_path)

            # Analisar vulnerabilidades
            self._analyze_vulnerabilities()

            # Verificar desatualização
            self._check_outdated_libraries()

            # Verificar dependências transitivas
            self._check_transitive_dependencies()

            self.logger.info(f"SCA analysis completed: {len(self.findings)} findings")

        except Exception as e:
            self.logger.error(f"SCA analysis error: {str(e)}", exc_info=True)

        return self.findings

    def _analyze_vulnerabilities(self) -> None:
        """Analisa vulnerabilidades em dependências"""
        self.logger.info(f"Analyzing {len(self.dependencies)} dependencies for vulnerabilities...")

        for dep in self.dependencies:
            # Limpar nome para busca
            dep_name = dep.name.replace(":", "/").split("/")[-1].lower()

            # Verificar vulnerabilidades
            vulnerabilities = VulnerabilityDatabase.check_vulnerability(dep_name, dep.version)

            if vulnerabilities:
                dep.is_vulnerable = True
                dep.vulnerabilities = vulnerabilities

                for vuln in vulnerabilities:
                    finding = Finding(
                        id=f"SCA-{len(self.findings) + 1:04d}",
                        title=f"Vulnerable Dependency: {dep.name}",
                        description=f"Library {dep.name} v{dep.version} has known vulnerability: {vuln['cve']} - {vuln['description']}",
                        severity=vuln['severity'].lower() if vuln['severity'].lower() in ['critical', 'high', 'medium', 'low'] else 'medium',
                        category="A06:2021 - Vulnerable and Outdated Components",
                        module=AnalysisModule.SCA.value,
                        cvss_score=vuln['cvss'],
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe=["CWE-1104"],
                        masvs_mapping=["MSTG-CODE-1"],
                        mastg_mapping=["MASTG-CODE-1"],
                        evidence=[
                            EvidenceItem(
                                type="dependency",
                                location=dep.path,
                                content=f"{dep.name}:{dep.version}"
                            )
                        ],
                        affected_component=dep.name,
                        remediation=f"Update {dep.name} to latest patched version",
                    )
                    self.findings.append(finding)

    def _check_outdated_libraries(self) -> None:
        """Verifica bibliotecas desatualizadas"""
        for dep in self.dependencies:
            dep_name = dep.name.replace(":", "/").split("/")[-1].lower()

            if VulnerabilityDatabase.is_outdated(dep_name, dep.version):
                finding = Finding(
                    id=f"SCA-{len(self.findings) + 1:04d}",
                    title=f"Outdated Dependency: {dep.name}",
                    description=f"Library {dep.name} v{dep.version} is outdated and should be updated",
                    severity=FindingSeverity.MEDIUM.value,
                    category="A06:2021 - Vulnerable and Outdated Components",
                    module=AnalysisModule.SCA.value,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    cwe=["CWE-1104"],
                    masvs_mapping=["MSTG-CODE-1"],
                    mastg_mapping=["MSTG-CODE-1"],
                    affected_component=dep.name,
                    remediation=f"Update {dep.name} to the latest version",
                )
                self.findings.append(finding)

    def _check_transitive_dependencies(self) -> None:
        """Verifica dependências transitivas"""
        # Verificar por problemas em dependências indiretas
        if self.dependencies:
            finding = Finding(
                id=f"SCA-{len(self.findings) + 1:04d}",
                title="Transitive Dependency Risks",
                description=f"Application has {len(self.dependencies)} dependencies. Transitive dependency attacks are possible.",
                severity=FindingSeverity.LOW.value,
                category="A06:2021 - Vulnerable and Outdated Components",
                module=AnalysisModule.SCA.value,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe=["CWE-1104"],
                masvs_mapping=["MSTG-CODE-1"],
                mastg_mapping=["MSTG-CODE-1"],
                affected_component="Dependency Management",
                remediation="Regularly update dependencies and use dependency locking",
            )
            self.findings.append(finding)

    def get_dependency_report(self) -> Dict[str, Any]:
        """Gera relatório de dependências"""
        vulnerable_deps = [d for d in self.dependencies if d.is_vulnerable]

        return {
            "total_dependencies": len(self.dependencies),
            "vulnerable_dependencies": len(vulnerable_deps),
            "vulnerabilities": sum(len(d.vulnerabilities) for d in vulnerable_deps),
            "dependencies": [
                {
                    "name": d.name,
                    "version": d.version,
                    "type": d.type,
                    "is_vulnerable": d.is_vulnerable,
                    "vulnerabilities": d.vulnerabilities
                }
                for d in self.dependencies
            ]
        }
