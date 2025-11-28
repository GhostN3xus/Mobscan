"""
AnalysisManager - Central Analysis Orchestration Engine

Coordina SAST, DAST, Instrumentation (Frida) e SCA (Software Composition Analysis).
Gerencia pipeline de análise e padroniza entrada/saída de módulos.

Pipeline:
  preprocessing → module_executions → merge_findings → validation → correlation → scoring → reporting
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Type
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import concurrent.futures
import hashlib

logger = logging.getLogger(__name__)


class AnalysisModule(str, Enum):
    """Tipos de módulos de análise"""
    SAST = "sast"
    DAST = "dast"
    FRIDA = "frida"
    SCA = "sca"


class FindingSeverity(str, Enum):
    """Níveis de severidade de acordo com OWASP"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    """Níveis de confiança do achado"""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EvidenceItem:
    """Evidência de um achado"""
    type: str  # "code_snippet", "network_request", "file", "log", "config", etc
    location: str  # Localização no código/arquivo
    content: str  # Conteúdo da evidência
    line_number: Optional[int] = None
    confidence: str = ConfidenceLevel.HIGH.value


@dataclass
class Finding:
    """
    Schema JSON padronizado para Findings

    Estrutura:
    {
        id, title, description, severity, category, masvs_mapping,
        evidence, source, confidence, location
    }
    """
    id: str
    title: str
    description: str
    severity: str  # Enum FindingSeverity
    category: str  # Categoria OWASP (ex: A02:2021)
    module: str  # AnalysisModule
    cvss_score: float
    cvss_vector: str
    cwe: List[str] = field(default_factory=list)
    masvs_mapping: List[str] = field(default_factory=list)  # MASVS requirements
    mastg_mapping: List[str] = field(default_factory=list)  # MASTG tests
    evidence: List[EvidenceItem] = field(default_factory=list)
    source_module: str = ""  # Qual módulo encontrou
    confidence: str = ConfidenceLevel.HIGH.value
    location: Optional[str] = None
    affected_component: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    hash: str = ""  # Hash para deduplicação

    def calculate_hash(self) -> str:
        """Calcula hash para deduplicação"""
        content = f"{self.title}{self.description}{self.location}{self.affected_component}"
        self.hash = hashlib.sha256(content.encode()).hexdigest()
        return self.hash

    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        data = asdict(self)
        data['evidence'] = [asdict(e) for e in self.evidence]
        return data

    def to_json(self) -> str:
        """Converte para JSON"""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class AnalysisConfig:
    """Configuração para análise"""
    timeout_per_module: int = 300  # segundos
    parallel_execution: bool = True
    max_workers: int = 4
    enable_deduplication: bool = True
    enable_correlation: bool = True
    enable_severity_scoring: bool = True


class BaseAnalysisModule:
    """Classe base para todos os módulos de análise"""

    def __init__(self, module_type: AnalysisModule, name: str):
        self.module_type = module_type
        self.name = name
        self.logger = logging.getLogger(f"mobscan.{module_type.value}")
        self.findings: List[Finding] = []
        self.is_enabled = True

    def validate_input(self, app_path: str) -> bool:
        """Valida entrada do módulo"""
        app_file = Path(app_path)
        if not app_file.exists():
            self.logger.error(f"Application file not found: {app_path}")
            return False
        return True

    def execute(self, app_path: str, config: Dict[str, Any]) -> List[Finding]:
        """Executa análise. Deve ser implementado por subclasses."""
        raise NotImplementedError

    def preprocess(self, app_path: str) -> Any:
        """Pré-processamento (parsing, extração, etc)"""
        pass

    def postprocess(self, findings: List[Finding]) -> List[Finding]:
        """Pós-processamento de findings"""
        for finding in findings:
            finding.calculate_hash()
            finding.source_module = self.module_type.value
        return findings


class AnalysisManager:
    """
    Gerenciador Central de Análise

    Responsabilidades:
    - Registrar módulos de análise
    - Coordenar execução paralela
    - Validar e correlacionar findings
    - Aplicar scoring de risco
    - Gerar relatórios
    """

    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self.logger = logging.getLogger("mobscan.analysis_manager")
        self.modules: Dict[AnalysisModule, BaseAnalysisModule] = {}
        self.findings: List[Finding] = []
        self.scan_id = str(uuid.uuid4())
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None

    def register_module(self, module: BaseAnalysisModule) -> None:
        """Registra um módulo de análise"""
        self.modules[module.module_type] = module
        self.logger.info(f"Module registered: {module.module_type.value} - {module.name}")

    def enable_module(self, module_type: AnalysisModule) -> None:
        """Ativa um módulo"""
        if module_type in self.modules:
            self.modules[module_type].is_enabled = True
            self.logger.info(f"Module enabled: {module_type.value}")

    def disable_module(self, module_type: AnalysisModule) -> None:
        """Desativa um módulo"""
        if module_type in self.modules:
            self.modules[module_type].is_enabled = False
            self.logger.info(f"Module disabled: {module_type.value}")

    def run_analysis(self, app_path: str, module_configs: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Executa pipeline completo de análise

        Args:
            app_path: Caminho para APK/IPA
            module_configs: Configurações específicas por módulo

        Returns:
            Resultado da análise com métricas
        """
        self.logger.info(f"Starting analysis pipeline for: {app_path}")
        self.scan_start_time = datetime.now()
        self.findings = []
        module_configs = module_configs or {}

        try:
            # 1. Preprocessing
            self.logger.info("Phase 1: Preprocessing")
            self._preprocessing(app_path)

            # 2. Module Executions
            self.logger.info("Phase 2: Module Executions")
            module_findings = self._execute_modules(app_path, module_configs)

            # 3. Merge Findings
            self.logger.info("Phase 3: Merging findings")
            self._merge_findings(module_findings)

            # 4. Validation
            self.logger.info("Phase 4: Validating findings")
            self._validate_findings()

            # 5. Correlation
            self.logger.info("Phase 5: Correlating findings")
            self._correlate_findings()

            # 6. Scoring
            self.logger.info("Phase 6: Severity scoring")
            self._apply_scoring()

            # 7. Reporting
            self.logger.info("Phase 7: Generating report")
            report = self._generate_report()

            self.scan_end_time = datetime.now()
            return report

        except Exception as e:
            self.logger.error(f"Analysis pipeline error: {str(e)}", exc_info=True)
            raise

    def _preprocessing(self, app_path: str) -> None:
        """Pré-processamento de aplicação"""
        app_file = Path(app_path)
        if not app_file.exists():
            raise FileNotFoundError(f"Application file not found: {app_path}")

        self.logger.info(f"Application file: {app_file.name}")
        self.logger.info(f"File size: {app_file.stat().st_size / (1024*1024):.2f} MB")
        self.logger.info(f"File type: {app_file.suffix}")

    def _execute_modules(self, app_path: str, configs: Dict[str, Dict[str, Any]]) -> Dict[AnalysisModule, List[Finding]]:
        """Executa módulos de análise em paralelo ou sequencial"""
        module_findings: Dict[AnalysisModule, List[Finding]] = {}

        if self.config.parallel_execution:
            module_findings = self._execute_parallel(app_path, configs)
        else:
            module_findings = self._execute_sequential(app_path, configs)

        return module_findings

    def _execute_parallel(self, app_path: str, configs: Dict[str, Dict[str, Any]]) -> Dict[AnalysisModule, List[Finding]]:
        """Execução paralela de módulos"""
        module_findings: Dict[AnalysisModule, List[Finding]] = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {}

            for module_type, module in self.modules.items():
                if not module.is_enabled:
                    continue

                config = configs.get(module_type.value, {})
                future = executor.submit(
                    self._run_module_safe,
                    module,
                    app_path,
                    config
                )
                futures[future] = module_type

            for future in concurrent.futures.as_completed(futures):
                module_type = futures[future]
                try:
                    findings = future.result(timeout=self.config.timeout_per_module)
                    module_findings[module_type] = findings or []
                    self.logger.info(f"Module {module_type.value} completed: {len(module_findings[module_type])} findings")
                except Exception as e:
                    self.logger.error(f"Module {module_type.value} failed: {str(e)}")
                    module_findings[module_type] = []

        return module_findings

    def _execute_sequential(self, app_path: str, configs: Dict[str, Dict[str, Any]]) -> Dict[AnalysisModule, List[Finding]]:
        """Execução sequencial de módulos"""
        module_findings: Dict[AnalysisModule, List[Finding]] = {}

        for module_type, module in self.modules.items():
            if not module.is_enabled:
                continue

            config = configs.get(module_type.value, {})
            try:
                findings = self._run_module_safe(module, app_path, config)
                module_findings[module_type] = findings or []
                self.logger.info(f"Module {module_type.value} completed: {len(module_findings[module_type])} findings")
            except Exception as e:
                self.logger.error(f"Module {module_type.value} failed: {str(e)}")
                module_findings[module_type] = []

        return module_findings

    def _run_module_safe(self, module: BaseAnalysisModule, app_path: str, config: Dict[str, Any]) -> List[Finding]:
        """Executa módulo com tratamento de erros"""
        try:
            if not module.validate_input(app_path):
                return []

            # Pré-processamento
            module.preprocess(app_path)

            # Execução
            findings = module.execute(app_path, config)

            # Pós-processamento
            findings = module.postprocess(findings)

            return findings
        except Exception as e:
            self.logger.error(f"Error in module {module.module_type.value}: {str(e)}")
            return []

    def _merge_findings(self, module_findings: Dict[AnalysisModule, List[Finding]]) -> None:
        """Mescla findings de todos os módulos"""
        total_findings = 0
        for module_type, findings in module_findings.items():
            self.findings.extend(findings)
            total_findings += len(findings)

        self.logger.info(f"Total findings from all modules: {total_findings}")

    def _validate_findings(self) -> None:
        """Valida findings"""
        valid_findings = []

        for finding in self.findings:
            # Validações básicas
            if not finding.id or not finding.title:
                self.logger.warning(f"Invalid finding (missing id/title)")
                continue

            if finding.severity not in [e.value for e in FindingSeverity]:
                self.logger.warning(f"Invalid severity: {finding.severity}")
                finding.severity = FindingSeverity.MEDIUM.value

            valid_findings.append(finding)

        self.findings = valid_findings
        self.logger.info(f"Findings after validation: {len(self.findings)}")

    def _correlate_findings(self) -> None:
        """Correlaciona e deduplica findings"""
        if not self.config.enable_deduplication:
            return

        # Calcula hashes para deduplicação
        for finding in self.findings:
            finding.calculate_hash()

        # Remove duplicatas
        seen_hashes = set()
        unique_findings = []

        for finding in self.findings:
            if finding.hash not in seen_hashes:
                unique_findings.append(finding)
                seen_hashes.add(finding.hash)

        duplicates_removed = len(self.findings) - len(unique_findings)
        self.findings = unique_findings
        self.logger.info(f"Removed {duplicates_removed} duplicate findings")

    def _apply_scoring(self) -> None:
        """Aplica scoring de severidade"""
        if not self.config.enable_severity_scoring:
            return

        # Ordenar por CVSS score
        self.findings.sort(key=lambda x: x.cvss_score, reverse=True)

        # Calcular estatísticas
        severity_counts = {
            FindingSeverity.CRITICAL.value: 0,
            FindingSeverity.HIGH.value: 0,
            FindingSeverity.MEDIUM.value: 0,
            FindingSeverity.LOW.value: 0,
            FindingSeverity.INFO.value: 0,
        }

        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        self.logger.info(f"Severity distribution: {severity_counts}")

    def _generate_report(self) -> Dict[str, Any]:
        """Gera relatório de análise"""
        duration_seconds = 0
        if self.scan_start_time and self.scan_end_time:
            duration_seconds = (self.scan_end_time - self.scan_start_time).total_seconds()

        # Contadores por severidade
        severity_counts = {
            FindingSeverity.CRITICAL.value: 0,
            FindingSeverity.HIGH.value: 0,
            FindingSeverity.MEDIUM.value: 0,
            FindingSeverity.LOW.value: 0,
            FindingSeverity.INFO.value: 0,
        }

        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        # Calcular risk score
        risk_score = self._calculate_risk_score()

        return {
            "scan_id": self.scan_id,
            "timestamp": self.scan_start_time.isoformat() if self.scan_start_time else None,
            "duration_seconds": duration_seconds,
            "total_findings": len(self.findings),
            "severity_distribution": severity_counts,
            "risk_score": risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "modules_executed": list(self.modules.keys()),
        }

    def _calculate_risk_score(self) -> float:
        """Calcula score de risco (0-10)"""
        if not self.findings:
            return 0.0

        # Peso por severidade
        weights = {
            FindingSeverity.CRITICAL.value: 10.0,
            FindingSeverity.HIGH.value: 7.0,
            FindingSeverity.MEDIUM.value: 5.0,
            FindingSeverity.LOW.value: 2.0,
            FindingSeverity.INFO.value: 1.0,
        }

        total_score = 0.0
        for finding in self.findings:
            weight = weights.get(finding.severity, 1.0)
            cvss_factor = min(finding.cvss_score / 10.0, 1.0)
            total_score += weight * cvss_factor

        # Normalizar para 0-10
        max_possible_score = len(self.findings) * 10.0
        risk_score = min((total_score / max_possible_score) * 10.0, 10.0) if max_possible_score > 0 else 0.0

        return round(risk_score, 2)

    def export_findings(self, format: str = "json") -> str:
        """Exporta findings em diferentes formatos"""
        if format == "json":
            return json.dumps([f.to_dict() for f in self.findings], indent=2)
        elif format == "csv":
            return self._export_csv()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_csv(self) -> str:
        """Exporta findings em CSV"""
        if not self.findings:
            return ""

        import csv
        from io import StringIO

        output = StringIO()
        fieldnames = ['id', 'title', 'severity', 'cvss_score', 'module', 'affected_component', 'remediation']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for finding in self.findings:
            writer.writerow({
                'id': finding.id,
                'title': finding.title,
                'severity': finding.severity,
                'cvss_score': finding.cvss_score,
                'module': finding.module,
                'affected_component': finding.affected_component,
                'remediation': finding.remediation,
            })

        return output.getvalue()

    def get_statistics(self) -> Dict[str, Any]:
        """Retorna estatísticas da análise"""
        duration_seconds = 0
        if self.scan_start_time and self.scan_end_time:
            duration_seconds = (self.scan_end_time - self.scan_start_time).total_seconds()

        return {
            "scan_id": self.scan_id,
            "total_findings": len(self.findings),
            "duration_seconds": duration_seconds,
            "modules_count": len([m for m in self.modules.values() if m.is_enabled]),
            "risk_score": self._calculate_risk_score(),
        }
