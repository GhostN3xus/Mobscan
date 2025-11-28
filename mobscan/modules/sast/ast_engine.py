"""
AST Engine - Abstract Syntax Tree Analysis for SAST

Implementa análise baseada em AST para detectar vulnerabilidades
em código de aplicações móveis.
"""

import re
import ast
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class TaintType(str, Enum):
    """Tipos de taint (source)"""
    USER_INPUT = "user_input"
    NETWORK = "network"
    FILE = "file"
    CRYPTO = "crypto"
    STORAGE = "storage"
    SENSITIVE_DATA = "sensitive_data"


class SinkType(str, Enum):
    """Tipos de sink (onde o taint não deveria chegar)"""
    CRYPTO = "crypto"
    STORAGE = "storage"
    NETWORK = "network"
    LOGGING = "logging"
    EXECUTION = "execution"
    DATABASE = "database"


@dataclass
class DataFlowPath:
    """Representa um caminho de fluxo de dados"""
    source: str
    sink: str
    path: List[str]
    is_sanitized: bool = False
    confidence: float = 0.8


class TaintAnalyzer:
    """Analisa fluxo de dados (taint analysis)"""

    # Fontes de dados sensíveis
    SOURCES = {
        TaintType.USER_INPUT: [
            r'getIntent',
            r'Bundle\.get',
            r'Uri',
            r'SharedPreferences',
            r'Intent\.getExtra',
            r'getArguments',
            r'request\.getParameter',
        ],
        TaintType.NETWORK: [
            r'HttpResponse',
            r'URLConnection',
            r'Socket',
            r'DataInputStream',
            r'NetworkRequest',
        ],
        TaintType.FILE: [
            r'FileInputStream',
            r'FileReader',
            r'readFile',
            r'Files\.read',
        ],
        TaintType.CRYPTO: [
            r'cipher\.doFinal',
            r'MessageDigest',
            r'SecureRandom',
        ],
        TaintType.STORAGE: [
            r'SharedPreferences',
            r'SQLiteDatabase',
            r'Realm',
            r'realm\.copyToRealmOrUpdate',
        ],
    }

    # Sinks perigosos
    SINKS = {
        SinkType.CRYPTO: [
            r'Cipher\.getInstance\(["\']([^"\']+)["\']',
            r'MessageDigest\.getInstance\(["\']([^"\']+)["\']',
        ],
        SinkType.STORAGE: [
            r'SharedPreferences\.Editor\.putString',
            r'insert\(',
            r'update\(',
            r'execute\(',
        ],
        SinkType.LOGGING: [
            r'Log\.d\(',
            r'Log\.e\(',
            r'System\.out\.println',
            r'println',
        ],
        SinkType.EXECUTION: [
            r'Runtime\.getRuntime\(\)\.exec',
            r'ProcessBuilder',
        ],
        SinkType.NETWORK: [
            r'\.setRequestProperty\(',
            r'\.write\(',
            r'connect\(\)',
        ],
    }

    def __init__(self):
        self.data_flows: List[DataFlowPath] = []

    def analyze_code(self, code: str) -> List[DataFlowPath]:
        """Analisa código para detectar fluxos de dados"""
        self.data_flows = []

        # Encontra sources
        sources = self._find_sources(code)

        # Encontra sinks
        sinks = self._find_sinks(code)

        # Correlaciona source -> sink
        for source in sources:
            for sink in sinks:
                path = self._trace_path(code, source, sink)
                if path:
                    self.data_flows.append(path)

        return self.data_flows

    def _find_sources(self, code: str) -> List[Tuple[str, TaintType]]:
        """Encontra sources de taint"""
        sources = []

        for taint_type, patterns in self.SOURCES.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    sources.append((match.group(0), taint_type))

        return sources

    def _find_sinks(self, code: str) -> List[Tuple[str, SinkType]]:
        """Encontra sinks de taint"""
        sinks = []

        for sink_type, patterns in self.SINKS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE)
                for match in matches:
                    sinks.append((match.group(0), sink_type))

        return sinks

    def _trace_path(self, code: str, source: Tuple[str, TaintType], sink: Tuple[str, SinkType]) -> Optional[DataFlowPath]:
        """Rastreia caminho entre source e sink"""
        source_text, source_type = source
        sink_text, sink_type = sink

        # Verificar se há validação/sanitização entre source e sink
        is_sanitized = self._check_sanitization(code, source_text, sink_text)

        path = DataFlowPath(
            source=f"{source_type.value}:{source_text}",
            sink=f"{sink_type.value}:{sink_text}",
            path=[source_text, sink_text],
            is_sanitized=is_sanitized,
            confidence=0.9 if not is_sanitized else 0.3
        )

        return path

    def _check_sanitization(self, code: str, source: str, sink: str) -> bool:
        """Verifica se há sanitização entre source e sink"""
        sanitization_patterns = [
            r'TextUtils\.isEmpty',
            r'validate',
            r'sanitize',
            r'trim\(\)',
            r'replaceAll',
            r'URLEncoder\.encode',
            r'Html\.escapeHtml32',
        ]

        for pattern in sanitization_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True

        return False


class ControlFlowAnalyzer:
    """Analisa Control Flow Graph (CFG)"""

    def __init__(self):
        self.nodes: List[str] = []
        self.edges: List[Tuple[str, str]] = []

    def analyze_functions(self, code: str) -> Dict[str, Any]:
        """Analisa funções e seu CFG"""
        results = {}

        # Encontra definições de funções
        function_pattern = r'(?:def|fun|void|int|String|boolean|Object)\s+(\w+)\s*\('
        functions = re.finditer(function_pattern, code)

        for func_match in functions:
            func_name = func_match.group(1)
            func_start = func_match.start()

            # Encontra o corpo da função (simples heurística)
            # Em produção, usaria parser completo
            cfg = self._extract_cfg_simple(code[func_start:])
            results[func_name] = {
                'nodes': cfg.get('nodes', []),
                'edges': cfg.get('edges', []),
                'complexity': len(cfg.get('nodes', [])),
            }

        return results

    def _extract_cfg_simple(self, code: str) -> Dict[str, Any]:
        """Extração simples de CFG"""
        nodes = []
        edges = []

        # Encontra estruturas de controle
        control_patterns = [
            (r'if\s*\(', 'if'),
            (r'else', 'else'),
            (r'for\s*\(', 'for'),
            (r'while\s*\(', 'while'),
            (r'switch\s*\(', 'switch'),
            (r'case\s+', 'case'),
            (r'try\s*\{', 'try'),
            (r'catch\s*\(', 'catch'),
        ]

        for pattern, node_type in control_patterns:
            matches = re.finditer(pattern, code)
            for i, match in enumerate(matches):
                node_id = f"{node_type}_{i}"
                nodes.append(node_id)
                if i > 0:
                    edges.append((f"{node_type}_{i-1}", node_id))

        return {
            'nodes': nodes,
            'edges': edges,
        }


class VulnerabilityDetector:
    """Detecta vulnerabilidades específicas em código"""

    # Padrões de vulnerabilidades
    VULNERABILITY_PATTERNS = {
        "weak_crypto": [
            (r'Cipher\.getInstance\(["\']DES["\']', "Weak Cryptography: DES"),
            (r'MessageDigest\.getInstance\(["\']MD5["\']', "Weak Hash: MD5"),
            (r'MessageDigest\.getInstance\(["\']SHA1["\']', "Weak Hash: SHA-1"),
            (r'Cipher\.getInstance\(["\']ECB["\']', "ECB Mode is Weak"),
        ],
        "hardcoded_secrets": [
            (r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9]+)["\']', "Hardcoded API Key"),
            (r'password\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded Password"),
            (r'secret\s*[=:]\s*["\']([a-zA-Z0-9]+)["\']', "Hardcoded Secret"),
            (r'token\s*[=:]\s*["\']([a-zA-Z0-9]+)["\']', "Hardcoded Token"),
        ],
        "insecure_storage": [
            (r'SharedPreferences.*getSharedPreferences\(["\']', "Unencrypted SharedPreferences"),
            (r'\.putString\(', "Storing unencrypted data"),
        ],
        "insecure_logging": [
            (r'Log\.d\(\s*["\']', "Debug logging enabled"),
            (r'System\.out\.println\(', "Using System.out for logging"),
        ],
        "webview_issues": [
            (r'setJavaScriptEnabled\(true\)', "JavaScript enabled in WebView"),
            (r'addJavascriptInterface\(', "JavaScript Interface exposed"),
            (r'setWebContentsDebuggingEnabled\(true\)', "WebView debugging enabled"),
        ],
        "insecure_deserialization": [
            (r'ObjectInputStream', "Insecure Deserialization"),
            (r'readObject\(\)', "Unsafe readObject call"),
        ],
    }

    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []

    def detect(self, code: str, source_file: str = "") -> List[Dict[str, Any]]:
        """Detecta vulnerabilidades no código"""
        self.vulnerabilities = []

        for category, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern, description in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    vuln = {
                        'category': category,
                        'description': description,
                        'pattern': pattern,
                        'match': match.group(0),
                        'line': code[:match.start()].count('\n') + 1,
                        'file': source_file,
                    }
                    self.vulnerabilities.append(vuln)

        return self.vulnerabilities


class ASTEngine:
    """Motor de análise AST completo"""

    def __init__(self):
        self.taint_analyzer = TaintAnalyzer()
        self.cfg_analyzer = ControlFlowAnalyzer()
        self.vuln_detector = VulnerabilityDetector()

    def analyze_code(self, code: str, source_file: str = "") -> Dict[str, Any]:
        """Análise completa de código"""
        return {
            'data_flows': self.taint_analyzer.analyze_code(code),
            'control_flow': self.cfg_analyzer.analyze_functions(code),
            'vulnerabilities': self.vuln_detector.detect(code, source_file),
        }
