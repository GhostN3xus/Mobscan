"""
mitmproxy Integration Module.

Integrates Mobscan with mitmproxy for intercepting and analyzing
network traffic during mobile application testing.
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import re


logger = logging.getLogger(__name__)


@dataclass
class RequestData:
    """Captured HTTP request data"""

    timestamp: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    client_address: str


@dataclass
class ResponseData:
    """Captured HTTP response data"""

    timestamp: str
    status_code: int
    headers: Dict[str, str]
    body: Optional[bytes]
    content_type: str


@dataclass
class CapturedFlow:
    """Complete HTTP flow (request + response)"""

    request: RequestData
    response: Optional[ResponseData] = None
    issues: List[Dict[str, Any]] = field(default_factory=list)


class MitmproxyAnalyzer:
    """Analyzer for mitmproxy captured flows"""

    def __init__(self):
        """Initialize analyzer"""
        self.flows: List[CapturedFlow] = []
        self.sensitive_patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize regex patterns for sensitive data detection"""
        return {
            "api_key": re.compile(
                r"(api[_-]?key|apikey|api_token|token)['\"]?\s*[=:]\s*['\"]?([a-zA-Z0-9\-_]{20,})",
                re.IGNORECASE,
            ),
            "password": re.compile(
                r"(password|passwd|pwd)['\"]?\s*[=:]\s*['\"]?([^'\"\s&]{6,})",
                re.IGNORECASE,
            ),
            "credit_card": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "jwt": re.compile(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            ),
            "bearer_token": re.compile(
                r"(bearer|token)['\"]?\s*[=:]\s*['\"]?([a-zA-Z0-9\-_\.]{20,})",
                re.IGNORECASE,
            ),
        }

    def add_flow(self, flow: CapturedFlow):
        """Add captured flow to analyzer"""
        self.flows.append(flow)

    def analyze_flow(self, flow: CapturedFlow) -> Dict[str, Any]:
        """Analyze single flow for security issues"""
        issues = []

        # Check request
        req_issues = self._analyze_request(flow.request)
        issues.extend(req_issues)

        # Check response if available
        if flow.response:
            resp_issues = self._analyze_response(flow.response)
            issues.extend(resp_issues)

        flow.issues = issues
        return {"flow": flow, "issues": issues}

    def _analyze_request(self, request: RequestData) -> List[Dict[str, Any]]:
        """Analyze request for security issues"""
        issues = []

        # Check for sensitive data in URL
        if self._contains_sensitive_data(request.url):
            issues.append({
                "type": "sensitive_data_in_url",
                "severity": "high",
                "message": "Sensitive data detected in URL",
                "url": request.url,
            })

        # Check for sensitive data in headers
        for header, value in request.headers.items():
            if self._contains_sensitive_data(str(value)):
                issues.append({
                    "type": "sensitive_data_in_headers",
                    "severity": "high",
                    "message": f"Sensitive data in header: {header}",
                    "header": header,
                })

        # Check for unencrypted requests
        if not request.url.startswith("https"):
            issues.append({
                "type": "unencrypted_communication",
                "severity": "critical",
                "message": "Unencrypted HTTP communication detected",
                "url": request.url,
            })

        # Check request body if present
        if request.body:
            body_str = self._decode_body(request.body)
            if self._contains_sensitive_data(body_str):
                issues.append({
                    "type": "sensitive_data_in_body",
                    "severity": "high",
                    "message": "Sensitive data detected in request body",
                })

        return issues

    def _analyze_response(self, response: ResponseData) -> List[Dict[str, Any]]:
        """Analyze response for security issues"""
        issues = []

        # Check for security headers
        security_headers = {
            "strict-transport-security": "HSTS",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "content-security-policy": "CSP",
            "x-xss-protection": "X-XSS-Protection",
        }

        for header, name in security_headers.items():
            if header.lower() not in {h.lower() for h in response.headers.keys()}:
                issues.append({
                    "type": "missing_security_header",
                    "severity": "medium",
                    "message": f"Missing security header: {name}",
                    "header": name,
                })

        # Check for sensitive data in response body
        if response.body:
            body_str = self._decode_body(response.body)
            if self._contains_sensitive_data(body_str):
                issues.append({
                    "type": "sensitive_data_in_response",
                    "severity": "high",
                    "message": "Sensitive data detected in response body",
                })

        # Check response status code
        if response.status_code >= 400:
            issues.append({
                "type": "http_error",
                "severity": "medium",
                "message": f"HTTP Error: {response.status_code}",
                "status_code": response.status_code,
            })

        return issues

    def _contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data patterns"""
        for pattern in self.sensitive_patterns.values():
            if pattern.search(text):
                return True
        return False

    def _decode_body(self, body: bytes) -> str:
        """Decode body to string, handling various encodings"""
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return body.decode("latin-1")
            except Exception:
                return "[binary data]"

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary"""
        total_flows = len(self.flows)
        total_issues = sum(len(f.issues) for f in self.flows)

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        issue_types = {}

        for flow in self.flows:
            for issue in flow.issues:
                severity = issue.get("severity", "low")
                severity_counts[severity] += 1

                issue_type = issue.get("type", "unknown")
                issue_types[issue_type] = issue_types.get(issue_type, 0) + 1

        return {
            "total_flows": total_flows,
            "total_issues": total_issues,
            "severity_distribution": severity_counts,
            "issue_types": issue_types,
        }

    def export_findings(self) -> List[Dict[str, Any]]:
        """Export all findings as list"""
        findings = []
        for flow in self.flows:
            for issue in flow.issues:
                findings.append({
                    "url": flow.request.url,
                    "method": flow.request.method,
                    **issue,
                })
        return findings


class MitmproxyProxy:
    """Wrapper for mitmproxy proxy functionality"""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        upstream_proxy: Optional[str] = None,
    ):
        """
        Initialize proxy.

        Args:
            listen_host: Host to listen on
            listen_port: Port to listen on
            upstream_proxy: Upstream proxy URL if chaining
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_proxy = upstream_proxy
        self.analyzer = MitmproxyAnalyzer()

    def get_proxy_url(self) -> str:
        """Get proxy URL"""
        return f"http://{self.listen_host}:{self.listen_port}"

    def capture_and_analyze(self, callback: Optional[Callable] = None) -> MitmproxyAnalyzer:
        """
        Start capturing traffic and analyzing flows.

        Args:
            callback: Optional callback function for each flow

        Returns:
            Analyzer instance with captured flows
        """
        logger.info(f"Starting proxy on {self.get_proxy_url()}")
        # Note: Full mitmproxy integration would require running
        # the proxy in a separate process or async context
        logger.info("Analyzer ready for processing flows")
        return self.analyzer

    def add_flow_for_analysis(self, flow: CapturedFlow):
        """Add flow to analyzer"""
        self.analyzer.add_flow(flow)
        self.analyzer.analyze_flow(flow)
