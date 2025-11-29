"""
Proxy Handler - HTTP/HTTPS traffic interception and analysis

Integrates with mitmproxy or built-in proxy to intercept and analyze network traffic.
"""

import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import re

logger = logging.getLogger(__name__)


@dataclass
class RequestInfo:
    """Information about an HTTP request"""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ResponseInfo:
    """Information about an HTTP response"""
    status_code: int
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    content_type: str = ""

    def to_dict(self) -> Dict:
        return {
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body,
            'content_type': self.content_type,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class InterceptedFlow:
    """Complete HTTP request-response flow"""
    request: RequestInfo
    response: Optional[ResponseInfo] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'request': self.request.to_dict(),
            'response': self.response.to_dict() if self.response else None,
            'findings': self.findings
        }


class ProxyAnalyzer:
    """Analyzes intercepted traffic for security issues"""

    # Sensitive patterns to detect in responses
    SENSITIVE_PATTERNS = {
        'api_key': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        'token': r'(?i)(auth|token|bearer)\s+([a-zA-Z0-9_\-\.]+)',
        'password': r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
        'private_key': r'-----BEGIN PRIVATE KEY-----',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    }

    def __init__(self):
        self.logger = logger
        self.captured_flows: List[InterceptedFlow] = []

    def analyze_flow(self, flow: InterceptedFlow) -> List[Dict[str, Any]]:
        """Analyze a captured HTTP flow for security issues"""
        findings = []

        # Analyze response for sensitive data leakage
        if flow.response:
            findings.extend(self._check_sensitive_data(flow))
            findings.extend(self._check_security_headers(flow))
            findings.extend(self._check_caching_headers(flow))

        flow.findings = findings
        return findings

    def _check_sensitive_data(self, flow: InterceptedFlow) -> List[Dict[str, Any]]:
        """Check for sensitive data in response"""
        findings = []

        if not flow.response or not flow.response.body:
            return findings

        response_text = flow.response.body
        for data_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.finditer(pattern, response_text)
            for match in matches:
                findings.append({
                    'type': 'sensitive_data_leakage',
                    'data_type': data_type,
                    'url': flow.request.url,
                    'location': 'response_body',
                    'severity': 'high' if data_type in ['api_key', 'private_key', 'token'] else 'medium',
                    'description': f'Found {data_type} in response body'
                })

        # Check headers
        for header_name, header_value in (flow.response.headers or {}).items():
            for data_type, pattern in self.SENSITIVE_PATTERNS.items():
                if re.search(pattern, header_value):
                    findings.append({
                        'type': 'sensitive_data_leakage',
                        'data_type': data_type,
                        'url': flow.request.url,
                        'location': f'header:{header_name}',
                        'severity': 'critical' if data_type in ['api_key', 'token'] else 'high',
                        'description': f'Found {data_type} in {header_name} header'
                    })

        return findings

    def _check_security_headers(self, flow: InterceptedFlow) -> List[Dict[str, Any]]:
        """Check for missing or weak security headers"""
        findings = []

        if not flow.response:
            return findings

        required_headers = {
            'Strict-Transport-Security': 'HSTS header missing - enables HTTPS enforcement',
            'X-Content-Type-Options': 'X-Content-Type-Options missing - enables MIME sniffing attacks',
            'X-Frame-Options': 'X-Frame-Options missing - clickjacking vulnerability',
            'X-XSS-Protection': 'X-XSS-Protection missing - weak XSS protection',
            'Content-Security-Policy': 'CSP missing - weak XSS/injection protection',
        }

        headers = flow.response.headers or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, description in required_headers.items():
            header_lower = header.lower()
            if header_lower not in headers_lower:
                findings.append({
                    'type': 'missing_security_header',
                    'header': header,
                    'url': flow.request.url,
                    'severity': 'medium',
                    'description': description
                })

        return findings

    def _check_caching_headers(self, flow: InterceptedFlow) -> List[Dict[str, Any]]:
        """Check for insecure caching of sensitive data"""
        findings = []

        if not flow.response:
            return findings

        headers = flow.response.headers or {}
        cache_control = headers.get('Cache-Control', '').lower()

        # Check if sensitive endpoints are cached
        sensitive_endpoints = ['/login', '/auth', '/api/token', '/api/password', '/api/key']

        if any(endpoint in flow.request.url for endpoint in sensitive_endpoints):
            if 'no-cache' not in cache_control and 'no-store' not in cache_control:
                findings.append({
                    'type': 'insecure_caching',
                    'url': flow.request.url,
                    'severity': 'high',
                    'description': 'Sensitive endpoint response is cacheable'
                })

        return findings

    def capture_flow(self, flow: InterceptedFlow):
        """Capture and store a flow"""
        self.captured_flows.append(flow)
        self.analyze_flow(flow)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of captured flows"""
        total_flows = len(self.captured_flows)
        total_findings = sum(len(f.findings) for f in self.captured_flows)

        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for flow in self.captured_flows:
            for finding in flow.findings:
                severity = finding.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            'total_flows': total_flows,
            'total_findings': total_findings,
            'severity_distribution': severity_counts,
            'endpoints': len(set(f.request.url for f in self.captured_flows))
        }

    def get_flows_by_severity(self, severity: str) -> List[InterceptedFlow]:
        """Get all flows with findings of a specific severity"""
        return [
            f for f in self.captured_flows
            if any(finding.get('severity') == severity for finding in f.findings)
        ]

    def clear_flows(self):
        """Clear captured flows"""
        self.captured_flows.clear()


class MitmProxyIntegration:
    """Integration with mitmproxy for traffic interception"""

    def __init__(self, port: int = 8080, cert_file: Optional[str] = None):
        self.port = port
        self.cert_file = cert_file
        self.analyzer = ProxyAnalyzer()
        self.is_running = False

    def start(self) -> bool:
        """Start the proxy server"""
        try:
            # In production, would start actual mitmproxy instance
            # For now, this is a stub
            logger.info(f"Starting mitmproxy on port {self.port}")
            self.is_running = True
            return True
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            return False

    def stop(self):
        """Stop the proxy server"""
        self.is_running = False
        logger.info("Proxy stopped")

    def get_captured_flows(self) -> List[InterceptedFlow]:
        """Get all captured flows"""
        return self.analyzer.captured_flows

    def export_flows_har(self, filepath: str):
        """Export captured flows in HAR format"""
        # HAR format export
        har = {
            'log': {
                'version': '1.2',
                'creator': {'name': 'Mobscan', 'version': '1.0'},
                'entries': []
            }
        }

        for flow in self.analyzer.captured_flows:
            entry = {
                'startedDateTime': flow.request.timestamp.isoformat(),
                'request': {
                    'method': flow.request.method,
                    'url': flow.request.url,
                    'headers': [
                        {'name': k, 'value': v}
                        for k, v in (flow.request.headers or {}).items()
                    ]
                },
                'response': {
                    'status': flow.response.status_code if flow.response else 0,
                    'headers': [
                        {'name': k, 'value': v}
                        for k, v in (flow.response.headers or {}).items()
                    ] if flow.response else []
                } if flow.response else None,
                'timings': {}
            }
            har['log']['entries'].append(entry)

        import json
        with open(filepath, 'w') as f:
            json.dump(har, f, indent=2)

        logger.info(f"HAR file exported to {filepath}")
