"""
Prometheus Metrics for Mobscan.

Provides comprehensive metrics collection and monitoring capabilities
for scans, analysis, and system performance.
"""

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Summary,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
import logging
from typing import Dict, Any, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class MobscanMetrics:
    """Prometheus metrics for Mobscan framework"""

    def __init__(self):
        """Initialize Mobscan metrics"""

        # Scan Metrics
        self.scans_total = Counter(
            "mobscan_scans_total",
            "Total number of scans performed",
            ["status", "module"],
        )

        self.scan_duration = Histogram(
            "mobscan_scan_duration_seconds",
            "Scan execution duration in seconds",
            ["module"],
            buckets=(1, 5, 10, 30, 60, 300, 600, 1800, 3600),
        )

        self.scan_findings = Counter(
            "mobscan_findings_total",
            "Total findings discovered",
            ["severity", "module"],
        )

        # Analysis Metrics
        self.analysis_duration = Summary(
            "mobscan_analysis_duration_seconds",
            "Analysis execution time",
            ["module"],
        )

        self.modules_executed = Counter(
            "mobscan_modules_executed_total",
            "Total module executions",
            ["module", "status"],
        )

        # Module-specific Metrics
        self.sast_checks = Counter(
            "mobscan_sast_checks_total",
            "Total SAST checks performed",
            ["rule_type"],
        )

        self.dast_requests = Counter(
            "mobscan_dast_requests_total",
            "Total DAST requests made",
            ["method", "status"],
        )

        self.frida_hooks = Counter(
            "mobscan_frida_hooks_total",
            "Total Frida hooks executed",
            ["hook_type"],
        )

        # Cache Metrics
        self.cache_hits = Counter(
            "mobscan_cache_hits_total",
            "Total cache hits",
            ["cache_type"],
        )

        self.cache_misses = Counter(
            "mobscan_cache_misses_total",
            "Total cache misses",
            ["cache_type"],
        )

        self.cache_size = Gauge(
            "mobscan_cache_size_bytes",
            "Current cache size in bytes",
            ["cache_type"],
        )

        # Error Metrics
        self.errors_total = Counter(
            "mobscan_errors_total",
            "Total errors encountered",
            ["error_type", "module"],
        )

        self.api_errors = Counter(
            "mobscan_api_errors_total",
            "Total API errors",
            ["status_code", "endpoint"],
        )

        # API Metrics
        self.api_requests = Counter(
            "mobscan_api_requests_total",
            "Total API requests",
            ["method", "endpoint", "status"],
        )

        self.api_request_duration = Histogram(
            "mobscan_api_request_duration_seconds",
            "API request duration",
            ["method", "endpoint"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 10),
        )

        # System Metrics
        self.active_scans = Gauge(
            "mobscan_active_scans",
            "Number of active scans",
        )

        self.queue_size = Gauge(
            "mobscan_queue_size",
            "Number of queued jobs",
        )

        self.worker_threads = Gauge(
            "mobscan_worker_threads",
            "Number of active worker threads",
        )

        # Report Metrics
        self.reports_generated = Counter(
            "mobscan_reports_generated_total",
            "Total reports generated",
            ["format"],
        )

        self.report_size = Histogram(
            "mobscan_report_size_bytes",
            "Report size in bytes",
            ["format"],
            buckets=(1024, 10240, 102400, 1024000, 10240000),
        )

        logger.info("Mobscan metrics initialized")

    def record_scan_start(self, module: str):
        """Record scan start"""
        self.active_scans.inc()
        logger.debug(f"Scan started for module: {module}")

    def record_scan_end(self, module: str, status: str, duration: float):
        """Record scan end"""
        self.active_scans.dec()
        self.scans_total.labels(status=status, module=module).inc()
        self.scan_duration.labels(module=module).observe(duration)
        logger.debug(f"Scan ended for module: {module}, status: {status}, duration: {duration}s")

    def record_finding(self, severity: str, module: str):
        """Record a finding"""
        self.scan_findings.labels(severity=severity, module=module).inc()
        logger.debug(f"Finding recorded: {severity} in {module}")

    def record_module_execution(self, module: str, status: str, duration: float):
        """Record module execution"""
        self.modules_executed.labels(module=module, status=status).inc()
        self.analysis_duration.labels(module=module).observe(duration)
        logger.debug(f"Module {module} executed with status {status}")

    def record_sast_check(self, rule_type: str):
        """Record SAST check"""
        self.sast_checks.labels(rule_type=rule_type).inc()

    def record_dast_request(self, method: str, status_code: int):
        """Record DAST request"""
        self.dast_requests.labels(method=method, status=status_code).inc()

    def record_frida_hook(self, hook_type: str):
        """Record Frida hook execution"""
        self.frida_hooks.labels(hook_type=hook_type).inc()

    def record_cache_hit(self, cache_type: str = "redis"):
        """Record cache hit"""
        self.cache_hits.labels(cache_type=cache_type).inc()

    def record_cache_miss(self, cache_type: str = "redis"):
        """Record cache miss"""
        self.cache_misses.labels(cache_type=cache_type).inc()

    def set_cache_size(self, size_bytes: int, cache_type: str = "redis"):
        """Set cache size"""
        self.cache_size.labels(cache_type=cache_type).set(size_bytes)

    def record_error(self, error_type: str, module: str):
        """Record an error"""
        self.errors_total.labels(error_type=error_type, module=module).inc()
        logger.warning(f"Error recorded: {error_type} in {module}")

    def record_api_error(self, status_code: int, endpoint: str):
        """Record API error"""
        self.api_errors.labels(status_code=status_code, endpoint=endpoint).inc()

    def record_api_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration: float,
    ):
        """Record API request"""
        self.api_requests.labels(method=method, endpoint=endpoint, status=status_code).inc()
        self.api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)

    def set_queue_size(self, size: int):
        """Set queue size"""
        self.queue_size.set(size)

    def set_worker_threads(self, count: int):
        """Set worker thread count"""
        self.worker_threads.set(count)

    def record_report_generated(self, format: str, size_bytes: int):
        """Record report generation"""
        self.reports_generated.labels(format=format).inc()
        self.report_size.labels(format=format).observe(size_bytes)

    def export_metrics(self) -> bytes:
        """Export metrics in Prometheus format"""
        return generate_latest()

    def export_metrics_text(self) -> str:
        """Export metrics as text"""
        return self.export_metrics().decode("utf-8")


# Global metrics instance
_metrics: Optional[MobscanMetrics] = None


def initialize_metrics() -> MobscanMetrics:
    """Initialize global metrics"""
    global _metrics
    _metrics = MobscanMetrics()
    return _metrics


def get_metrics() -> Optional[MobscanMetrics]:
    """Get global metrics instance"""
    global _metrics
    if _metrics is None:
        _metrics = MobscanMetrics()
    return _metrics


def export_metrics() -> bytes:
    """Export all metrics in Prometheus format"""
    metrics = get_metrics()
    if metrics:
        return metrics.export_metrics()
    return b""
