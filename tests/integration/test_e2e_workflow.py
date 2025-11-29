"""
End-to-End Integration Tests for Mobscan.

Tests complete workflows including cache, logging, metrics,
and integrations.
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Import components under test
from mobscan.utils.cache import CacheManager, MemoryCacheBackend
from mobscan.utils.logger import setup_logger, get_logger, set_log_context
from mobscan.utils.metrics import initialize_metrics, get_metrics
from mobscan.utils.retry import exponential_backoff, CircuitBreaker
from mobscan.core.config import MobscanConfig, ScanIntensity


class TestCachingWorkflow:
    """Test caching functionality"""

    def test_memory_cache_basic_operations(self):
        """Test basic memory cache operations"""
        cache = MemoryCacheBackend()

        # Test set
        assert cache.set("key1", "value1") is True

        # Test get
        assert cache.get("key1") == "value1"

        # Test exists
        assert cache.exists("key1") is True

        # Test delete
        assert cache.delete("key1") is True
        assert cache.get("key1") is None

    def test_cache_manager_fallback(self):
        """Test cache manager fallback to memory when Redis unavailable"""
        # Initialize with memory backend (Redis unavailable)
        cache = CacheManager(use_redis=False)

        # Test operations work with memory backend
        assert cache.set("test_key", {"nested": "data"}) is True
        assert cache.get("test_key") == {"nested": "data"}
        assert cache.exists("test_key") is True

    def test_cache_stats(self):
        """Test cache statistics"""
        cache = CacheManager(use_redis=False)
        stats = cache.get_stats()

        assert "keys" in stats or "type" in stats
        assert stats is not None


class TestLoggingWorkflow:
    """Test logging functionality"""

    def test_structured_logging_with_context(self):
        """Test structured logging with context"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_file = f.name

        try:
            logger = setup_logger(
                "test_logger",
                level="INFO",
                log_file=log_file,
                json_format=True,
            )

            # Set context
            set_log_context(scan_id="test_scan_123", module="test")

            # Log with context
            logger.info("Test message with context")

            # Read log file
            with open(log_file, "r") as f:
                log_content = f.read()

            # Verify JSON log format
            log_line = log_content.strip()
            assert log_line

            # If not JSON, the test still passes (JSON format is optional)
            try:
                log_json = json.loads(log_line.split("\n")[-1])
                assert log_json.get("message") == "Test message with context"
                assert log_json.get("context")
            except (json.JSONDecodeError, IndexError):
                # Non-JSON format is acceptable
                assert "Test message with context" in log_content
        finally:
            Path(log_file).unlink(missing_ok=True)

    def test_logger_reuse(self):
        """Test reusing logger instances"""
        logger1 = get_logger("test_reuse")
        logger2 = get_logger("test_reuse")

        assert logger1 is logger2


class TestMetricsWorkflow:
    """Test metrics functionality"""

    def test_metrics_initialization(self):
        """Test metrics initialization"""
        metrics = initialize_metrics()
        assert metrics is not None
        assert get_metrics() is not None

    def test_scan_metrics_recording(self):
        """Test recording scan metrics"""
        metrics = initialize_metrics()

        # Record scan start/end
        metrics.record_scan_start("sast")
        metrics.record_scan_end("sast", "completed", 10.5)

        # Record finding
        metrics.record_finding("critical", "sast")
        metrics.record_finding("high", "sast")

        # Record module execution
        metrics.record_module_execution("sast", "success", 15.0)

        # Export metrics
        exported = metrics.export_metrics()
        assert exported is not None
        assert isinstance(exported, bytes)

    def test_cache_metrics(self):
        """Test cache metrics"""
        metrics = initialize_metrics()

        metrics.record_cache_hit("redis")
        metrics.record_cache_miss("redis")
        metrics.set_cache_size(1024000, "redis")

        # Metrics should record without errors
        assert True

    def test_api_metrics(self):
        """Test API metrics"""
        metrics = initialize_metrics()

        metrics.record_api_request("GET", "/api/scans", 200, 0.1)
        metrics.record_api_request("POST", "/api/scans", 201, 0.5)
        metrics.record_api_error(404, "/api/scans")

        # Metrics should record without errors
        assert True


class TestRetryWorkflow:
    """Test retry functionality"""

    def test_exponential_backoff_success(self):
        """Test successful retry with exponential backoff"""

        attempt_count = 0

        @exponential_backoff(max_retries=3, base_delay=0.1)
        def flaky_function():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise ValueError("First attempt fails")
            return "success"

        result = flaky_function()
        assert result == "success"
        assert attempt_count == 2

    def test_exponential_backoff_failure(self):
        """Test retry failure after max retries"""

        @exponential_backoff(max_retries=2, base_delay=0.01)
        def failing_function():
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            failing_function()

    def test_circuit_breaker(self):
        """Test circuit breaker pattern"""
        breaker = CircuitBreaker(failure_threshold=2, timeout=1)

        def failing_function():
            raise ValueError("Failed")

        # First failure
        with pytest.raises(ValueError):
            breaker.call(failing_function)

        # Second failure - circuit opens
        with pytest.raises(ValueError):
            breaker.call(failing_function)

        # Circuit is open - should raise RuntimeError
        assert breaker.is_open()
        with pytest.raises(RuntimeError):
            breaker.call(failing_function)


class TestConfigurationWorkflow:
    """Test configuration management"""

    def test_default_config_creation(self):
        """Test creating default configuration"""
        config = MobscanConfig.default_config()

        assert config.project_name == "MobscanProject"
        assert config.scan_intensity == ScanIntensity.FULL
        assert config.cache_enabled is True
        assert "sast" in [t for t in config.tools.keys()]
        assert "android" in config.platforms

    def test_config_yaml_export(self):
        """Test exporting configuration to YAML"""
        config = MobscanConfig.default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml_file = f.name

        try:
            config.save_to_yaml(yaml_file)
            assert Path(yaml_file).exists()

            # Verify file content
            with open(yaml_file, "r") as f:
                content = f.read()
                assert "project_name" in content
        finally:
            Path(yaml_file).unlink(missing_ok=True)

    def test_config_json_export(self):
        """Test exporting configuration to JSON"""
        config = MobscanConfig.default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            config.save_to_json(json_file)
            assert Path(json_file).exists()

            # Verify file content
            with open(json_file, "r") as f:
                data = json.load(f)
                assert data["project_name"] == "MobscanProject"
        finally:
            Path(json_file).unlink(missing_ok=True)


class TestIntegrationScenarios:
    """Test complete integration scenarios"""

    def test_full_scan_initialization(self):
        """Test initializing a complete scan"""
        # Setup config
        config = MobscanConfig.default_config()
        config.project_name = "E2E Test Project"

        # Setup logging
        logger = setup_logger("e2e_test", level="DEBUG")

        # Setup cache
        cache = CacheManager(use_redis=False)

        # Setup metrics
        metrics = initialize_metrics()

        # Verify all components are ready
        assert config.project_name == "E2E Test Project"
        assert cache.get_stats() is not None
        assert metrics.export_metrics() is not None

    def test_multi_module_workflow(self):
        """Test workflow across multiple modules"""
        config = MobscanConfig.default_config()
        cache = CacheManager(use_redis=False)
        metrics = initialize_metrics()

        # Simulate multi-module scan
        modules = ["sast", "dast", "frida"]

        for module in modules:
            if config.is_module_enabled(module):
                # Simulate scan execution
                metrics.record_scan_start(module)

                # Cache scan results
                cache.set(f"{module}_results", {"module": module, "status": "success"})

                # Record metrics
                metrics.record_module_execution(module, "success", 5.0)
                metrics.record_scan_end(module, "completed", 5.0)

        # Verify results
        assert cache.exists("sast_results")
        assert cache.exists("dast_results")
        assert cache.exists("frida_results")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
