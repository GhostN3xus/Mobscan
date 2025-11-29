"""
Configuration Validator - Validates Mobscan configurations

Ensures all configurations are valid before processing
"""

import logging
from typing import Dict, Any, List, Tuple
from jsonschema import validate, ValidationError

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates Mobscan configuration files"""

    # JSON Schema for configuration
    CONFIG_SCHEMA = {
        "type": "object",
        "required": ["version", "modules"],
        "properties": {
            "version": {"type": "string"},
            "modules": {
                "type": "object",
                "properties": {
                    "sast": {"type": "boolean"},
                    "dast": {"type": "boolean"},
                    "frida": {"type": "boolean"},
                    "sca": {"type": "boolean"}
                }
            },
            "scan": {
                "type": "object",
                "properties": {
                    "intensity": {
                        "type": "string",
                        "enum": ["quick", "standard", "full", "comprehensive"]
                    },
                    "timeout": {"type": "integer", "minimum": 60},
                    "parallel_workers": {"type": "integer", "minimum": 1, "maximum": 16}
                }
            },
            "reporting": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["json", "pdf", "docx", "markdown", "html"]}
                    },
                    "output_dir": {"type": "string"}
                }
            },
            "integrations": {
                "type": "object",
                "properties": {
                    "slack": {"type": "object"},
                    "jira": {"type": "object"},
                    "github": {"type": "object"}
                }
            }
        }
    }

    @staticmethod
    def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate configuration against schema.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        try:
            validate(instance=config, schema=ConfigValidator.CONFIG_SCHEMA)
            logger.info("Configuration validation passed")
            return True, []
        except ValidationError as e:
            error_msg = f"Configuration validation error: {e.message}"
            logger.error(error_msg)
            errors.append(error_msg)
            return False, errors

    @staticmethod
    def validate_paths(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate that all paths in configuration exist.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        from pathlib import Path

        errors = []

        # Check output directory
        if 'reporting' in config and 'output_dir' in config['reporting']:
            output_dir = Path(config['reporting']['output_dir'])
            if not output_dir.exists():
                error_msg = f"Output directory does not exist: {output_dir}"
                logger.error(error_msg)
                errors.append(error_msg)

        return len(errors) == 0, errors

    @staticmethod
    def validate_timeouts(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate timeout values.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        if 'scan' in config:
            scan_config = config['scan']
            if 'timeout' in scan_config:
                timeout = scan_config['timeout']
                if timeout < 60:
                    error_msg = "Timeout must be at least 60 seconds"
                    logger.error(error_msg)
                    errors.append(error_msg)
                if timeout > 86400:  # 24 hours
                    error_msg = "Timeout cannot exceed 24 hours"
                    logger.error(error_msg)
                    errors.append(error_msg)

        return len(errors) == 0, errors

    @staticmethod
    def validate_modules(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate module configuration.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        if 'modules' in config:
            modules = config['modules']
            valid_modules = ['sast', 'dast', 'frida', 'sca']

            for module in modules.keys():
                if module not in valid_modules:
                    error_msg = f"Unknown module: {module}"
                    logger.error(error_msg)
                    errors.append(error_msg)

        return len(errors) == 0, errors

    @staticmethod
    def validate_all(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Run all validation checks.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        all_errors = []

        checks = [
            ConfigValidator.validate_config,
            ConfigValidator.validate_paths,
            ConfigValidator.validate_timeouts,
            ConfigValidator.validate_modules,
        ]

        for check in checks:
            is_valid, errors = check(config)
            if not is_valid:
                all_errors.extend(errors)

        if all_errors:
            logger.error(f"Configuration validation failed with {len(all_errors)} error(s)")
            return False, all_errors
        else:
            logger.info("All configuration validations passed")
            return True, []


class InputValidator:
    """Validates user inputs"""

    @staticmethod
    def validate_app_path(app_path: str) -> Tuple[bool, str]:
        """
        Validate application path.

        Args:
            app_path: Path to APK or IPA file

        Returns:
            Tuple of (is_valid, error_message)
        """
        from pathlib import Path

        path = Path(app_path)

        if not path.exists():
            return False, f"File not found: {app_path}"

        if not path.is_file():
            return False, f"Not a file: {app_path}"

        suffix = path.suffix.lower()
        if suffix not in ['.apk', '.ipa']:
            return False, f"Invalid application format: {suffix}. Expected .apk or .ipa"

        # Check file size (should be > 1MB and < 1GB)
        file_size = path.stat().st_size
        if file_size < 1024 * 1024:
            return False, f"File too small: {file_size} bytes"

        if file_size > 1024 * 1024 * 1024:
            return False, f"File too large: {file_size} bytes"

        return True, ""

    @staticmethod
    def validate_intensity(intensity: str) -> Tuple[bool, str]:
        """
        Validate scan intensity.

        Args:
            intensity: Scan intensity level

        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_intensities = ['quick', 'standard', 'full', 'comprehensive']

        if intensity.lower() not in valid_intensities:
            return False, f"Invalid intensity: {intensity}. Must be one of: {', '.join(valid_intensities)}"

        return True, ""

    @staticmethod
    def validate_modules(modules: List[str]) -> Tuple[bool, str]:
        """
        Validate modules list.

        Args:
            modules: List of module names

        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_modules = ['sast', 'dast', 'frida', 'sca']

        for module in modules:
            if module.lower() not in valid_modules:
                return False, f"Unknown module: {module}. Valid modules: {', '.join(valid_modules)}"

        if len(modules) == 0:
            return False, "At least one module must be specified"

        return True, ""

    @staticmethod
    def validate_report_format(format: str) -> Tuple[bool, str]:
        """
        Validate report format.

        Args:
            format: Report format

        Returns:
            Tuple of (is_valid, error_message)
        """
        valid_formats = ['json', 'pdf', 'docx', 'markdown', 'html']

        if format.lower() not in valid_formats:
            return False, f"Invalid format: {format}. Valid formats: {', '.join(valid_formats)}"

        return True, ""

    @staticmethod
    def validate_proxy(proxy: str) -> Tuple[bool, str]:
        """
        Validate proxy configuration.

        Args:
            proxy: Proxy address (ip:port)

        Returns:
            Tuple of (is_valid, error_message)
        """
        import re

        pattern = r'^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$'

        if not re.match(pattern, proxy):
            return False, f"Invalid proxy format: {proxy}. Expected: 127.0.0.1:8080"

        # Check IP octets
        ip, port = proxy.split(':')
        octets = ip.split('.')
        for octet in octets:
            num = int(octet)
            if num < 0 or num > 255:
                return False, f"Invalid IP address: {ip}"

        # Check port
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False, f"Invalid port: {port}"

        return True, ""
