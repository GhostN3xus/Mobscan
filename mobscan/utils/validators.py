"""
Input validation utilities for Mobscan.

Validates application files, configurations, and package names.
"""

import re
from pathlib import Path
from typing import Dict, Any


def validate_app_path(app_path: str) -> bool:
    """
    Validate that an application file exists and is a valid format.

    Args:
        app_path: Path to APK or IPA file

    Returns:
        True if valid, False otherwise
    """
    if not app_path:
        return False

    path = Path(app_path)

    # Check if file exists
    if not path.exists():
        return False

    # Check file extension
    valid_extensions = ['.apk', '.ipa', '.aab']
    if path.suffix.lower() not in valid_extensions:
        return False

    # Check file size (should be at least 1MB)
    if path.stat().st_size < 1024 * 1024:
        return False

    return True


def is_valid_package_name(package_name: str) -> bool:
    """
    Validate a package name format.

    Args:
        package_name: Package name to validate

    Returns:
        True if valid, False otherwise
    """
    if not package_name:
        return False

    # Android package name format: com.example.app
    # iOS bundle ID format: com.example.app
    pattern = r'^[a-zA-Z][a-zA-Z0-9.]*[a-zA-Z0-9]$'

    if not re.match(pattern, package_name):
        return False

    # Check component length (each part should be < 64 chars)
    parts = package_name.split('.')
    if any(len(part) > 63 for part in parts):
        return False

    # Must have at least 2 parts (company.app)
    if len(parts) < 2:
        return False

    return True


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration dictionary.

    Args:
        config: Configuration dict to validate

    Returns:
        True if valid, False otherwise
    """
    if not isinstance(config, dict):
        return False

    # Check required fields
    required_fields = ['scan_intensity']

    for field in required_fields:
        if field not in config:
            return False

    # Validate scan_intensity values
    valid_intensities = ['quick', 'standard', 'full', 'comprehensive']
    if config.get('scan_intensity') not in valid_intensities:
        return False

    return True


def validate_platform(platform: str) -> bool:
    """
    Validate platform name.

    Args:
        platform: Platform name (android or ios)

    Returns:
        True if valid, False otherwise
    """
    return platform.lower() in ['android', 'ios']


def validate_severity(severity: str) -> bool:
    """
    Validate severity level.

    Args:
        severity: Severity level

    Returns:
        True if valid, False otherwise
    """
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    return severity.lower() in valid_severities
