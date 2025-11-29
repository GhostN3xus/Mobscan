"""
Integration Module - External Tools Integration

This module provides integration with external security testing tools:
- MobSF: Mobile Security Framework for SAST
- ADB: Android Debug Bridge for device interaction
- mitmproxy: Man-in-the-middle proxy for traffic analysis
- Frida: Dynamic instrumentation framework

All integrations follow a common interface for easy extensibility.
"""

from .adb_integration import ADBIntegration
from .mobsf_integration import MobSFIntegration
from .mitmproxy_integration import MitmProxyIntegration

__all__ = [
    'ADBIntegration',
    'MobSFIntegration',
    'MitmProxyIntegration',
]

__version__ = '1.0.0'
__author__ = 'Mobscan Security Team'

# Integration status
AVAILABLE_INTEGRATIONS = {
    'adb': ADBIntegration,
    'mobsf': MobSFIntegration,
    'mitmproxy': MitmProxyIntegration,
}


def get_integration(name: str):
    """
    Get an integration class by name.

    Args:
        name: Name of the integration ('adb', 'mobsf', 'mitmproxy')

    Returns:
        Integration class

    Raises:
        KeyError: If integration name is not found

    Example:
        >>> adb = get_integration('adb')()
        >>> adb.connect('emulator-5554')
    """
    if name not in AVAILABLE_INTEGRATIONS:
        raise KeyError(f"Integration '{name}' not found. Available: {list(AVAILABLE_INTEGRATIONS.keys())}")

    return AVAILABLE_INTEGRATIONS[name]


def list_integrations():
    """
    List all available integrations.

    Returns:
        List of integration names

    Example:
        >>> integrations = list_integrations()
        >>> print(integrations)
        ['adb', 'mobsf', 'mitmproxy']
    """
    return list(AVAILABLE_INTEGRATIONS.keys())
