"""
Frida Module - Runtime Instrumentation and Dynamic Analysis

Performs runtime testing using Frida instrumentation including:
- Root/Jailbreak detection bypass testing
- Debugger detection testing
- Method hooking for security validation
- Cryptographic operation monitoring
"""

from .frida_engine import FridaEngine

__all__ = ['FridaEngine']
