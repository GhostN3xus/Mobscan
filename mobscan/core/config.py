"""
Configuration Management

Handles all configuration for the Mobscan framework including
paths, tool settings, and scanning parameters.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
import json
from enum import Enum


class ScanIntensity(Enum):
    """Scan intensity levels"""
    QUICK = "quick"           # Quick baseline scan
    STANDARD = "standard"      # Standard comprehensive scan
    FULL = "full"             # Full exhaustive scan
    COMPREHENSIVE = "comprehensive"  # Maximum coverage


@dataclass
class ToolConfig:
    """Configuration for individual security tools"""
    name: str
    enabled: bool = True
    docker_image: Optional[str] = None
    version: str = "latest"
    timeout: int = 3600  # seconds
    arguments: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)


@dataclass
class PlatformConfig:
    """Platform-specific configuration"""
    platform: str  # android or ios
    min_api_level: Optional[int] = None
    target_api_level: Optional[int] = None
    emulator_enabled: bool = False
    emulator_image: Optional[str] = None
    device_serial: Optional[str] = None
    proxy_url: Optional[str] = None
    burp_config: Optional[str] = None


@dataclass
class ReportConfig:
    """Report generation configuration"""
    formats: List[str] = field(default_factory=lambda: ["json", "pdf"])
    include_evidence: bool = True
    include_remediation: bool = True
    severity_threshold: str = "Low"  # Critical, High, Medium, Low, Info
    masvs_levels: List[str] = field(default_factory=lambda: ["L1", "L2"])
    executive_summary: bool = True
    technical_details: bool = True
    output_directory: str = "./reports"


@dataclass
class MobscanConfig:
    """
    Main configuration for Mobscan framework.
    Can be loaded from YAML, JSON, or environment variables.
    """

    # Basic Settings
    project_name: str = "MobscanProject"
    version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

    # Scan Settings
    scan_intensity: ScanIntensity = ScanIntensity.FULL
    parallel_workers: int = 4
    timeout_global: int = 7200  # seconds
    cache_enabled: bool = True
    cache_directory: str = "./.cache"

    # Tools Configuration
    tools: Dict[str, ToolConfig] = field(default_factory=dict)

    # Modules to Execute
    modules_enabled: List[str] = field(default_factory=lambda: [
        "sast",
        "dast",
        "frida",
        "integration"
    ])

    # Platforms
    platforms: Dict[str, PlatformConfig] = field(default_factory=dict)

    # Reporting
    report_config: ReportConfig = field(default_factory=ReportConfig)

    # Paths
    app_root: str = "./"
    output_base: str = "./output"
    temp_directory: str = "/tmp/mobscan"
    tools_directory: str = "./tools"

    # Advanced Options
    masvs_levels: List[str] = field(default_factory=lambda: ["L1", "L2"])
    custom_rules_path: Optional[str] = None
    proxy_settings: Dict[str, Any] = field(default_factory=dict)
    ci_cd_mode: bool = False
    webhook_url: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def load_from_yaml(self, filepath: str) -> 'MobscanConfig':
        """Load configuration from YAML file"""
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            return self._merge_config(data)

    def load_from_json(self, filepath: str) -> 'MobscanConfig':
        """Load configuration from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            return self._merge_config(data)

    def _merge_config(self, data: Dict) -> 'MobscanConfig':
        """Merge loaded configuration with current config"""
        # This is a simplified implementation
        # In production, implement recursive merging
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

    def save_to_yaml(self, filepath: str):
        """Save configuration to YAML file"""
        config_dict = self._to_dict()
        with open(filepath, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)

    def save_to_json(self, filepath: str):
        """Save configuration to JSON file"""
        config_dict = self._to_dict()
        with open(filepath, 'w') as f:
            json.dump(config_dict, f, indent=2)

    def _to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            "project_name": self.project_name,
            "version": self.version,
            "debug": self.debug,
            "log_level": self.log_level,
            "scan_intensity": self.scan_intensity.value,
            "parallel_workers": self.parallel_workers,
            "timeout_global": self.timeout_global,
            "cache_enabled": self.cache_enabled,
            "cache_directory": self.cache_directory,
            "modules_enabled": self.modules_enabled,
            "masvs_levels": self.masvs_levels,
            "output_base": self.output_base,
            "metadata": self.metadata,
        }

    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """Get configuration for a specific tool"""
        return self.tools.get(tool_name)

    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled"""
        tool = self.get_tool_config(tool_name)
        return tool.enabled if tool else False

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled"""
        return module_name in self.modules_enabled

    @classmethod
    def default_config(cls) -> 'MobscanConfig':
        """Create default configuration with all standard tools"""
        config = cls()

        # Add default tools
        config.tools = {
            "mobsf": ToolConfig(
                name="mobsf",
                enabled=True,
                docker_image="mobsf/mobsf:latest",
                version="3.8.1"
            ),
            "frida": ToolConfig(
                name="frida",
                enabled=True,
                version="16.0.0"
            ),
            "objection": ToolConfig(
                name="objection",
                enabled=True,
                version="1.11.0"
            ),
            "jadx": ToolConfig(
                name="jadx",
                enabled=True,
                version="1.4.0"
            ),
            "mitmproxy": ToolConfig(
                name="mitmproxy",
                enabled=True,
                docker_image="mitmproxy/mitmproxy:latest"
            ),
            "adb": ToolConfig(
                name="adb",
                enabled=True,
                version="latest"
            ),
        }

        # Add platform configurations
        config.platforms = {
            "android": PlatformConfig(
                platform="android",
                min_api_level=21,
                target_api_level=33,
                emulator_enabled=False
            ),
            "ios": PlatformConfig(
                platform="ios",
                emulator_enabled=False
            ),
        }

        return config
