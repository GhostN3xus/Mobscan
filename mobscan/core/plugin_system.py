"""
Plugin System - Professional plugin architecture for Mobscan

Allows third-party developers to extend Mobscan with custom modules and analyzers.
"""

import logging
import importlib
import inspect
from typing import Dict, List, Type, Optional, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class PluginCapability:
    """Describes a capability provided by a plugin"""
    name: str
    description: str
    version: str = "1.0.0"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginMetadata:
    """Metadata for a plugin"""
    id: str
    name: str
    version: str
    author: str
    description: str
    capabilities: List[PluginCapability] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    priority: int = 100  # Higher = executes first


class PluginInterface(ABC):
    """
    Base interface for all plugins.

    All plugins must inherit from this class and implement required methods.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the plugin with configuration.

        Args:
            config: Plugin configuration

        Returns:
            True if initialization successful
        """
        pass

    @abstractmethod
    def shutdown(self):
        """Cleanup when plugin is unloaded"""
        pass

    def on_event(self, event_type: str, event_data: Dict[str, Any]) -> Any:
        """
        Handle events from the framework.

        Default implementation does nothing.
        Override to handle specific events.
        """
        return None


class AnalyzerPlugin(PluginInterface):
    """Base class for analyzer plugins (SAST, DAST, etc)"""

    @abstractmethod
    def analyze(self, app_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run analysis on an app.

        Args:
            app_path: Path to the app
            config: Analysis configuration

        Returns:
            List of findings
        """
        pass


class ReporterPlugin(PluginInterface):
    """Base class for reporter plugins"""

    @abstractmethod
    def generate_report(self, scan_result: Any, config: Dict[str, Any]) -> str:
        """
        Generate a report.

        Args:
            scan_result: The scan result object
            config: Report configuration

        Returns:
            Generated report (file path or content)
        """
        pass


class IntegrationPlugin(PluginInterface):
    """Base class for integration plugins (JIRA, Slack, etc)"""

    @abstractmethod
    def send(self, finding_data: Dict[str, Any]) -> bool:
        """
        Send data to the external system.

        Args:
            finding_data: Finding or scan data to send

        Returns:
            True if successful
        """
        pass


class PluginManager:
    """
    Manages plugin loading, registration, and lifecycle.
    """

    def __init__(self):
        self.plugins: Dict[str, PluginInterface] = {}
        self.metadata: Dict[str, PluginMetadata] = {}
        self.plugin_paths: List[Path] = []
        self.logger = logger

    def register_plugin_path(self, path: Path):
        """Register a path to search for plugins"""
        if path.exists() and path.is_dir():
            self.plugin_paths.append(path)
            self.logger.info(f"Registered plugin path: {path}")
        else:
            self.logger.warning(f"Invalid plugin path: {path}")

    def load_plugin(self, plugin_module_path: str) -> bool:
        """
        Load a plugin from a module path.

        Args:
            plugin_module_path: e.g., "mobscan.plugins.custom_analyzer"

        Returns:
            True if loaded successfully
        """
        try:
            # Import the module
            module = importlib.import_module(plugin_module_path)

            # Find all plugin classes in module
            plugin_classes = [
                obj for name, obj in inspect.getmembers(module)
                if (inspect.isclass(obj) and
                    issubclass(obj, PluginInterface) and
                    obj != PluginInterface and
                    obj not in [AnalyzerPlugin, ReporterPlugin, IntegrationPlugin])
            ]

            if not plugin_classes:
                self.logger.warning(f"No plugins found in {plugin_module_path}")
                return False

            # Register each plugin
            for plugin_class in plugin_classes:
                try:
                    instance = plugin_class()
                    metadata = instance.metadata

                    # Check dependencies
                    for dep in metadata.dependencies:
                        if dep not in self.plugins:
                            self.logger.warning(
                                f"Plugin {metadata.id} requires {dep} which is not loaded"
                            )
                            return False

                    # Initialize plugin
                    if instance.initialize({}):
                        self.plugins[metadata.id] = instance
                        self.metadata[metadata.id] = metadata
                        self.logger.info(
                            f"Loaded plugin: {metadata.name} v{metadata.version}"
                        )
                    else:
                        self.logger.error(
                            f"Failed to initialize plugin: {metadata.id}"
                        )
                        return False

                except Exception as e:
                    self.logger.error(f"Error loading plugin class {plugin_class}: {e}")
                    return False

            return True

        except ImportError as e:
            self.logger.error(f"Failed to import {plugin_module_path}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error loading plugin from {plugin_module_path}: {e}")
            return False

    def load_plugins_from_directory(self, directory: Path) -> int:
        """
        Load all plugins from a directory.

        Args:
            directory: Directory containing plugin modules

        Returns:
            Number of plugins loaded
        """
        if not directory.exists():
            self.logger.warning(f"Plugin directory not found: {directory}")
            return 0

        loaded = 0
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            module_name = py_file.stem
            # Construct module path based on directory
            # This is a simplified version - adjust based on your package structure

            try:
                module = importlib.import_module(f"mobscan.plugins.{module_name}")
                # Find and register plugins
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and
                        issubclass(obj, PluginInterface) and
                        obj != PluginInterface):
                        try:
                            instance = obj()
                            metadata = instance.metadata
                            if instance.initialize({}):
                                self.plugins[metadata.id] = instance
                                self.metadata[metadata.id] = metadata
                                loaded += 1
                                self.logger.info(
                                    f"Loaded plugin: {metadata.name} "
                                    f"({module_name})"
                                )
                        except Exception as e:
                            self.logger.error(f"Error loading {name}: {e}")

            except ImportError as e:
                self.logger.warning(f"Could not import {module_name}: {e}")

        return loaded

    def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a plugin"""
        if plugin_id in self.plugins:
            try:
                self.plugins[plugin_id].shutdown()
                del self.plugins[plugin_id]
                del self.metadata[plugin_id]
                self.logger.info(f"Unloaded plugin: {plugin_id}")
                return True
            except Exception as e:
                self.logger.error(f"Error unloading plugin {plugin_id}: {e}")
                return False
        return False

    def get_plugin(self, plugin_id: str) -> Optional[PluginInterface]:
        """Get a loaded plugin by ID"""
        return self.plugins.get(plugin_id)

    def get_plugins_by_type(self, plugin_type: Type) -> List[PluginInterface]:
        """Get all plugins of a specific type"""
        return [
            p for p in self.plugins.values()
            if isinstance(p, plugin_type)
        ]

    def get_analyzer_plugins(self) -> List[AnalyzerPlugin]:
        """Get all analyzer plugins"""
        return self.get_plugins_by_type(AnalyzerPlugin)

    def get_reporter_plugins(self) -> List[ReporterPlugin]:
        """Get all reporter plugins"""
        return self.get_plugins_by_type(ReporterPlugin)

    def get_integration_plugins(self) -> List[IntegrationPlugin]:
        """Get all integration plugins"""
        return self.get_plugins_by_type(IntegrationPlugin)

    def list_plugins(self) -> List[PluginMetadata]:
        """List all loaded plugins with metadata"""
        return list(self.metadata.values())

    def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin"""
        if plugin_id in self.metadata:
            self.metadata[plugin_id].enabled = True
            return True
        return False

    def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin"""
        if plugin_id in self.metadata:
            self.metadata[plugin_id].enabled = False
            return True
        return False

    def is_plugin_enabled(self, plugin_id: str) -> bool:
        """Check if a plugin is enabled"""
        if plugin_id in self.metadata:
            return self.metadata[plugin_id].enabled
        return False

    def get_plugin_metadata(self, plugin_id: str) -> Optional[PluginMetadata]:
        """Get metadata for a plugin"""
        return self.metadata.get(plugin_id)

    def broadcast_event(self, event_type: str, event_data: Dict[str, Any]):
        """Broadcast an event to all plugins"""
        for plugin in self.plugins.values():
            if self.is_plugin_enabled(plugin.metadata.id):
                try:
                    plugin.on_event(event_type, event_data)
                except Exception as e:
                    self.logger.error(
                        f"Error in plugin {plugin.metadata.id} "
                        f"event handler: {e}"
                    )

    def __repr__(self) -> str:
        return f"<PluginManager with {len(self.plugins)} plugins loaded>"


# Global instance
_global_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance"""
    global _global_plugin_manager
    if _global_plugin_manager is None:
        _global_plugin_manager = PluginManager()
    return _global_plugin_manager


def set_plugin_manager(manager: PluginManager):
    """Set a custom plugin manager"""
    global _global_plugin_manager
    _global_plugin_manager = manager
