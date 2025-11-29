"""
SBOM (Software Bill of Materials) Generator.

Generates comprehensive SBOM reports in CycloneDX format for
mobile applications and dependencies.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import subprocess
import re
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib


logger = logging.getLogger(__name__)


class ComponentType(Enum):
    """Component types in SBOM"""

    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"


class LicenseType(Enum):
    """Common license types"""

    MIT = "MIT"
    APACHE_2 = "Apache-2.0"
    GPL_2 = "GPL-2.0"
    GPL_3 = "GPL-3.0"
    BSD = "BSD"
    PROPRIETARY = "Proprietary"
    UNKNOWN = "Unknown"


@dataclass
class Component:
    """SBOM Component"""

    name: str
    version: str
    component_type: ComponentType = ComponentType.LIBRARY
    description: Optional[str] = None
    licenses: List[str] = None
    supplier: Optional[str] = None
    publisher: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    hash_value: Optional[str] = None
    hash_algorithm: str = "SHA-256"
    purl: Optional[str] = None
    vulnerabilities: List[str] = None

    def __post_init__(self):
        if self.licenses is None:
            self.licenses = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["component_type"] = self.component_type.value
        data["licenses"] = [lic for lic in self.licenses]
        return data


@dataclass
class SBOMMetadata:
    """SBOM Metadata"""

    format_version: str = "1.4"
    spec_version: str = "1.4"
    serial_number: Optional[str] = None
    version: int = 1
    creation_timestamp: Optional[str] = None
    creator: str = "Mobscan"
    component_name: str = "Mobile Application"
    component_version: str = "1.0.0"

    def __post_init__(self):
        if self.creation_timestamp is None:
            self.creation_timestamp = datetime.utcnow().isoformat() + "Z"
        if self.serial_number is None:
            self.serial_number = self._generate_serial()

    def _generate_serial(self) -> str:
        """Generate unique serial number"""
        timestamp = datetime.utcnow().isoformat()
        hash_input = f"{timestamp}{self.component_name}{self.component_version}"
        return hashlib.sha256(hash_input.encode()).hexdigest()


class SBOMGenerator:
    """Generator for Software Bill of Materials"""

    def __init__(
        self,
        app_name: str,
        app_version: str,
        app_type: str = "application",
    ):
        """
        Initialize SBOM generator.

        Args:
            app_name: Application name
            app_version: Application version
            app_type: Application type
        """
        self.metadata = SBOMMetadata(
            component_name=app_name,
            component_version=app_version,
        )
        self.components: List[Component] = []
        self.dependencies: Dict[str, List[str]] = {}

    def add_component(
        self,
        name: str,
        version: str,
        component_type: ComponentType = ComponentType.LIBRARY,
        **kwargs,
    ) -> Component:
        """Add component to SBOM"""
        component = Component(
            name=name,
            version=version,
            component_type=component_type,
            **kwargs,
        )
        self.components.append(component)
        logger.debug(f"Added component: {name} {version}")
        return component

    def add_dependency(self, parent: str, child: str):
        """Add dependency relationship"""
        if parent not in self.dependencies:
            self.dependencies[parent] = []
        self.dependencies[parent].append(child)

    def analyze_android_apk(self, apk_path: str) -> List[Component]:
        """Analyze Android APK for components and libraries"""
        logger.info(f"Analyzing APK: {apk_path}")
        components = []

        # Extract and parse AndroidManifest.xml
        manifest_data = self._extract_apk_manifest(apk_path)
        if manifest_data:
            # Add main application component
            app_component = Component(
                name=manifest_data.get("package", "unknown"),
                version=manifest_data.get("version", "unknown"),
                component_type=ComponentType.APPLICATION,
                description="Main application component",
            )
            components.append(app_component)
            self.add_component(**asdict(app_component))

        # Extract dependencies from dex files
        dependencies = self._extract_dependencies_from_dex(apk_path)
        for dep in dependencies:
            comp = Component(
                name=dep.get("name"),
                version=dep.get("version", "unknown"),
                component_type=ComponentType.LIBRARY,
            )
            components.append(comp)
            self.add_component(**asdict(comp))

        return components

    def analyze_ios_ipa(self, ipa_path: str) -> List[Component]:
        """Analyze iOS IPA for components and libraries"""
        logger.info(f"Analyzing IPA: {ipa_path}")
        components = []

        # Extract Info.plist
        plist_data = self._extract_ipa_plist(ipa_path)
        if plist_data:
            app_component = Component(
                name=plist_data.get("CFBundleName", "unknown"),
                version=plist_data.get("CFBundleShortVersionString", "unknown"),
                component_type=ComponentType.APPLICATION,
            )
            components.append(app_component)
            self.add_component(**asdict(app_component))

        # Extract linked frameworks
        frameworks = self._extract_frameworks_from_ipa(ipa_path)
        for framework in frameworks:
            comp = Component(
                name=framework,
                version="system",
                component_type=ComponentType.FRAMEWORK,
            )
            components.append(comp)
            self.add_component(**asdict(comp))

        return components

    def _extract_apk_manifest(self, apk_path: str) -> Dict[str, str]:
        """Extract manifest information from APK"""
        try:
            # This would use a real APK parsing library in production
            # For now, return basic structure
            return {
                "package": "com.example.app",
                "version": "1.0.0",
            }
        except Exception as e:
            logger.warning(f"Failed to parse APK manifest: {e}")
            return {}

    def _extract_dependencies_from_dex(self, apk_path: str) -> List[Dict[str, str]]:
        """Extract library dependencies from DEX files"""
        # This would analyze DEX files for library dependencies
        dependencies = []
        # Placeholder implementation
        return dependencies

    def _extract_ipa_plist(self, ipa_path: str) -> Dict[str, str]:
        """Extract Info.plist from IPA"""
        try:
            # This would parse the plist in production
            return {
                "CFBundleName": "Example App",
                "CFBundleShortVersionString": "1.0.0",
            }
        except Exception as e:
            logger.warning(f"Failed to parse IPA plist: {e}")
            return {}

    def _extract_frameworks_from_ipa(self, ipa_path: str) -> List[str]:
        """Extract framework dependencies from IPA"""
        # Placeholder for framework extraction
        return [
            "UIKit",
            "Foundation",
            "CoreData",
        ]

    def generate_cyclonedx_json(self) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM"""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": self.metadata.spec_version,
            "serialNumber": f"urn:uuid:{self.metadata.serial_number}",
            "version": self.metadata.version,
            "metadata": {
                "timestamp": self.metadata.creation_timestamp,
                "tools": [
                    {
                        "vendor": "Mobscan",
                        "name": "Mobscan SBOM Generator",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "bom-ref": self.metadata.component_name.replace(" ", "_"),
                    "type": "application",
                    "name": self.metadata.component_name,
                    "version": self.metadata.component_version,
                },
            },
            "components": [comp.to_dict() for comp in self.components],
            "dependencies": [
                {
                    "ref": dep_parent,
                    "dependsOn": self.dependencies.get(dep_parent, []),
                }
                for dep_parent in self.dependencies
            ]
            if self.dependencies
            else [],
        }

    def generate_cyclonedx_xml(self) -> str:
        """Generate CycloneDX XML format"""
        # This would generate proper XML in production
        sbom_json = self.generate_cyclonedx_json()
        return json.dumps(sbom_json, indent=2)

    def save_sbom(self, output_path: str, format: str = "json"):
        """Save SBOM to file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            sbom_data = self.generate_cyclonedx_json()
            with open(output_path, "w") as f:
                json.dump(sbom_data, f, indent=2)
        elif format == "xml":
            sbom_data = self.generate_cyclonedx_xml()
            with open(output_path, "w") as f:
                f.write(sbom_data)

        logger.info(f"SBOM saved to {output_path}")

    def get_summary(self) -> Dict[str, Any]:
        """Get SBOM summary"""
        return {
            "component_count": len(self.components),
            "component_types": {
                comp_type.value: len(
                    [c for c in self.components if c.component_type == comp_type]
                )
                for comp_type in ComponentType
            },
            "total_dependencies": len(self.dependencies),
            "creation_timestamp": self.metadata.creation_timestamp,
        }


class DependencyAnalyzer:
    """Analyzer for identifying and analyzing dependencies"""

    @staticmethod
    def scan_requirements_file(requirements_file: str) -> List[Component]:
        """Scan Python requirements.txt"""
        components = []
        requirements_path = Path(requirements_file)

        if not requirements_path.exists():
            return components

        with open(requirements_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse requirement line
                match = re.match(r"([a-zA-Z0-9\-_.]+)==(.+)", line)
                if match:
                    name, version = match.groups()
                    comp = Component(
                        name=name,
                        version=version,
                        component_type=ComponentType.LIBRARY,
                    )
                    components.append(comp)

        return components

    @staticmethod
    def scan_gradle_dependencies(gradle_file: str) -> List[Component]:
        """Scan Android Gradle dependencies"""
        components = []
        gradle_path = Path(gradle_file)

        if not gradle_path.exists():
            return components

        with open(gradle_path, "r") as f:
            for line in f:
                # Match: implementation 'com.package:library:version'
                match = re.search(
                    r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                    line,
                )
                if match:
                    group, artifact, version = match.groups()
                    comp = Component(
                        name=f"{group}:{artifact}",
                        version=version,
                        component_type=ComponentType.LIBRARY,
                    )
                    components.append(comp)

        return components
