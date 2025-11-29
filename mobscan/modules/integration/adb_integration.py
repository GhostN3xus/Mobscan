"""
ADB (Android Debug Bridge) Integration Module.

Provides interface for communicating with Android devices and emulators
for dynamic analysis and runtime inspection.
"""

import subprocess
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from mobscan.utils.retry import exponential_backoff, retry_with_backoff


logger = logging.getLogger(__name__)


@dataclass
class AndroidDevice:
    """Android device information"""

    serial: str
    status: str  # device, offline, no permissions, etc
    product: Optional[str] = None
    model: Optional[str] = None
    device_name: Optional[str] = None


@dataclass
class PackageInfo:
    """APK package information"""

    package_name: str
    version: str
    version_code: str
    install_location: str
    flags: str


class ADBClient:
    """Client for Android Debug Bridge"""

    def __init__(self, adb_path: str = "adb"):
        """
        Initialize ADB client.

        Args:
            adb_path: Path to adb binary
        """
        self.adb_path = adb_path
        self._verify_adb()

    def _verify_adb(self):
        """Verify ADB is installed and accessible"""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("ADB client verified")
            else:
                logger.warning("ADB verification failed")
        except FileNotFoundError:
            logger.error(f"ADB not found at {self.adb_path}")
            raise

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def list_devices(self) -> List[AndroidDevice]:
        """
        List connected Android devices.

        Returns:
            List of AndroidDevice objects
        """
        result = subprocess.run(
            [self.adb_path, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        devices = []
        lines = result.stdout.strip().split("\n")[1:]  # Skip header

        for line in lines:
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]

                device = AndroidDevice(serial=serial, status=status)

                # Parse additional info
                for part in parts[2:]:
                    if part.startswith("product:"):
                        device.product = part.split(":", 1)[1]
                    elif part.startswith("model:"):
                        device.model = part.split(":", 1)[1]
                    elif part.startswith("device:"):
                        device.device_name = part.split(":", 1)[1]

                devices.append(device)

        logger.info(f"Found {len(devices)} Android devices")
        return devices

    def get_device(self, serial: Optional[str] = None) -> Optional[AndroidDevice]:
        """Get specific device or first available device"""
        devices = self.list_devices()

        if not devices:
            return None

        if serial:
            for device in devices:
                if device.serial == serial:
                    return device
            return None

        # Return first online device
        for device in devices:
            if device.status == "device":
                return device

        # Return first device (even if offline)
        return devices[0] if devices else None

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_android_version(self, serial: Optional[str] = None) -> Optional[str]:
        """Get Android version of device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return None

        result = subprocess.run(
            [self.adb_path, "-s", serial, "shell", "getprop", "ro.build.version.release"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.stdout.strip() if result.returncode == 0 else None

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_api_level(self, serial: Optional[str] = None) -> Optional[int]:
        """Get API level of device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return None

        result = subprocess.run(
            [self.adb_path, "-s", serial, "shell", "getprop", "ro.build.version.sdk"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            try:
                return int(result.stdout.strip())
            except ValueError:
                return None
        return None

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_device_properties(self, serial: Optional[str] = None) -> Dict[str, str]:
        """Get device properties"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return {}

        result = subprocess.run(
            [self.adb_path, "-s", serial, "shell", "getprop"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        properties = {}
        for line in result.stdout.split("\n"):
            match = re.match(r"\[(.+?)\]:\s\[(.+?)\]", line)
            if match:
                properties[match.group(1)] = match.group(2)

        return properties

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def list_packages(self, serial: Optional[str] = None) -> List[str]:
        """List all installed packages"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return []

        result = subprocess.run(
            [self.adb_path, "-s", serial, "shell", "pm", "list", "packages"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        packages = []
        for line in result.stdout.split("\n"):
            if line.startswith("package:"):
                packages.append(line.split(":", 1)[1])

        return packages

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_package_info(self, package_name: str, serial: Optional[str] = None) -> Optional[PackageInfo]:
        """Get package information"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return None

        result = subprocess.run(
            [self.adb_path, "-s", serial, "shell", "dumpsys", "package", package_name],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return None

        info = PackageInfo(
            package_name=package_name,
            version="",
            version_code="",
            install_location="",
            flags="",
        )

        for line in result.stdout.split("\n"):
            if "versionName=" in line:
                info.version = line.split("versionName=")[1].strip()
            elif "versionCode=" in line:
                info.version_code = line.split("versionCode=")[1].strip()
            elif "installLocation=" in line:
                info.install_location = line.split("installLocation=")[1].strip()
            elif "flags=" in line:
                info.flags = line.split("flags=")[1].strip()

        return info

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_logcat(self, serial: Optional[str] = None, lines: int = 100) -> str:
        """Get device logcat output"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return ""

        result = subprocess.run(
            [self.adb_path, "-s", serial, "logcat", "-d", "-n", str(lines)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.stdout if result.returncode == 0 else ""

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def install_apk(self, apk_path: str, serial: Optional[str] = None) -> bool:
        """Install APK on device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return False

        result = subprocess.run(
            [self.adb_path, "-s", serial, "install", apk_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        success = result.returncode == 0 and "Success" in result.stdout
        if success:
            logger.info(f"APK installed successfully on {serial}")
        else:
            logger.error(f"Failed to install APK: {result.stdout}")

        return success

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def uninstall_package(self, package_name: str, serial: Optional[str] = None) -> bool:
        """Uninstall package from device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return False

        result = subprocess.run(
            [self.adb_path, "-s", serial, "uninstall", package_name],
            capture_output=True,
            text=True,
            timeout=30,
        )

        return result.returncode == 0

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def launch_app(self, package_name: str, serial: Optional[str] = None) -> bool:
        """Launch app on device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return False

        result = subprocess.run(
            [
                self.adb_path,
                "-s",
                serial,
                "shell",
                "am",
                "start",
                "-n",
                f"{package_name}/.MainActivity",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def push_file(self, local_path: str, remote_path: str, serial: Optional[str] = None) -> bool:
        """Push file to device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return False

        result = subprocess.run(
            [self.adb_path, "-s", serial, "push", local_path, remote_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        return result.returncode == 0

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def pull_file(self, remote_path: str, local_path: str, serial: Optional[str] = None) -> bool:
        """Pull file from device"""
        serial = serial or self._get_serial(serial)
        if not serial:
            return False

        result = subprocess.run(
            [self.adb_path, "-s", serial, "pull", remote_path, local_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        return result.returncode == 0

    def _get_serial(self, serial: Optional[str] = None) -> Optional[str]:
        """Get device serial"""
        if serial:
            return serial

        device = self.get_device()
        return device.serial if device else None


class AndroidAnalyzer:
    """High-level analyzer for Android devices"""

    def __init__(self, adb_client: ADBClient):
        """Initialize analyzer"""
        self.adb = adb_client

    def get_device_fingerprint(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """Get complete device fingerprint"""
        device = self.adb.get_device(serial)
        if not device:
            return {}

        return {
            "serial": device.serial,
            "status": device.status,
            "android_version": self.adb.get_android_version(device.serial),
            "api_level": self.adb.get_api_level(device.serial),
            "properties": self.adb.get_device_properties(device.serial),
        }

    def analyze_installed_packages(
        self, serial: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze installed packages"""
        packages = self.adb.list_packages(serial)
        results = {
            "total_packages": len(packages),
            "packages": [],
        }

        for package in packages[:20]:  # Limit to 20 for performance
            info = self.adb.get_package_info(package, serial)
            if info:
                results["packages"].append({
                    "name": info.package_name,
                    "version": info.version,
                    "version_code": info.version_code,
                })

        return results
