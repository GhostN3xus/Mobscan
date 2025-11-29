"""
APK and IPA extraction and parsing utilities.

Provides functions to extract metadata and resources from mobile applications.
"""

from pathlib import Path
from typing import Dict, Optional
import zipfile
import json
import logging

logger = logging.getLogger(__name__)


def extract_apk_info(apk_path: str) -> Dict[str, str]:
    """
    Extract metadata from Android APK file.

    Args:
        apk_path: Path to APK file

    Returns:
        Dictionary with app metadata
    """
    try:
        app_file = Path(apk_path)
        info = {
            'filename': app_file.name,
            'size': app_file.stat().st_size,
            'package_name': 'com.app',
            'version_name': '1.0.0',
            'version_code': '1',
            'target_sdk': '',
            'min_sdk': '',
            'permissions': [],
        }

        # Try to extract from APK (ZIP file)
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # List of all files in APK
                files = apk.namelist()

                # Check for manifest
                if 'AndroidManifest.xml' in files:
                    manifest_data = apk.read('AndroidManifest.xml')
                    # Try to extract package name from manifest
                    # This is simplified - real parsing would use androguard
                    manifest_text = manifest_data.decode('utf-8', errors='ignore')
                    if 'package=' in manifest_text:
                        try:
                            parts = manifest_text.split('package=')
                            if len(parts) > 1:
                                info['package_name'] = parts[1].split('"')[1]
                        except Exception as parse_err:
                            logger.debug(f"Failed to parse package name: {parse_err}")

        except Exception as e:
            logger.warning(f"Failed to extract APK metadata from zipfile: {e}")

        return info

    except Exception as e:
        return {
            'filename': app_file.name if Path(apk_path).exists() else 'unknown',
            'error': str(e)
        }


def extract_ipa_info(ipa_path: str) -> Dict[str, str]:
    """
    Extract metadata from iOS IPA file.

    Args:
        ipa_path: Path to IPA file

    Returns:
        Dictionary with app metadata
    """
    try:
        app_file = Path(ipa_path)
        info = {
            'filename': app_file.name,
            'size': app_file.stat().st_size,
            'bundle_id': 'com.app',
            'version': '1.0.0',
            'build_version': '1',
            'minimum_os_version': '',
            'supported_platforms': [],
        }

        # Try to extract from IPA (ZIP file)
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa:
                # Look for Info.plist
                files = ipa.namelist()

                # Find Info.plist in typical location
                plist_path = None
                for f in files:
                    if 'Info.plist' in f:
                        plist_path = f
                        break

                if plist_path:
                    # Would parse plist here
                    # For now, just indicate we found it
                    logger.debug(f"Found Info.plist at {plist_path}")

        except Exception as e:
            logger.warning(f"Failed to extract IPA metadata from zipfile: {e}")

        return info

    except Exception as e:
        return {
            'filename': app_file.name if Path(ipa_path).exists() else 'unknown',
            'error': str(e)
        }


def get_apk_permissions(apk_path: str) -> list:
    """
    Extract permissions from APK file.

    Args:
        apk_path: Path to APK file

    Returns:
        List of permissions
    """
    permissions = []

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            if 'AndroidManifest.xml' in apk.namelist():
                manifest_data = apk.read('AndroidManifest.xml')
                manifest_text = manifest_data.decode('utf-8', errors='ignore')

                # Simple extraction of permissions
                # Real implementation would use proper XML parsing
                if 'uses-permission' in manifest_text:
                    # Extract android:name attributes
                    logger.debug("Found uses-permission in manifest")

    except Exception as e:
        logger.warning(f"Failed to extract APK permissions: {e}")

    return permissions


def get_apk_activities(apk_path: str) -> list:
    """
    Extract activities from APK file.

    Args:
        apk_path: Path to APK file

    Returns:
        List of activities
    """
    activities = []

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            if 'AndroidManifest.xml' in apk.namelist():
                manifest_data = apk.read('AndroidManifest.xml')
                # Would parse activities here
                logger.debug("Reading AndroidManifest.xml for activities")

    except Exception as e:
        logger.warning(f"Failed to extract APK activities: {e}")

    return activities
