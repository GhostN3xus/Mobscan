"""
General helper functions for Mobscan.

Provides utility functions for file management, platform detection, etc.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional


def get_app_platform(app_path: str) -> str:
    """
    Determine application platform from file extension.

    Args:
        app_path: Path to application file

    Returns:
        Platform name ('android' or 'ios')
    """
    app_file = Path(app_path)
    extension = app_file.suffix.lower()

    if extension == '.apk':
        return 'android'
    elif extension == '.ipa':
        return 'ios'
    elif extension == '.aab':
        return 'android'
    else:
        return 'unknown'


def ensure_directory(dir_path: str) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        dir_path: Path to directory

    Returns:
        Path object
    """
    path = Path(dir_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_temp_files(dir_path: Optional[str] = None):
    """
    Clean up temporary files and directories.

    Args:
        dir_path: Specific directory to clean, or None for default temp
    """
    if dir_path is None:
        dir_path = tempfile.gettempdir()

    try:
        temp_path = Path(dir_path)
        if temp_path.exists():
            # Look for mobscan temp directories
            for item in temp_path.glob('mobscan_*'):
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                elif item.is_file():
                    item.unlink(missing_ok=True)
    except Exception as e:
        pass


def get_file_size_mb(file_path: str) -> float:
    """
    Get file size in megabytes.

    Args:
        file_path: Path to file

    Returns:
        File size in MB
    """
    try:
        size_bytes = Path(file_path).stat().st_size
        return size_bytes / (1024 * 1024)
    except Exception:
        return 0.0


def format_bytes(size_bytes: int) -> str:
    """
    Format bytes to human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def get_current_timestamp() -> str:
    """Get current timestamp as ISO format string."""
    from datetime import datetime
    return datetime.utcnow().isoformat() + 'Z'


def is_file_readable(file_path: str) -> bool:
    """
    Check if a file is readable.

    Args:
        file_path: Path to file

    Returns:
        True if readable, False otherwise
    """
    try:
        path = Path(file_path)
        return path.exists() and os.access(path, os.R_OK)
    except Exception:
        return False


def safe_delete_file(file_path: str) -> bool:
    """
    Safely delete a file.

    Args:
        file_path: Path to file

    Returns:
        True if deleted, False otherwise
    """
    try:
        Path(file_path).unlink()
        return True
    except Exception:
        return False
