"""
Logging utilities for Mobscan.

Provides centralized logging configuration with support for structured
JSON logging, multiple handlers, and context tracking.
"""

import logging
import json
import sys
import traceback
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import inspect


# Global logger dictionary
_loggers = {}
_log_context = {}


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add context if available
        if _log_context:
            log_data["context"] = _log_context.copy()

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        return json.dumps(log_data)


class StructuredLogger(logging.Logger):
    """Extended logger with structured logging capabilities"""

    def with_context(self, **kwargs):
        """Add context to all subsequent logs"""
        _log_context.update(kwargs)
        return self

    def clear_context(self):
        """Clear logging context"""
        _log_context.clear()

    def log_with_data(
        self,
        level: int,
        message: str,
        extra_data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Log with additional structured data"""
        record = self.makeRecord(
            self.name,
            level,
            inspect.currentframe().f_back.f_code.co_filename,
            inspect.currentframe().f_back.f_lineno,
            message,
            (),
            None,
            func=inspect.currentframe().f_back.f_code.co_name,
        )
        if extra_data:
            record.extra_data = extra_data
        self.handle(record)


def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    json_format: bool = False,
) -> logging.Logger:
    """
    Setup and configure a logger.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to log to
        format_string: Custom format string
        json_format: Use JSON formatter for structured logging

    Returns:
        Configured logger instance
    """
    # Set custom logger class
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Prevent duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        if not format_string:
            format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(format_string)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(getattr(logging, level.upper()))
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(getattr(logging, level.upper()))
        logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger or create a new one.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    if name not in _loggers:
        return setup_logger(name)
    return _loggers[name]


def configure_root_logger(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
):
    """
    Configure the root logger.

    Args:
        level: Logging level
        log_file: Optional file path
        json_format: Enable JSON formatting
    """
    return setup_logger(
        "mobscan",
        level=level,
        log_file=log_file,
        json_format=json_format,
    )


def set_log_context(**kwargs):
    """Set logging context for correlation tracking"""
    _log_context.update(kwargs)


def clear_log_context():
    """Clear logging context"""
    _log_context.clear()


def get_log_context() -> Dict[str, Any]:
    """Get current logging context"""
    return _log_context.copy()
