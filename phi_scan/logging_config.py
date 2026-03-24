"""Structured logging setup for PhiScan (--log-level, --log-file)."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import TextIO

from phi_scan.exceptions import PhiScanLoggingError

__all__ = [
    "LOG_FORMAT",
    "configure_logging",
    "get_logger",
]

_LOGGER_NAME: str = "phi_scan"
LOG_FORMAT: str = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
_DEFAULT_LOG_DIRECTORY: Path = Path.home() / ".phi-scanner"
_DEFAULT_LOG_FILENAME: str = "phi-scan.log"
_DEFAULT_CONSOLE_LEVEL: int = logging.WARNING
_MAX_LOG_FILE_BYTES: int = 10 * 1024 * 1024
_LOG_FILE_BACKUP_COUNT: int = 5
_SILENCED_LOG_LEVEL: int = logging.CRITICAL + 1


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the phi_scan namespace.

    Args:
        name: Optional sub-name appended to the root logger (e.g. "scanner").
            Pass None to get the root phi_scan logger directly.

    Returns:
        A Logger instance under the phi_scan hierarchy.
    """
    if name is None:
        return logging.getLogger(_LOGGER_NAME)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def configure_logging(
    console_level: int = _DEFAULT_CONSOLE_LEVEL,
    log_file_path: Path | None = None,
    is_quiet: bool = False,
) -> None:
    """Configure the phi_scan logger with console and optional file handlers.

    Must be called once at CLI startup before any scanning begins. Calling it
    a second time replaces all existing handlers on the phi_scan logger.

    Args:
        console_level: Logging level for the console handler. Ignored when
            is_quiet is True. Defaults to WARNING.
        log_file_path: If provided, attach a rotating file handler writing to
            this path. The parent directory is created if it does not exist.
            Defaults to None (no file logging).
        is_quiet: When True, suppress all console output by setting the console
            handler level to CRITICAL+1 (effectively silenced). File handler
            is unaffected.
    """
    root_logger = logging.getLogger(_LOGGER_NAME)
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    console_handler = _build_console_handler(
        level=_SILENCED_LOG_LEVEL if is_quiet else console_level,
    )
    root_logger.addHandler(console_handler)

    if log_file_path is not None:
        file_handler = _build_file_handler(log_file_path)
        root_logger.addHandler(file_handler)


def _build_console_handler(level: int) -> logging.StreamHandler[TextIO]:
    """Build a StreamHandler with the standard phi_scan log format.

    Args:
        level: The logging level threshold for this handler.

    Returns:
        A configured StreamHandler writing to stderr.
    """
    handler: logging.StreamHandler[TextIO] = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def _build_file_handler(log_file_path: Path) -> logging.handlers.RotatingFileHandler:
    """Build a RotatingFileHandler, creating the parent directory if needed.

    Args:
        log_file_path: Absolute path to the log file. The parent directory is
            created with mode 0o700 if it does not already exist.

    Returns:
        A configured RotatingFileHandler at DEBUG level.

    Raises:
        PhiScanLoggingError: If log_file_path resolves to a symlink. Following
            symlinks during log writes could redirect output to arbitrary files.
    """
    expanded_path = log_file_path.expanduser()
    if expanded_path.is_symlink():
        raise PhiScanLoggingError(f"Log file path must not be a symlink: {expanded_path}")
    resolved_path = expanded_path.resolve()
    resolved_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        resolved_path,
        maxBytes=_MAX_LOG_FILE_BYTES,
        backupCount=_LOG_FILE_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler
