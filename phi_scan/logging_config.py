"""Structured logging setup for PhiScan (--log-level, --log-file)."""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import TextIO

from phi_scan.constants import BYTES_PER_MEGABYTE
from phi_scan.exceptions import PhiScanLoggingError

__all__ = [
    "LOGGER_NAME",
    "LOG_FORMAT",
    "replace_logger_handlers",
    "get_logger",
]

LOGGER_NAME: str = "phi_scan"
LOG_FORMAT: str = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
_DEFAULT_CONSOLE_LEVEL: int = logging.WARNING
_MAX_LOG_FILE_MEGABYTES: int = 10
_MAX_LOG_FILE_BYTES: int = _MAX_LOG_FILE_MEGABYTES * BYTES_PER_MEGABYTE
_LOG_FILE_BACKUP_COUNT: int = 5
_SILENCED_LOG_LEVEL: int = logging.CRITICAL + 1
_LOG_DIRECTORY_MODE: int = 0o700
_SYMLINK_LOG_PATH_ERROR: str = "Log file path must not be a symlink: {path}"
_SYMLINK_LOG_PARENT_ERROR: str = "Log file path resolves through a symlink: {path}"
_LOG_DIRECTORY_CREATION_ERROR: str = "Cannot create log directory: {path}"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the phi_scan namespace.

    Args:
        name: Optional sub-name appended to the root logger (e.g. "scanner").
            Pass None to get the root phi_scan logger directly.

    Returns:
        A Logger instance under the phi_scan hierarchy.
    """
    if name is None:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def replace_logger_handlers(
    console_level: int = _DEFAULT_CONSOLE_LEVEL,
    log_file_path: Path | None = None,
    is_quiet: bool = False,
) -> None:
    """Replace all phi_scan logger handlers with a fresh console and optional file handler.

    Clears any existing handlers and attaches new ones. Calling this a second
    time fully replaces the first configuration.

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
    root_logger = logging.getLogger(LOGGER_NAME)
    root_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

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
    """Build a RotatingFileHandler, rejecting symlinks and creating the directory.

    Args:
        log_file_path: Path to the log file. Expanded, normalized, and validated
            before the handler is created.

    Returns:
        A configured RotatingFileHandler at DEBUG level.

    Raises:
        PhiScanLoggingError: If log_file_path or any parent component is a
            symlink, or if the log directory cannot be created.
    """
    expanded_path = log_file_path.expanduser()
    if expanded_path.is_symlink():
        raise PhiScanLoggingError(_SYMLINK_LOG_PATH_ERROR.format(path=expanded_path))
    normalized_path = Path(os.path.normpath(expanded_path.absolute()))
    _reject_symlinked_parents(normalized_path)
    _create_log_directory(normalized_path.parent)
    return _build_rotating_handler(normalized_path)


def _reject_symlinked_parents(normalized_path: Path) -> None:
    """Raise PhiScanLoggingError if any existing path component is a symlink.

    Expects a pre-normalized path (.. already collapsed) so that crafted paths
    cannot hide a symlinked component by placing it after a .. segment.

    Args:
        normalized_path: The log file path after expanduser() and normpath()
            have been applied. Caller is responsible for pre-normalization.

    Raises:
        PhiScanLoggingError: If any existing component of normalized_path is
            a symlink.
    """
    cumulative = Path(normalized_path.anchor)
    for path_component in normalized_path.parts[1:]:
        cumulative = cumulative / path_component
        if cumulative.exists() and cumulative.is_symlink():
            raise PhiScanLoggingError(_SYMLINK_LOG_PARENT_ERROR.format(path=normalized_path))


def _create_log_directory(directory: Path) -> None:
    """Create directory and all parents with restricted permissions.

    Args:
        directory: The directory path to create.

    Raises:
        PhiScanLoggingError: If the directory cannot be created due to a
            permissions or OS error.
    """
    try:
        directory.mkdir(mode=_LOG_DIRECTORY_MODE, parents=True, exist_ok=True)
    except OSError as error:
        raise PhiScanLoggingError(_LOG_DIRECTORY_CREATION_ERROR.format(path=directory)) from error


def _build_rotating_handler(log_file_path: Path) -> logging.handlers.RotatingFileHandler:
    """Build and configure a RotatingFileHandler at DEBUG level.

    Args:
        log_file_path: Normalized, validated path to the log file.

    Returns:
        A configured RotatingFileHandler.
    """
    handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=_MAX_LOG_FILE_BYTES,
        backupCount=_LOG_FILE_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler
