"""Tests for phi_scan.logging_config — structured logging setup."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from phi_scan.exceptions import PhiScanLoggingError
from phi_scan.logging_config import LOG_FORMAT, configure_logging, get_logger

_PHI_SCAN_LOGGER_NAME: str = "phi_scan"


@pytest.fixture(autouse=True)
def reset_phi_scan_logger() -> object:
    """Ensure each test starts and ends with a clean phi_scan logger state."""
    yield
    logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    logger.handlers.clear()


# ---------------------------------------------------------------------------
# get_logger
# ---------------------------------------------------------------------------


def test_get_logger_returns_root_phi_scan_logger_when_name_is_none() -> None:
    logger = get_logger()

    assert logger.name == _PHI_SCAN_LOGGER_NAME


def test_get_logger_returns_child_logger_under_phi_scan_namespace() -> None:
    logger = get_logger("scanner")

    assert logger.name == "phi_scan.scanner"


def test_get_logger_child_is_logging_logger_instance() -> None:
    logger = get_logger("test_child")

    assert isinstance(logger, logging.Logger)


# ---------------------------------------------------------------------------
# configure_logging — handler attachment
# ---------------------------------------------------------------------------


def test_configure_logging_attaches_exactly_one_handler_without_log_file() -> None:
    configure_logging()
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)

    assert len(root_logger.handlers) == 1


def test_configure_logging_attaches_two_handlers_when_log_file_provided(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logging(log_file_path=log_file)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)

    assert len(root_logger.handlers) == 2


def test_configure_logging_replaces_handlers_on_second_call() -> None:
    configure_logging()
    configure_logging()
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)

    # If handlers were appended instead of replaced, this would be 2.
    assert len(root_logger.handlers) == 1


def test_configure_logging_sets_root_logger_level_to_debug() -> None:
    configure_logging()
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)

    assert root_logger.level == logging.DEBUG


# ---------------------------------------------------------------------------
# configure_logging — console level
# ---------------------------------------------------------------------------


def test_configure_logging_console_handler_defaults_to_warning_level() -> None:
    configure_logging()
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.level == logging.WARNING


def test_configure_logging_respects_explicit_console_level() -> None:
    configure_logging(console_level=logging.DEBUG)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.level == logging.DEBUG


def test_configure_logging_quiet_mode_silences_console_handler() -> None:
    configure_logging(is_quiet=True)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    # Level is CRITICAL+1, which is above any standard level.
    assert console_handler.level > logging.CRITICAL


# ---------------------------------------------------------------------------
# configure_logging — file handler
# ---------------------------------------------------------------------------


def _get_file_handler(
    root_logger: logging.Logger,
) -> logging.handlers.RotatingFileHandler:
    """Return the RotatingFileHandler attached to root_logger."""
    return next(
        h for h in root_logger.handlers if isinstance(h, logging.handlers.RotatingFileHandler)
    )


def test_configure_logging_file_handler_is_at_debug_level(tmp_path: Path) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logging(log_file_path=log_file)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    file_handler = _get_file_handler(root_logger)

    assert file_handler.level == logging.DEBUG


def test_configure_logging_creates_log_file_parent_directory(tmp_path: Path) -> None:
    nested_log_file = tmp_path / "nested" / "dir" / "phi-scan.log"

    configure_logging(log_file_path=nested_log_file)

    assert nested_log_file.parent.exists()


def test_configure_logging_quiet_mode_does_not_silence_file_handler(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logging(log_file_path=log_file, is_quiet=True)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    file_handler = _get_file_handler(root_logger)

    # File handler must remain at DEBUG even when console is silenced.
    assert file_handler.level == logging.DEBUG


def test_configure_logging_file_handler_is_rotating_type(tmp_path: Path) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logging(log_file_path=log_file)
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    file_handler = _get_file_handler(root_logger)

    assert isinstance(file_handler, logging.handlers.RotatingFileHandler)


def test_configure_logging_raises_phi_scan_logging_error_for_symlinked_log_path(
    tmp_path: Path,
) -> None:
    real_file = tmp_path / "real.log"
    real_file.touch()
    symlink_path = tmp_path / "phi-scan.log"
    symlink_path.symlink_to(real_file)

    with pytest.raises(PhiScanLoggingError):
        configure_logging(log_file_path=symlink_path)


# ---------------------------------------------------------------------------
# configure_logging — log format
# ---------------------------------------------------------------------------


def test_configure_logging_console_handler_has_formatter() -> None:
    configure_logging()
    root_logger = logging.getLogger(_PHI_SCAN_LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.formatter is not None


def test_configure_logging_log_format_contains_levelname_and_name() -> None:
    assert "%(levelname)s" in LOG_FORMAT
    assert "%(name)s" in LOG_FORMAT
