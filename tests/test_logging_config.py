"""Tests for phi_scan.logging_config — structured logging setup."""

from __future__ import annotations

import logging
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest

from phi_scan.exceptions import PhiScanLoggingError
from phi_scan.logging_config import LOG_FORMAT, LOGGER_NAME, configure_logger_handlers, get_logger


@pytest.fixture(autouse=True)
def reset_phi_scan_logger() -> Generator[None, None, None]:
    """Ensure each test starts and ends with a clean phi_scan logger state."""
    yield
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()


# ---------------------------------------------------------------------------
# get_logger
# ---------------------------------------------------------------------------


def test_get_logger_returns_root_phi_scan_logger_when_name_is_none() -> None:
    logger = get_logger()

    assert logger.name == LOGGER_NAME


def test_get_logger_returns_child_logger_under_phi_scan_namespace() -> None:
    logger = get_logger("scanner")

    assert logger.name == f"{LOGGER_NAME}.scanner"


def test_get_logger_child_is_logging_logger_instance() -> None:
    logger = get_logger("test_child")

    assert isinstance(logger, logging.Logger)


# ---------------------------------------------------------------------------
# configure_logger_handlers — handler attachment
# ---------------------------------------------------------------------------


def test_configure_logger_handlers_attaches_exactly_one_handler_without_log_file() -> None:
    configure_logger_handlers()
    root_logger = logging.getLogger(LOGGER_NAME)

    assert len(root_logger.handlers) == 1


def test_configure_logger_handlers_attaches_two_handlers_when_log_file_provided(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logger_handlers(log_file_path=log_file)
    root_logger = logging.getLogger(LOGGER_NAME)

    assert len(root_logger.handlers) == 2


def test_configure_logger_handlers_replaces_handlers_on_second_call() -> None:
    configure_logger_handlers()
    configure_logger_handlers()
    root_logger = logging.getLogger(LOGGER_NAME)

    # If handlers were appended instead of replaced, this would be 2.
    assert len(root_logger.handlers) == 1


def test_configure_logger_handlers_sets_root_logger_level_to_debug() -> None:
    configure_logger_handlers()
    root_logger = logging.getLogger(LOGGER_NAME)

    assert root_logger.level == logging.DEBUG


# ---------------------------------------------------------------------------
# configure_logger_handlers — console level
# ---------------------------------------------------------------------------


def test_configure_logger_handlers_console_handler_defaults_to_warning_level() -> None:
    configure_logger_handlers()
    root_logger = logging.getLogger(LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.level == logging.WARNING


def test_configure_logger_handlers_respects_explicit_console_level() -> None:
    configure_logger_handlers(console_level=logging.DEBUG)
    root_logger = logging.getLogger(LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.level == logging.DEBUG


def test_configure_logger_handlers_quiet_mode_silences_console_handler() -> None:
    configure_logger_handlers(is_quiet=True)
    root_logger = logging.getLogger(LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    # Level is CRITICAL+1, which is above any standard level.
    assert console_handler.level > logging.CRITICAL


# ---------------------------------------------------------------------------
# configure_logger_handlers — file handler
# ---------------------------------------------------------------------------


def _extract_rotating_file_handler(
    root_logger: logging.Logger,
) -> logging.handlers.RotatingFileHandler:
    """Return the RotatingFileHandler attached to root_logger."""
    file_handler = next(
        (h for h in root_logger.handlers if isinstance(h, logging.handlers.RotatingFileHandler)),
        None,
    )
    assert file_handler is not None, "No RotatingFileHandler attached to root logger"
    return file_handler


def test_configure_logger_handlers_file_handler_is_at_debug_level(tmp_path: Path) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logger_handlers(log_file_path=log_file)
    root_logger = logging.getLogger(LOGGER_NAME)
    file_handler = _extract_rotating_file_handler(root_logger)

    assert file_handler.level == logging.DEBUG


def test_configure_logger_handlers_creates_log_file_parent_directory(tmp_path: Path) -> None:
    nested_log_file = tmp_path / "nested" / "dir" / "phi-scan.log"

    configure_logger_handlers(log_file_path=nested_log_file)

    assert nested_log_file.parent.exists()


def test_configure_logger_handlers_quiet_mode_does_not_silence_file_handler(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "phi-scan.log"

    configure_logger_handlers(log_file_path=log_file, is_quiet=True)
    root_logger = logging.getLogger(LOGGER_NAME)
    file_handler = _extract_rotating_file_handler(root_logger)

    # File handler must remain at DEBUG even when console is silenced.
    assert file_handler.level == logging.DEBUG


def test_configure_logger_handlers_raises_phi_scan_logging_error_for_symlinked_log_path(
    tmp_path: Path,
) -> None:
    real_file = tmp_path / "real.log"
    real_file.touch()
    symlink_path = tmp_path / "phi-scan.log"
    symlink_path.symlink_to(real_file)

    with pytest.raises(PhiScanLoggingError):
        configure_logger_handlers(log_file_path=symlink_path)


def test_configure_logger_handlers_raises_phi_scan_logging_error_when_directory_creation_fails(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "phi-scan.log"

    with patch("pathlib.Path.mkdir", side_effect=OSError("permission denied")):
        with pytest.raises(PhiScanLoggingError):
            configure_logger_handlers(log_file_path=log_file)


def test_configure_logger_handlers_raises_phi_scan_logging_error_for_symlinked_parent_directory(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    symlink_dir = tmp_path / "symlink_dir"
    symlink_dir.symlink_to(real_dir)
    log_file = symlink_dir / "phi-scan.log"

    with pytest.raises(PhiScanLoggingError):
        configure_logger_handlers(log_file_path=log_file)


def test_configure_logger_handlers_allows_dotdot_path_that_normalizes_to_safe_location(
    tmp_path: Path,
) -> None:
    # normpath collapses .. segments before the symlink check, so a path like
    # extra_dir/../real_dir/phi-scan.log (where no component is a symlink) is
    # safe and must not raise — the .. simply cancels out extra_dir.
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    extra_dir = tmp_path / "extra_dir"
    extra_dir.mkdir()
    log_file = extra_dir / ".." / "real_dir" / "phi-scan.log"

    configure_logger_handlers(log_file_path=log_file)

    assert (real_dir / "phi-scan.log").exists()


# ---------------------------------------------------------------------------
# configure_logger_handlers — log format
# ---------------------------------------------------------------------------


def test_configure_logger_handlers_console_handler_has_formatter() -> None:
    configure_logger_handlers()
    root_logger = logging.getLogger(LOGGER_NAME)
    console_handler = root_logger.handlers[0]

    assert console_handler.formatter is not None


def test_configure_logger_handlers_log_format_contains_levelname_and_name() -> None:
    assert "%(levelname)s" in LOG_FORMAT
    assert "%(name)s" in LOG_FORMAT
