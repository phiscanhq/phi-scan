"""Shared scan configuration loader used by cli.py and cli_baseline.py."""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

import typer

from phi_scan.config import load_config
from phi_scan.constants import (
    DEFAULT_CONFIG_FILENAME,
    EXIT_CODE_ERROR,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError
from phi_scan.models import ScanConfig

_logger: logging.Logger = logging.getLogger(__name__)

_CONFIG_LOAD_FAILURE_WARNING: str = (
    "Config file {path!r} exists but could not be loaded — using defaults: {error}"
)
_INVALID_SEVERITY_THRESHOLD_ERROR: str = (
    "Invalid severity threshold {value!r}. Accepted values: info, low, medium, high."
)
_NO_CONFIG_FILE_HINT: str = (
    "No {filename} found — using built-in defaults. "
    "Run `phi-scan config init` to create a config file."
)


def load_scan_config(config_path: Path | None, severity_threshold: str | None) -> ScanConfig:
    """Load ScanConfig from file, applying a CLI severity override if provided.

    A missing or unreadable config file is not an error — defaults are used so
    `phi-scan scan .` works out of the box without any config file.

    Args:
        config_path: Path to .phi-scanner.yml, or None to use the default name.
        severity_threshold: CLI override for the minimum severity level, or None.

    Returns:
        A fully populated ScanConfig with any CLI overrides applied.

    Raises:
        typer.Exit: If severity_threshold is not a valid SeverityLevel value.
    """
    resolved_config_path = config_path or Path(DEFAULT_CONFIG_FILENAME)
    try:
        scan_config = load_config(resolved_config_path)
    except ConfigurationError as config_error:
        if resolved_config_path.exists():
            _logger.warning(
                _CONFIG_LOAD_FAILURE_WARNING.format(
                    path=str(resolved_config_path), error=config_error
                )
            )
        else:
            typer.echo(_NO_CONFIG_FILE_HINT.format(filename=resolved_config_path.name), err=True)
        scan_config = ScanConfig()
    if severity_threshold is None:
        return scan_config
    try:
        parsed_severity = SeverityLevel(severity_threshold.lower())
    except ValueError:
        typer.echo(_INVALID_SEVERITY_THRESHOLD_ERROR.format(value=severity_threshold), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    return dataclasses.replace(scan_config, severity_threshold=parsed_severity)
