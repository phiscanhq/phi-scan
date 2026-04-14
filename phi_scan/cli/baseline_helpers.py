"""Private helpers backing the `phi-scan baseline` subcommands.

Extracted from ``cli/baseline.py`` so that the command module contains
only the Typer subcommand wiring. All baseline I/O (load, write, error
translation to ``typer.Exit``) and the baseline-producing scan helper
live here and are imported by the commands.
"""

from __future__ import annotations

from pathlib import Path

import typer

from phi_scan.baseline import BaselineSnapshot, create_baseline, load_baseline
from phi_scan.cli.scan_config import load_scan_config
from phi_scan.constants import (
    BASELINE_LOAD_ERROR_MESSAGE,
    DEFAULT_IGNORE_FILENAME,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
)
from phi_scan.exceptions import BaselineError
from phi_scan.models import ScanResult
from phi_scan.scanner import collect_scan_targets, execute_scan, load_ignore_patterns

__all__ = [
    "entry_count_label",
    "load_baseline_or_exit",
    "load_optional_baseline",
    "run_scan_for_baseline",
    "write_baseline_or_exit",
]

_BASELINE_NO_FILE_WARNING: str = (
    "No baseline file found at {path!r}. Run 'phi-scan baseline create' to create one."
)
_BASELINE_ERROR_MESSAGE: str = "Baseline error: {error}"
_ENTRY_LABEL_SINGULAR: str = "entry"
_ENTRY_LABEL_PLURAL: str = "entries"
_SINGULAR_COUNT: int = 1


def load_baseline_or_exit(baseline_path: Path) -> BaselineSnapshot:
    """Load a baseline snapshot, exiting with an error message on any failure."""
    try:
        snapshot = load_baseline(baseline_path=baseline_path)
    except BaselineError as baseline_load_error:
        typer.echo(_BASELINE_ERROR_MESSAGE.format(error=baseline_load_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from baseline_load_error
    if snapshot is None:
        typer.echo(_BASELINE_NO_FILE_WARNING.format(path=baseline_path), err=True)
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    return snapshot


def load_optional_baseline(baseline_path: Path) -> BaselineSnapshot | None:
    """Load a baseline snapshot, returning None and printing a warning on failure."""
    try:
        return load_baseline(baseline_path=baseline_path)
    except BaselineError as baseline_load_error:
        typer.echo(BASELINE_LOAD_ERROR_MESSAGE.format(error=baseline_load_error), err=True)
        return None


def write_baseline_or_exit(
    scan_result: ScanResult,
    max_age_days: int,
    baseline_path: Path,
) -> BaselineSnapshot:
    """Create and write a baseline snapshot, exiting with an error message on failure."""
    try:
        return create_baseline(scan_result, max_age_days, baseline_path=baseline_path)
    except BaselineError as baseline_load_error:
        typer.echo(_BASELINE_ERROR_MESSAGE.format(error=baseline_load_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from baseline_load_error


def entry_count_label(count: int) -> str:
    """Return 'entry' for 1 item, 'entries' otherwise."""
    return _ENTRY_LABEL_SINGULAR if count == _SINGULAR_COUNT else _ENTRY_LABEL_PLURAL


def run_scan_for_baseline(scan_root: Path) -> ScanResult:
    """Run a full scan of scan_root using default config, returning the ScanResult."""
    scan_config = load_scan_config(None, None)
    ignore_patterns = load_ignore_patterns(Path(DEFAULT_IGNORE_FILENAME))
    if scan_config.exclude_paths:
        ignore_patterns.extend(scan_config.exclude_paths)
    scan_targets = collect_scan_targets(scan_root, ignore_patterns, scan_config)
    return execute_scan(scan_targets, scan_config)
