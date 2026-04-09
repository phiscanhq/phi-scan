"""Baseline command group — phi-scan baseline <subcommand>."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from phi_scan.baseline import (
    BaselineSnapshot,
    compute_baseline_diff,
    create_baseline,
    detect_baseline_drift,
    get_baseline_summary,
    load_baseline,
)
from phi_scan.cli_scan_config import load_scan_config
from phi_scan.constants import (
    BASELINE_DRIFT_WARNING_PERCENT,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_BASELINE_MAX_AGE_DAYS,
    DEFAULT_IGNORE_FILENAME,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
)
from phi_scan.exceptions import BaselineError
from phi_scan.models import ScanResult
from phi_scan.output import (
    display_baseline_diff,
    display_baseline_drift_warning,
    display_baseline_summary,
    get_console,
)
from phi_scan.scanner import collect_scan_targets, execute_scan, load_ignore_patterns

baseline_app = typer.Typer(
    name="baseline",
    help="Manage the scan baseline — accept existing findings and enforce zero new PHI.",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASELINE_PATH_HELP: str = (
    "Path to the .phi-scanbaseline file. Defaults to .phi-scanbaseline in CWD."
)
_BASELINE_MAX_AGE_HELP: str = (
    "Days until baseline entries expire and revert to active findings (default: 90)."
)
_BASELINE_SCAN_PATH_HELP: str = "Directory to scan when creating or updating the baseline."
_BASELINE_NO_FILE_WARNING: str = (
    "No baseline file found at {path!r}. Run 'phi-scan baseline create' to create one."
)
_BASELINE_CREATED_MESSAGE: str = (
    "Baseline created: {path}  ({count} {label} accepted, expires in {days} days)"
)
_BASELINE_UPDATED_MESSAGE: str = (
    "Baseline updated: {path}  ({count} {label} accepted, expires in {days} days)"
)
_BASELINE_CLEARED_MESSAGE: str = "Baseline cleared: {path}"
_BASELINE_NOT_FOUND_MESSAGE: str = "No baseline file found at {path!r} — nothing to clear."
_BASELINE_CLEAR_CONFIRM_PROMPT: str = "This will remove the baseline at {path!r}. Continue? [y/N]"
_BASELINE_CLEAR_ABORTED_MESSAGE: str = "Baseline clear aborted."
_BASELINE_ERROR_MESSAGE: str = "Baseline error: {error}"
_BASELINE_LOAD_ERROR_MESSAGE: str = "Could not load baseline: {error}"
_BASELINE_CONFIRM_YES: str = "y"
_ENTRY_LABEL_SINGULAR: str = "entry"
_ENTRY_LABEL_PLURAL: str = "entries"
_SINGULAR_COUNT: int = 1

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _load_baseline_or_exit(baseline_path: Path) -> BaselineSnapshot:
    """Load a baseline snapshot, exiting with an error message on any failure.

    Centralises the try/except + None-check pattern repeated across
    ``baseline show`` and ``baseline diff``.

    Args:
        baseline_path: Path to the .phi-scanbaseline file.

    Returns:
        Loaded snapshot (never None — exits instead).

    Raises:
        typer.Exit: With EXIT_CODE_ERROR on BaselineError, or EXIT_CODE_CLEAN
            when no baseline file exists yet.
    """
    try:
        snapshot = load_baseline(baseline_path=baseline_path)
    except BaselineError as error:
        typer.echo(_BASELINE_ERROR_MESSAGE.format(error=error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    if snapshot is None:
        typer.echo(_BASELINE_NO_FILE_WARNING.format(path=baseline_path), err=True)
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    return snapshot


def _load_baseline_or_warn(baseline_path: Path) -> BaselineSnapshot | None:
    """Load a baseline snapshot, printing a warning and returning None on failure.

    Args:
        baseline_path: Path to the .phi-scanbaseline file.

    Returns:
        Loaded snapshot, or None when the file is missing or unreadable.
    """
    try:
        return load_baseline(baseline_path=baseline_path)
    except BaselineError as error:
        typer.echo(_BASELINE_LOAD_ERROR_MESSAGE.format(error=error), err=True)
        return None


def _write_baseline_or_exit(
    scan_result: ScanResult,
    max_age_days: int,
    baseline_path: Path,
) -> BaselineSnapshot:
    """Create and write a baseline snapshot, exiting with an error message on failure.

    Centralises the try/except pattern repeated across ``baseline create``
    and ``baseline update``.

    Args:
        scan_result:    Completed scan whose findings become the new baseline.
        max_age_days:   Maximum age in days before a baseline entry expires.
        baseline_path:  Path to write the .phi-scanbaseline file.

    Returns:
        The newly written snapshot.

    Raises:
        typer.Exit: With EXIT_CODE_ERROR when the file cannot be written.
    """
    try:
        return create_baseline(scan_result, max_age_days, baseline_path=baseline_path)
    except BaselineError as error:
        typer.echo(_BASELINE_ERROR_MESSAGE.format(error=error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)


def _entry_count_label(count: int) -> str:
    """Return 'entry' for 1 item, 'entries' otherwise."""
    return _ENTRY_LABEL_SINGULAR if count == _SINGULAR_COUNT else _ENTRY_LABEL_PLURAL


def _run_scan_for_baseline(scan_root: Path) -> ScanResult:
    """Run a full scan of scan_root using default config, returning the ScanResult.

    Args:
        scan_root: Directory to scan.

    Returns:
        Aggregated ScanResult from execute_scan.
    """
    scan_config = load_scan_config(None, None)
    ignore_patterns = load_ignore_patterns(Path(DEFAULT_IGNORE_FILENAME))
    if scan_config.exclude_paths:
        ignore_patterns.extend(scan_config.exclude_paths)
    scan_targets = collect_scan_targets(scan_root, ignore_patterns, scan_config)
    return execute_scan(scan_targets, scan_config)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@baseline_app.command("create")
def baseline_create(
    path: Annotated[Path, typer.Argument(help=_BASELINE_SCAN_PATH_HELP)] = Path("."),
    max_age_days: Annotated[
        int, typer.Option("--max-age-days", help=_BASELINE_MAX_AGE_HELP)
    ] = DEFAULT_BASELINE_MAX_AGE_DAYS,
    baseline_path: Annotated[
        Path, typer.Option("--baseline-path", help=_BASELINE_PATH_HELP)
    ] = Path(DEFAULT_BASELINE_FILENAME),
) -> None:
    """Run a full scan and save all findings as the accepted baseline.

    The baseline file is written to .phi-scanbaseline in the current directory.
    Commit it to your repository so all developers share the same baseline.
    """
    console = get_console()
    scan_result = _run_scan_for_baseline(path)
    snapshot = _write_baseline_or_exit(scan_result, max_age_days, baseline_path)
    count = len(snapshot.entries)
    console.print(
        _BASELINE_CREATED_MESSAGE.format(
            path=baseline_path,
            count=count,
            label=_entry_count_label(count),
            days=max_age_days,
        )
    )


@baseline_app.command("show")
def baseline_show(
    baseline_path: Annotated[
        Path, typer.Option("--baseline-path", help=_BASELINE_PATH_HELP)
    ] = Path(DEFAULT_BASELINE_FILENAME),
) -> None:
    """Display summary statistics for the current baseline."""
    snapshot = _load_baseline_or_exit(baseline_path)
    summary = get_baseline_summary(snapshot, baseline_path)
    display_baseline_summary(summary)


@baseline_app.command("clear")
def baseline_clear(
    baseline_path: Annotated[
        Path, typer.Option("--baseline-path", help=_BASELINE_PATH_HELP)
    ] = Path(DEFAULT_BASELINE_FILENAME),
) -> None:
    """Remove the baseline file, reverting all findings to active."""
    if not baseline_path.exists():
        typer.echo(_BASELINE_NOT_FOUND_MESSAGE.format(path=baseline_path))
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    raw_answer = (
        typer.prompt(_BASELINE_CLEAR_CONFIRM_PROMPT.format(path=baseline_path), default="")
        .strip()
        .lower()
    )
    if raw_answer != _BASELINE_CONFIRM_YES:
        typer.echo(_BASELINE_CLEAR_ABORTED_MESSAGE)
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    baseline_path.unlink()
    typer.echo(_BASELINE_CLEARED_MESSAGE.format(path=baseline_path))


@baseline_app.command("update")
def baseline_update(
    path: Annotated[Path, typer.Argument(help=_BASELINE_SCAN_PATH_HELP)] = Path("."),
    max_age_days: Annotated[
        int, typer.Option("--max-age-days", help=_BASELINE_MAX_AGE_HELP)
    ] = DEFAULT_BASELINE_MAX_AGE_DAYS,
    baseline_path: Annotated[
        Path, typer.Option("--baseline-path", help=_BASELINE_PATH_HELP)
    ] = Path(DEFAULT_BASELINE_FILENAME),
) -> None:
    """Re-scan and overwrite the baseline with the current findings.

    Warn when the new entry count is significantly higher than the previous count
    (drift detection). A large increase suggests PHI accumulation rather than
    remediation.
    """
    console = get_console()
    old_snapshot = _load_baseline_or_warn(baseline_path)
    scan_result = _run_scan_for_baseline(path)
    new_snapshot = _write_baseline_or_exit(scan_result, max_age_days, baseline_path)
    if old_snapshot is not None:
        drift = detect_baseline_drift(old_snapshot, new_snapshot)
        if drift > BASELINE_DRIFT_WARNING_PERCENT:
            display_baseline_drift_warning(
                len(old_snapshot.entries), len(new_snapshot.entries), drift
            )
    count = len(new_snapshot.entries)
    console.print(
        _BASELINE_UPDATED_MESSAGE.format(
            path=baseline_path,
            count=count,
            label=_entry_count_label(count),
            days=max_age_days,
        )
    )


@baseline_app.command("diff")
def baseline_diff(
    path: Annotated[Path, typer.Argument(help=_BASELINE_SCAN_PATH_HELP)] = Path("."),
    baseline_path: Annotated[
        Path, typer.Option("--baseline-path", help=_BASELINE_PATH_HELP)
    ] = Path(DEFAULT_BASELINE_FILENAME),
) -> None:
    """Compare the current scan against the baseline.

    Shows new findings (not in baseline), resolved findings (in baseline but no
    longer detected), and persisting findings (still present and still baselined).
    """
    snapshot = _load_baseline_or_exit(baseline_path)
    scan_result = _run_scan_for_baseline(path)
    diff = compute_baseline_diff(snapshot, scan_result)
    display_baseline_diff(diff)
