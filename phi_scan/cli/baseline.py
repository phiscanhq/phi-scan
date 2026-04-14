"""Baseline command group — phi-scan baseline <subcommand>."""

from __future__ import annotations

__all__ = ["baseline_app"]

from pathlib import Path
from typing import Annotated

import typer

from phi_scan.baseline import (
    compute_baseline_diff,
    detect_baseline_drift,
    get_baseline_summary,
)
from phi_scan.cli.baseline_helpers import (
    entry_count_label,
    load_baseline_or_exit,
    load_optional_baseline,
    run_scan_for_baseline,
    write_baseline_or_exit,
)
from phi_scan.constants import (
    BASELINE_DRIFT_WARNING_PERCENT,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_BASELINE_MAX_AGE_DAYS,
    EXIT_CODE_CLEAN,
)
from phi_scan.output import (
    display_baseline_diff,
    display_baseline_drift_warning,
    display_baseline_summary,
    get_console,
)

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

_BASELINE_CONFIRM_YES: str = "y"


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
    scan_result = run_scan_for_baseline(path)
    snapshot = write_baseline_or_exit(scan_result, max_age_days, baseline_path)
    count = len(snapshot.entries)
    console.print(
        _BASELINE_CREATED_MESSAGE.format(
            path=baseline_path,
            count=count,
            label=entry_count_label(count),
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
    snapshot = load_baseline_or_exit(baseline_path)
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
    old_snapshot = load_optional_baseline(baseline_path)
    scan_result = run_scan_for_baseline(path)
    new_snapshot = write_baseline_or_exit(scan_result, max_age_days, baseline_path)
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
            label=entry_count_label(count),
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
    snapshot = load_baseline_or_exit(baseline_path)
    scan_result = run_scan_for_baseline(path)
    diff = compute_baseline_diff(snapshot, scan_result)
    display_baseline_diff(diff)
