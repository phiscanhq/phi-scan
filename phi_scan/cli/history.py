"""`phi-scan history` and `phi-scan report` commands."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any

import typer

from phi_scan.audit import (
    ChainVerifyResult,
    ensure_current_schema,
    get_last_scan,
    query_recent_scans,
    verify_audit_chain,
)
from phi_scan.constants import (
    DEFAULT_DATABASE_PATH,
    EXIT_CODE_VIOLATION,
)

_HISTORY_LAST_HELP: str = "Show scans from the last N days (e.g. 30d)."
_HISTORY_VERIFY_HELP: str = (
    "Recompute HMAC-SHA256 hash chain and report PASS or FAIL. "
    "Exits with code 1 if the chain is broken (tamper detected)."
)
_HISTORY_REPO_HELP: str = (
    "Filter by repository path (e.g. /home/user/my-repo). "
    "The path is SHA-256 hashed before comparison against stored repository_hash values."
)
_HISTORY_VIOLATIONS_ONLY_HELP: str = (
    "Show only scans where PHI findings were detected (is_clean=false)."
)
_DEFAULT_HISTORY_PERIOD: str = "30d"
_DAYS_PERIOD_SUFFIX: str = "d"
_HISTORY_PERIOD_FORMAT_ERROR: str = (
    "Period must be in the format '30d' (number of days), got {period!r}"
)
_NO_SCAN_HISTORY_MESSAGE: str = "No scan history found."
_HISTORY_ROW_FORMAT: str = "{scanned_at}  {status}  risk={risk_level}  files={files_scanned}"
_ZERO_FILES_SCANNED: int = 0

_NO_LAST_SCAN_MESSAGE: str = "No scan record found. Run `phi-scan scan` first."
_LAST_SCAN_HEADER: str = "Last scan result:"

_AUDIT_KEY_SCANNED_AT: str = "scanned_at"
_AUDIT_KEY_IS_CLEAN: str = "is_clean"
_AUDIT_KEY_RISK_LEVEL: str = "risk_level"
_AUDIT_KEY_FILES_SCANNED: str = "files_scanned"
_CLEAN_STATUS_LABEL: str = "CLEAN"
_VIOLATION_STATUS_LABEL: str = "VIOLATION"
_UNKNOWN_LABEL: str = "unknown"

_AUDIT_CHAIN_PASS_MESSAGE: str = "Audit chain integrity: PASS — all row hashes verified."
_AUDIT_CHAIN_FAIL_MESSAGE: str = (
    "Audit chain integrity: FAIL — one or more rows failed hash verification. "
    "The audit log may have been tampered with."
)
_AUDIT_CHAIN_SKIP_MESSAGE: str = (
    "Audit chain verification skipped — no audit key found. "
    "Run 'phi-scan setup' to generate the key."
)
_AUDIT_CHAIN_SKIPPED_ROWS_WARNING: str = (
    "Warning: {skipped_rows} row(s) had no chain hash and were not verified. "
    "Treat this audit as partially unverified."
)
_AUDIT_CHAIN_VERIFY_FLAG: str = "--verify"


def _parse_lookback_days(period: str) -> int:
    """Parse a period string like '30d' into an integer number of days."""
    if not period.endswith(_DAYS_PERIOD_SUFFIX):
        raise typer.BadParameter(_HISTORY_PERIOD_FORMAT_ERROR.format(period=period))
    day_count_str = period[: -len(_DAYS_PERIOD_SUFFIX)]
    if not day_count_str.isdigit():
        raise typer.BadParameter(_HISTORY_PERIOD_FORMAT_ERROR.format(period=period))
    return int(day_count_str)


def _display_scan_event_row(scan_event_record: dict[str, Any]) -> None:
    """Print a single audit scan event as a one-line summary."""
    scanned_at = scan_event_record.get(_AUDIT_KEY_SCANNED_AT, _UNKNOWN_LABEL)
    is_clean = scan_event_record.get(_AUDIT_KEY_IS_CLEAN, False)
    risk_level = scan_event_record.get(_AUDIT_KEY_RISK_LEVEL, _UNKNOWN_LABEL)
    files_scanned = scan_event_record.get(_AUDIT_KEY_FILES_SCANNED, _ZERO_FILES_SCANNED)
    status = _CLEAN_STATUS_LABEL if is_clean else _VIOLATION_STATUS_LABEL
    typer.echo(
        _HISTORY_ROW_FORMAT.format(
            scanned_at=scanned_at,
            status=status,
            risk_level=risk_level,
            files_scanned=files_scanned,
        )
    )


def _display_scan_history(scan_events: list[dict[str, Any]]) -> None:
    """Print a list of audit scan events, or a no-history message if empty."""
    if not scan_events:
        typer.echo(_NO_SCAN_HISTORY_MESSAGE)
        return
    for scan_event in scan_events:
        _display_scan_event_row(scan_event)


def display_last_scan() -> None:
    """Display the most recent scan result from the audit log."""
    database_path = Path(DEFAULT_DATABASE_PATH).expanduser()
    ensure_current_schema(database_path)
    last_scan_event = get_last_scan(database_path)
    if last_scan_event is None:
        typer.echo(_NO_LAST_SCAN_MESSAGE)
        return
    typer.echo(_LAST_SCAN_HEADER)
    _display_scan_event_row(last_scan_event)


def display_history(
    last: Annotated[str, typer.Option("--last", help=_HISTORY_LAST_HELP)] = _DEFAULT_HISTORY_PERIOD,
    should_verify: Annotated[
        bool, typer.Option(_AUDIT_CHAIN_VERIFY_FLAG, help=_HISTORY_VERIFY_HELP)
    ] = False,
    repository_path: Annotated[str | None, typer.Option("--repo", help=_HISTORY_REPO_HELP)] = None,
    should_show_violations_only: Annotated[
        bool, typer.Option("--violations-only", help=_HISTORY_VIOLATIONS_ONLY_HELP)
    ] = False,
) -> None:
    """Query the audit log for recent scan history."""
    lookback_days = _parse_lookback_days(last)
    database_path = Path(DEFAULT_DATABASE_PATH).expanduser()
    ensure_current_schema(database_path)
    if should_verify:
        verify_result: ChainVerifyResult = verify_audit_chain(database_path)
        if not verify_result.key_present:
            typer.echo(_AUDIT_CHAIN_SKIP_MESSAGE, err=True)
        elif verify_result.is_intact:
            typer.echo(_AUDIT_CHAIN_PASS_MESSAGE)
            if verify_result.skipped_rows > 0:
                typer.echo(
                    _AUDIT_CHAIN_SKIPPED_ROWS_WARNING.format(
                        skipped_rows=verify_result.skipped_rows
                    ),
                    err=True,
                )
        else:
            typer.echo(_AUDIT_CHAIN_FAIL_MESSAGE, err=True)
            raise typer.Exit(code=EXIT_CODE_VIOLATION)
    repository_hash = (
        hashlib.sha256(repository_path.encode("utf-8")).hexdigest() if repository_path else None
    )
    scan_events = query_recent_scans(
        database_path,
        lookback_days,
        repository_hash=repository_hash,
        should_show_violations_only=should_show_violations_only,
    )
    _display_scan_history(scan_events)
