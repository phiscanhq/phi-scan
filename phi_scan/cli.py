"""Typer CLI entry point for PhiScan."""

from __future__ import annotations

import dataclasses
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.live import Live
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from phi_scan import __version__
from phi_scan.audit import (
    create_audit_schema,
    get_last_scan,
    insert_scan_event,
    query_recent_scans,
)
from phi_scan.config import create_default_config, load_config
from phi_scan.constants import (
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_DATABASE_PATH,
    DEFAULT_IGNORE_FILENAME,
    DEFAULT_TEXT_ENCODING,
    EXIT_CODE_CLEAN,
    EXIT_CODE_VIOLATION,
    OutputFormat,
    SeverityLevel,
)
from phi_scan.diff import get_changed_files_from_diff
from phi_scan.exceptions import AuditLogError, ConfigurationError
from phi_scan.logging_config import get_logger, replace_logger_handlers
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.output import (
    WatchEvent,
    build_dashboard_layout,
    build_watch_layout,
    create_scan_progress,
    display_banner,
    display_category_breakdown,
    display_clean_result,
    display_clean_summary_panel,
    display_code_context_panel,
    display_exit_code_message,
    display_file_tree,
    display_file_type_summary,
    display_findings_table,
    display_phase_audit,
    display_phase_collecting,
    display_phase_report,
    display_phase_scanning,
    display_risk_level_badge,
    display_scan_header,
    display_severity_inline,
    display_status_spinner,
    display_violation_alert,
    display_violation_summary_panel,
    format_csv,
    format_json,
    format_sarif,
)
from phi_scan.scanner import (
    build_scan_result,
    collect_scan_targets,
    execute_scan,
    load_ignore_patterns,
    scan_file,
)

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["app"]

_logger: logging.Logger = get_logger("cli")

# ---------------------------------------------------------------------------
# App and sub-app definitions
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="phi-scan",
    help="PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only.",
    no_args_is_help=True,
)

config_app = typer.Typer(name="config", help="Manage PhiScan configuration.")
app.add_typer(config_app)

# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------

_VERSION_OUTPUT_FORMAT: str = "phi-scan {version}"
_VERSION_FLAG_HELP: str = "Show version and exit."

# ---------------------------------------------------------------------------
# Scan command help strings
# ---------------------------------------------------------------------------

_SCAN_PATH_HELP: str = "Directory or file to scan. Defaults to the current directory."
_SCAN_DIFF_HELP: str = "Scan only files changed since the given git ref (e.g. HEAD~1)."
_SCAN_FILE_HELP: str = "Scan a single file with detailed output."
_SCAN_OUTPUT_HELP: str = "Output format: table, json, sarif, csv (pdf/html/junit in Phase 3)."
_SCAN_CONFIG_HELP: str = "Path to .phi-scanner.yml. Defaults to .phi-scanner.yml in CWD."
_SCAN_SEVERITY_HELP: str = "Minimum severity threshold: info, low, medium, high."
_SCAN_LOG_LEVEL_HELP: str = "Logging verbosity: debug, info, warning, error."
_SCAN_LOG_FILE_HELP: str = "Write structured logs to this file in addition to stderr."
_SCAN_QUIET_HELP: str = "Suppress all terminal output. Exit code still reflects findings."
_SCAN_NO_CACHE_HELP: str = (
    "Bypass the content-hash scan cache. No-op in Phase 1; active from Phase 2."
)

# ---------------------------------------------------------------------------
# Watch command
# ---------------------------------------------------------------------------

_WATCH_PATH_HELP: str = "Directory to watch for file system changes."
_WATCH_POLL_INTERVAL_SECONDS: float = 1.0
_WATCH_LIVE_REFRESH_RATE: float = 4.0
_WATCH_LOG_MAX_EVENTS: int = 10
_WATCH_TIMESTAMP_FORMAT: str = "%H:%M:%S"
_WATCH_RESULT_CLEAN_TEXT: str = "✅ Clean"
_WATCH_RESULT_VIOLATION_FORMAT: str = "⚠  {count} findings detected"
_WATCH_RESULT_CLEAN_STYLE: str = "bold green"
_WATCH_RESULT_VIOLATION_STYLE: str = "bold red"

# ---------------------------------------------------------------------------
# History command
# ---------------------------------------------------------------------------

_HISTORY_LAST_HELP: str = "Show scans from the last N days (e.g. 30d)."
_DEFAULT_HISTORY_PERIOD: str = "30d"
_DAYS_PERIOD_SUFFIX: str = "d"
_HISTORY_PERIOD_FORMAT_ERROR: str = (
    "Period must be in the format '30d' (number of days), got {period!r}"
)
_NO_SCAN_HISTORY_MESSAGE: str = "No scan history found."
_HISTORY_ROW_FORMAT: str = "{scanned_at}  {status}  risk={risk_level}  files={files_scanned}"
_ZERO_FILES_SCANNED: int = 0

# ---------------------------------------------------------------------------
# Report command
# ---------------------------------------------------------------------------

_NO_LAST_SCAN_MESSAGE: str = "No scan record found. Run `phi-scan scan` first."
_LAST_SCAN_HEADER: str = "Last scan result:"

# ---------------------------------------------------------------------------
# Audit event dict keys (matching column names in the audit SQLite schema)
# ---------------------------------------------------------------------------

_AUDIT_KEY_SCANNED_AT: str = "scanned_at"
_AUDIT_KEY_IS_CLEAN: str = "is_clean"
_AUDIT_KEY_RISK_LEVEL: str = "risk_level"
_AUDIT_KEY_FILES_SCANNED: str = "files_scanned"
_CLEAN_STATUS_LABEL: str = "CLEAN"
_VIOLATION_STATUS_LABEL: str = "VIOLATION"
_UNKNOWN_LABEL: str = "unknown"

# ---------------------------------------------------------------------------
# Install / uninstall hook
# ---------------------------------------------------------------------------

_PRE_COMMIT_HOOK_PATH: str = ".git/hooks/pre-commit"
_HOOK_INSTALLED_MESSAGE: str = "Pre-commit hook installed: {path}"
_HOOK_ALREADY_EXISTS_MESSAGE: str = (
    "Pre-commit hook already exists at {path} — not overwriting. "
    "Remove it manually or run `phi-scan uninstall-hook` first."
)
_HOOK_REMOVED_MESSAGE: str = "Pre-commit hook removed: {path}"
_HOOK_NOT_FOUND_MESSAGE: str = "No phi-scan hook found at {path}."
_HOOK_NOT_OURS_MESSAGE: str = "Hook at {path} was not installed by phi-scan — not removing."
_HOOK_IS_SYMLINK_MESSAGE: str = "Hook at {path} is a symlink — not reading or removing."
_HOOK_SYMLINKED_COMPONENT_ERROR: str = (
    "Hook path component {component!r} is a symlink — refusing to write."
)
# Marker written into every hook we install; used to identify our hooks on uninstall.
_HOOK_MARKER: str = "phi-scan scan"
_HOOK_FILE_PERMISSIONS: int = 0o755
_HOOK_SCRIPT_CONTENT: str = (
    "#!/bin/sh\n"
    "# phi-scan pre-commit hook — installed by phi-scan install-hook\n"
    "phi-scan scan --diff HEAD --quiet\n"
    "if [ $? -ne 0 ]; then\n"
    "  echo 'phi-scan: PHI/PII detected — commit blocked'\n"
    "  exit 1\n"
    "fi\n"
)

# ---------------------------------------------------------------------------
# Config sub-app
# ---------------------------------------------------------------------------

_CONFIG_CREATED_MESSAGE: str = "Configuration file created: {path}"
_CONFIG_ALREADY_EXISTS_MESSAGE: str = "Config file already exists at {path} — not overwriting."

# ---------------------------------------------------------------------------
# Stub messages for Phase 2+ features
# ---------------------------------------------------------------------------

_INIT_STUB_MESSAGE: str = (
    "phi-scan init: full guided setup wizard is coming in Phase 1C. "
    "Run `phi-scan config init` to generate a config file now."
)
_SETUP_STUB_MESSAGE: str = (
    "phi-scan setup downloads spaCy NLP models. "
    "Run `pip install phi-scan[nlp]` first, then re-run (available from Phase 2)."
)
_DASHBOARD_REFRESH_SECONDS: float = 2.0
_DASHBOARD_REFRESH_RATE: float = 4.0
_DASHBOARD_HISTORY_COUNT: int = 10
_DASHBOARD_LOOKBACK_DAYS: int = 30
_DASHBOARD_FINDINGS_JSON_KEY: str = "findings_json"
_DASHBOARD_CATEGORY_KEY: str = "hipaa_category"
_DASHBOARD_UNKNOWN_CATEGORY: str = "unknown"
# Sentinel used when a scan row has no findings_json blob — parse as empty list.
_DASHBOARD_EMPTY_FINDINGS_JSON: str = "[]"

_SPINNER_CONFIG_LOAD_MESSAGE: str = "Loading configuration…"
_SPINNER_AUDIT_WRITE_MESSAGE: str = "Writing audit log…"

# Maximum characters of a file path shown in the progress bar description column.
# Longer paths are truncated with a leading ellipsis so the bar layout stays stable.
_PROGRESS_FILENAME_MAX_CHARS: int = 38
_PROGRESS_FILENAME_ELLIPSIS: str = "…"

# ---------------------------------------------------------------------------
# Error and warning messages
# ---------------------------------------------------------------------------

_CONFIG_LOAD_FAILURE_WARNING: str = (
    "Config file {path!r} exists but could not be loaded — using defaults: {error}"
)
_AUDIT_WRITE_FAILURE_WARNING: str = "Audit log write failed — scan result not persisted: {error}"
_UNSUPPORTED_OUTPUT_FORMAT_ERROR: str = (
    "Output format {fmt!r} is not supported in Phase 1. Supported: table, json, csv, sarif."
)
_INVALID_SEVERITY_THRESHOLD_ERROR: str = (
    "Invalid severity threshold {value!r}. Accepted values: info, low, medium, high."
)

# ---------------------------------------------------------------------------
# Log level configuration
# ---------------------------------------------------------------------------

_LOG_LEVEL_DEBUG: str = "debug"
_LOG_LEVEL_INFO: str = "info"
_LOG_LEVEL_WARNING: str = "warning"
_LOG_LEVEL_ERROR: str = "error"

_LOG_LEVEL_MAP: dict[str, int] = {
    _LOG_LEVEL_DEBUG: logging.DEBUG,
    _LOG_LEVEL_INFO: logging.INFO,
    _LOG_LEVEL_WARNING: logging.WARNING,
    _LOG_LEVEL_ERROR: logging.ERROR,
}

# ---------------------------------------------------------------------------
# Output format serializer dispatch table
# ---------------------------------------------------------------------------

_FORMAT_SERIALIZERS: dict[str, Callable[[ScanResult], str]] = {
    OutputFormat.JSON.value: format_json,
    OutputFormat.CSV.value: format_csv,
    OutputFormat.SARIF.value: format_sarif,
}

# ---------------------------------------------------------------------------
# Internal error exit code (distinct from VIOLATION — means CLI/config error)
# ---------------------------------------------------------------------------

_EXIT_CODE_ERROR: int = 2
_RGLOB_ALL_FILES_PATTERN: str = "*"

# ---------------------------------------------------------------------------
# Watch file-count helper and event handler
# ---------------------------------------------------------------------------


def _count_files_in_directory(directory: Path) -> int:
    """Return the number of regular files under directory (non-recursive cap is not applied).

    Args:
        directory: Root directory to traverse.

    Returns:
        Count of all regular files found via rglob.
    """
    return sum(
        1
        for candidate in directory.rglob(_RGLOB_ALL_FILES_PATTERN)
        if candidate.is_file() and not candidate.is_symlink()
    )


class _FileChangeMonitor(FileSystemEventHandler):
    """Watchdog event handler — appends a watch event to the rolling log on each file change.

    Phase 1: scan_file returns no findings so result is always clean. The Phase 1
    note is displayed in the watch header; per-event result shows the actual outcome.
    """

    def __init__(
        self,
        watch_root: Path,
        watch_events: deque[WatchEvent],
        scan_config: ScanConfig,
    ) -> None:
        super().__init__()
        self._watch_root = watch_root
        self._watch_events = watch_events
        self._scan_config = scan_config

    def on_any_event(self, event: FileSystemEvent) -> None:
        """Append a timestamped event record on any non-directory file change.

        Args:
            event: The watchdog file system event.
        """
        if event.is_directory:
            return
        changed_path = Path(str(event.src_path))
        # HIPAA traversal rule: never follow symlinks — a watchdog event can fire
        # for a symlinked path, which could point outside the watched directory and
        # expose files containing PHI that were never intended to be scanned.
        if changed_path.is_symlink():
            return
        _append_watch_event(changed_path, self._watch_events, self._scan_config)


# ---------------------------------------------------------------------------
# Internal helpers — scan command
# ---------------------------------------------------------------------------


@dataclass
class _ScanTargetOptions:
    """Options that control which files are selected for scanning.

    Groups four related inputs so _resolve_scan_targets stays within the
    three-argument limit required by CLAUDE.md.
    """

    scan_root: Path
    diff_ref: str | None
    single_file: Path | None
    config: ScanConfig


def _configure_logging(log_level: str, log_file: Path | None, is_quiet: bool) -> None:
    """Apply logging configuration from CLI flags.

    Args:
        log_level: One of debug, info, warning, error.
        log_file: Optional path for a rotating file handler.
        is_quiet: Suppress console output when True.
    """
    level = _LOG_LEVEL_MAP.get(log_level.lower(), logging.WARNING)
    replace_logger_handlers(console_level=level, log_file_path=log_file, is_quiet=is_quiet)


def _load_scan_config(config_path: Path | None, severity_threshold: str | None) -> ScanConfig:
    """Load ScanConfig from file, applying a CLI severity override if provided.

    A missing or unreadable config file is not an error in Phase 1 — defaults
    are used so `phi-scan scan .` works out of the box without any config file.

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
        scan_config = ScanConfig()
    if severity_threshold is None:
        return scan_config
    try:
        parsed_severity = SeverityLevel(severity_threshold.lower())
    except ValueError:
        typer.echo(_INVALID_SEVERITY_THRESHOLD_ERROR.format(value=severity_threshold), err=True)
        raise typer.Exit(code=_EXIT_CODE_ERROR)
    return dataclasses.replace(scan_config, severity_threshold=parsed_severity)


def _resolve_scan_targets(options: _ScanTargetOptions) -> list[Path]:
    """Return the list of files to scan based on the mode flags in options.

    Priority order: --file > --diff > directory traversal.

    Args:
        options: Grouped scan target options (root, diff ref, single file, config).

    Returns:
        Ordered list of file paths to pass to execute_scan.
    """
    if options.single_file is not None:
        return [options.single_file]
    if options.diff_ref is not None:
        return get_changed_files_from_diff(options.diff_ref)
    ignore_patterns = load_ignore_patterns(Path(DEFAULT_IGNORE_FILENAME))
    if options.config.exclude_paths:
        ignore_patterns.extend(options.config.exclude_paths)
    return collect_scan_targets(options.scan_root, ignore_patterns, options.config)


def _truncate_filename_for_progress(file_path: Path) -> str:
    """Return the file path as a string, truncated to fit the progress bar column.

    Args:
        file_path: Path to the file currently being scanned.

    Returns:
        Path string, truncated with a leading ellipsis when over the column width.
    """
    # as_posix() normalises to forward slashes on all platforms — consistent
    # display in progress bars regardless of OS path separator.
    path_string = file_path.as_posix()
    if len(path_string) <= _PROGRESS_FILENAME_MAX_CHARS:
        return path_string
    return _PROGRESS_FILENAME_ELLIPSIS + path_string[-_PROGRESS_FILENAME_MAX_CHARS:]


def _execute_scan_with_progress(
    scan_targets: list[Path],
    config: ScanConfig,
    should_show_progress: bool,
) -> ScanResult:
    """Run the scan loop, showing a Rich progress bar when should_show_progress is True.

    The progress bar is suppressed for machine-readable output formats (json/csv/sarif)
    and for --quiet mode, since terminal decoration must not appear in serialized output.

    Args:
        scan_targets: Files to scan, as returned by _resolve_scan_targets.
        config: Active scan configuration.
        should_show_progress: Show the Rich progress bar when True.

    Returns:
        Aggregated ScanResult for all scanned files.
    """
    if not should_show_progress:
        return execute_scan(scan_targets, config)
    all_findings: list[ScanFinding] = []
    scan_start = time.monotonic()
    with create_scan_progress(total_files=len(scan_targets)) as (progress, task_id):
        for file_path in scan_targets:
            progress_label = _truncate_filename_for_progress(file_path)
            progress.update(task_id, description=progress_label, advance=1)
            all_findings.extend(scan_file(file_path, config))
    scan_duration = time.monotonic() - scan_start
    return build_scan_result(tuple(all_findings), len(scan_targets), scan_duration)


def _write_audit_record(scan_result: ScanResult, database_path: Path) -> None:
    """Persist the scan result to the SQLite audit log.

    Audit failures are logged as warnings and do not abort the scan.
    HIPAA §164.530(j) requires best-effort audit retention — a write failure
    must be surfaced to operators but must not block the CI gate decision.

    Args:
        scan_result: The completed scan result to persist.
        database_path: Path to the SQLite audit database (may include ~).
    """
    resolved_path = database_path.expanduser()
    try:
        create_audit_schema(resolved_path)
        insert_scan_event(resolved_path, scan_result)
    except AuditLogError as audit_error:
        _logger.warning(_AUDIT_WRITE_FAILURE_WARNING.format(error=audit_error))


def _display_rich_scan_results(scan_result: ScanResult) -> None:
    """Render the full Rich terminal UI for a completed scan.

    Only called when in Rich/table mode. Callers are responsible for
    checking is_rich_mode before calling this function.

    Args:
        scan_result: The completed scan result.
    """
    if scan_result.findings:
        display_violation_alert(scan_result)
        display_risk_level_badge(scan_result)
        display_severity_inline(scan_result)
        display_category_breakdown(scan_result)
        display_file_tree(scan_result.findings)
        for finding in scan_result.findings:
            display_code_context_panel(finding)
        display_findings_table(scan_result.findings)
        display_violation_summary_panel(scan_result)
        display_exit_code_message(is_clean=False)
    else:
        display_clean_result()
        display_clean_summary_panel(scan_result)
        display_exit_code_message(is_clean=True)


def _emit_scan_output(scan_result: ScanResult, output_format: str, is_rich_mode: bool) -> None:
    """Render or serialize scan results in the requested output format.

    For table format in Rich mode, delegates to _display_rich_scan_results.
    For serialized formats (json/csv/sarif), writes to stdout via typer.echo
    regardless of is_rich_mode — the caller suppresses the call entirely for
    --quiet mode.

    Args:
        scan_result: The completed scan result.
        output_format: One of table, json, csv, sarif (others unsupported in Phase 1).
        is_rich_mode: True when table format and not quiet — activates the Rich UI path.

    Raises:
        typer.Exit: If output_format is not supported in Phase 1.
    """
    if output_format == OutputFormat.TABLE.value:
        if is_rich_mode:
            _display_rich_scan_results(scan_result)
        return
    serializer = _FORMAT_SERIALIZERS.get(output_format)
    if serializer is None:
        typer.echo(_UNSUPPORTED_OUTPUT_FORMAT_ERROR.format(fmt=output_format), err=True)
        raise typer.Exit(code=_EXIT_CODE_ERROR)
    typer.echo(serializer(scan_result))


# ---------------------------------------------------------------------------
# Internal helpers — history and report commands
# ---------------------------------------------------------------------------


def _parse_lookback_days(period: str) -> int:
    """Parse a period string like '30d' into an integer number of days.

    Args:
        period: A string ending in 'd' with a positive integer prefix.

    Returns:
        Number of lookback days as an integer.

    Raises:
        typer.BadParameter: If period is not in the expected format.
    """
    if not period.endswith(_DAYS_PERIOD_SUFFIX):
        raise typer.BadParameter(_HISTORY_PERIOD_FORMAT_ERROR.format(period=period))
    day_count_str = period[: -len(_DAYS_PERIOD_SUFFIX)]
    if not day_count_str.isdigit():
        raise typer.BadParameter(_HISTORY_PERIOD_FORMAT_ERROR.format(period=period))
    return int(day_count_str)


def _display_scan_event_row(scan_event_record: dict[str, Any]) -> None:
    """Print a single audit scan event as a one-line summary.

    Args:
        scan_event_record: Audit row dict as returned by get_last_scan or query_recent_scans.
    """
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
    """Print a list of audit scan events, or a no-history message if empty.

    Args:
        scan_events: List of audit row dicts from query_recent_scans.
    """
    if not scan_events:
        typer.echo(_NO_SCAN_HISTORY_MESSAGE)
        return
    for scan_event in scan_events:
        _display_scan_event_row(scan_event)


# ---------------------------------------------------------------------------
# Internal helpers — install-hook / uninstall-hook
# ---------------------------------------------------------------------------


def _reject_hook_path_with_symlinked_component(hook_path: Path) -> None:
    """Reject if any existing ancestor directory of hook_path is itself a symlink.

    Walks each path component individually instead of calling Path.resolve(),
    which would follow symlinks — prohibited by the security policy. A symlinked
    .git directory (common in git worktrees) would redirect hook writes to an
    unintended location; this guard catches that before any write occurs.

    Args:
        hook_path: The hook file path to validate before writing.

    Raises:
        typer.Exit: If any ancestor directory component is a symlink.
    """
    for ancestor in reversed(list(hook_path.parents)):
        if ancestor.is_symlink():
            typer.echo(
                _HOOK_SYMLINKED_COMPONENT_ERROR.format(component=str(ancestor)),
                err=True,
            )
            raise typer.Exit(code=_EXIT_CODE_ERROR)


# ---------------------------------------------------------------------------
# Internal helpers — watch command
# ---------------------------------------------------------------------------


def _append_watch_event(
    changed_path: Path,
    watch_events: deque[WatchEvent],
    scan_config: ScanConfig,
) -> None:
    """Scan changed_path, build a WatchEvent record, and append it to the deque.

    Args:
        changed_path: The file that changed, already confirmed non-symlink.
        watch_events: Rolling deque shared between the watchdog thread and main thread.
        scan_config: Scanner configuration used for the per-file scan.
    """
    findings = scan_file(changed_path, scan_config)
    result_text, result_style = _build_watch_result(findings)
    watch_events.append(
        WatchEvent(
            time=datetime.now().strftime(_WATCH_TIMESTAMP_FORMAT),
            file_path=str(changed_path),
            result_text=result_text,
            result_style=result_style,
        )
    )


def _build_watch_result(findings: list[ScanFinding]) -> tuple[str, str]:
    """Return display text and Rich style for a per-file watch scan result.

    Phase 1: scan_file always returns an empty list, so this always returns
    the inactive result. Phase 2+ will surface real finding counts.

    Args:
        findings: Findings returned by scan_file for the changed file.

    Returns:
        Tuple of (result_text, result_style) for the rolling event table.
    """
    if findings:
        text = _WATCH_RESULT_VIOLATION_FORMAT.format(count=len(findings))
        return text, _WATCH_RESULT_VIOLATION_STYLE
    return _WATCH_RESULT_CLEAN_TEXT, _WATCH_RESULT_CLEAN_STYLE


def _run_watch_live_loop(
    watch_path: Path,
    watch_events: deque[WatchEvent],
) -> None:
    """Drive the Rich Live display loop until Ctrl+C.

    Ctrl+C (KeyboardInterrupt) is the expected exit mechanism for watch mode —
    caught here to stop the Rich Live display cleanly before process exit.

    Args:
        watch_path: The watched directory, shown in the persistent header.
        watch_events: Shared deque updated by _FileChangeMonitor on the watchdog thread.
    """
    try:
        with Live(refresh_per_second=_WATCH_LIVE_REFRESH_RATE, screen=True) as live:
            while True:
                live.update(build_watch_layout(watch_path, list(watch_events)))
                time.sleep(_WATCH_POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        # Ctrl+C is the standard exit for watch mode — caught here to suppress the
        # default traceback and allow Rich to close the screen buffer cleanly.
        return


# ---------------------------------------------------------------------------
# --version callback
# ---------------------------------------------------------------------------


def _echo_version(is_version_requested: bool) -> None:
    """Print the installed phi-scan version and exit.

    Args:
        is_version_requested: True when --version / -V was passed.
    """
    if is_version_requested:
        typer.echo(_VERSION_OUTPUT_FORMAT.format(version=__version__))
        raise typer.Exit()


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@app.callback()
def main_callback(
    is_version_requested: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_echo_version,
            is_eager=True,
            help=_VERSION_FLAG_HELP,
        ),
    ] = False,
) -> None:
    """PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help=_SCAN_PATH_HELP)] = Path("."),
    diff_ref: Annotated[str | None, typer.Option("--diff", help=_SCAN_DIFF_HELP)] = None,
    single_file: Annotated[Path | None, typer.Option("--file", help=_SCAN_FILE_HELP)] = None,
    output_format: Annotated[
        str, typer.Option("--output", "-o", help=_SCAN_OUTPUT_HELP)
    ] = OutputFormat.TABLE.value,
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help=_SCAN_CONFIG_HELP)
    ] = None,
    severity_threshold: Annotated[
        str | None, typer.Option("--severity-threshold", help=_SCAN_SEVERITY_HELP)
    ] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help=_SCAN_LOG_LEVEL_HELP)
    ] = _LOG_LEVEL_WARNING,
    log_file: Annotated[Path | None, typer.Option("--log-file", help=_SCAN_LOG_FILE_HELP)] = None,
    is_quiet: Annotated[bool, typer.Option("--quiet", "-q", help=_SCAN_QUIET_HELP)] = False,
    should_bypass_cache: Annotated[
        bool, typer.Option("--no-cache", help=_SCAN_NO_CACHE_HELP)
    ] = False,
) -> None:
    """Scan a directory or file for PHI/PII.

    Parameters are Typer CLI declarations, not regular call-site arguments — the
    3-argument rule from CLAUDE.md applies to regular functions, not CLI commands
    whose parameters are read by Typer introspection. Scan target parameters are
    immediately packed into _ScanTargetOptions below. Rich UI (banner, progress,
    results table) is suppressed for serialised formats (json/csv/sarif) to keep
    stdout clean for pipe and file consumption.
    """
    _configure_logging(log_level, log_file, is_quiet)
    is_rich_mode = not is_quiet and output_format == OutputFormat.TABLE.value
    with display_status_spinner(_SPINNER_CONFIG_LOAD_MESSAGE, is_active=is_rich_mode):
        scan_config = _load_scan_config(config_path, severity_threshold)
    target_options = _ScanTargetOptions(
        scan_root=path,
        diff_ref=diff_ref,
        single_file=single_file,
        config=scan_config,
    )
    if is_rich_mode:
        display_banner()
        display_scan_header(path, scan_config)
        display_phase_collecting()
    scan_targets = _resolve_scan_targets(target_options)
    if is_rich_mode:
        display_file_type_summary(scan_targets)
        display_phase_scanning()
    scan_result = _execute_scan_with_progress(scan_targets, scan_config, is_rich_mode)
    if is_rich_mode:
        display_phase_audit()
    with display_status_spinner(_SPINNER_AUDIT_WRITE_MESSAGE, is_active=is_rich_mode):
        _write_audit_record(scan_result, scan_config.database_path)
    if not is_quiet and is_rich_mode:
        display_phase_report()
    if not is_quiet:
        _emit_scan_output(scan_result, output_format, is_rich_mode)
    raise typer.Exit(code=EXIT_CODE_CLEAN if scan_result.is_clean else EXIT_CODE_VIOLATION)


@app.command()
def watch(
    path: Annotated[Path, typer.Argument(help=_WATCH_PATH_HELP)] = Path("."),
) -> None:
    """Watch a directory and re-scan changed files. Detection active from Phase 2."""
    watch_path = path.resolve()
    if not watch_path.exists():
        raise typer.BadParameter(f"Path does not exist: {watch_path}", param_hint="'PATH'")
    if not watch_path.is_dir():
        raise typer.BadParameter(f"Path is not a directory: {watch_path}", param_hint="'PATH'")
    scan_config = ScanConfig()
    watch_events: deque[WatchEvent] = deque(maxlen=_WATCH_LOG_MAX_EVENTS)
    event_handler = _FileChangeMonitor(watch_path, watch_events, scan_config)
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)
    observer.start()
    try:
        _run_watch_live_loop(watch_path, watch_events)
    finally:
        observer.stop()
        observer.join()


@app.command("report")
def display_last_scan() -> None:
    """Display the most recent scan result from the audit log."""
    database_path = Path(DEFAULT_DATABASE_PATH).expanduser()
    create_audit_schema(database_path)
    last_scan_event = get_last_scan(database_path)
    if last_scan_event is None:
        typer.echo(_NO_LAST_SCAN_MESSAGE)
        return
    typer.echo(_LAST_SCAN_HEADER)
    _display_scan_event_row(last_scan_event)


@app.command("history")
def display_history(
    last: Annotated[str, typer.Option("--last", help=_HISTORY_LAST_HELP)] = _DEFAULT_HISTORY_PERIOD,
) -> None:
    """Query the audit log for recent scan history."""
    lookback_days = _parse_lookback_days(last)
    database_path = Path(DEFAULT_DATABASE_PATH).expanduser()
    create_audit_schema(database_path)
    scan_events = query_recent_scans(database_path, lookback_days)
    _display_scan_history(scan_events)


@app.command("install-hook")
def install_hook() -> None:
    """Install phi-scan as a git pre-commit hook."""
    hook_path = Path(_PRE_COMMIT_HOOK_PATH)
    if hook_path.exists() or hook_path.is_symlink():
        typer.echo(_HOOK_ALREADY_EXISTS_MESSAGE.format(path=hook_path))
        return
    _reject_hook_path_with_symlinked_component(hook_path)
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_HOOK_SCRIPT_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
    hook_path.chmod(_HOOK_FILE_PERMISSIONS)
    typer.echo(_HOOK_INSTALLED_MESSAGE.format(path=hook_path))


@app.command("uninstall-hook")
def uninstall_hook() -> None:
    """Remove the phi-scan git pre-commit hook."""
    hook_path = Path(_PRE_COMMIT_HOOK_PATH)
    if not hook_path.exists():
        typer.echo(_HOOK_NOT_FOUND_MESSAGE.format(path=hook_path))
        return
    if hook_path.is_symlink():
        typer.echo(_HOOK_IS_SYMLINK_MESSAGE.format(path=hook_path))
        return
    hook_content = hook_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    if _HOOK_MARKER not in hook_content:
        typer.echo(_HOOK_NOT_OURS_MESSAGE.format(path=hook_path))
        return
    hook_path.unlink()
    typer.echo(_HOOK_REMOVED_MESSAGE.format(path=hook_path))


@app.command("init")
def initialize_project() -> None:
    """Guided first-run wizard: config, ignore file, hook, model download."""
    typer.echo(_INIT_STUB_MESSAGE)


@app.command("setup")
def download_models() -> None:
    """Download spaCy NLP models and verify optional dependencies."""
    typer.echo(_SETUP_STUB_MESSAGE)


def _aggregate_category_totals(recent_scans: list[dict[str, Any]]) -> dict[str, int]:
    """Sum HIPAA category occurrences across all recent scan findings_json blobs.

    PHI safety guarantee: findings_json blobs written by audit.py contain only
    value_hash (SHA-256), file_path_hash (SHA-256), hipaa_category, severity,
    confidence, and line_number. Raw PHI values and code_context are explicitly
    excluded at the write path (see audit.py::_serialize_finding_for_storage).
    This function reads category metadata only — no raw PHI is ever present.

    Args:
        recent_scans: Scan rows from the audit DB as returned by query_recent_scans.

    Returns:
        Mapping of HIPAA category value string to total finding count.
    """
    totals: dict[str, int] = {}
    for row in recent_scans:
        category_finding_records = json.loads(
            row.get(_DASHBOARD_FINDINGS_JSON_KEY, _DASHBOARD_EMPTY_FINDINGS_JSON)
        )
        for finding_record in category_finding_records:
            category = finding_record.get(_DASHBOARD_CATEGORY_KEY, _DASHBOARD_UNKNOWN_CATEGORY)
            totals[category] = totals.get(category, 0) + 1
    return totals


@app.command("dashboard")
def display_dashboard() -> None:
    """Rich Live real-time scan dashboard.

    Ctrl+C (KeyboardInterrupt) is the expected and only exit mechanism for this
    command. The signal is caught here as an intentional boundary — not a domain
    error — solely to stop the Rich Live display cleanly before process exit.
    """
    database_path = Path(DEFAULT_DATABASE_PATH)
    try:
        with Live(refresh_per_second=_DASHBOARD_REFRESH_RATE, screen=True) as live:
            while True:
                recent_scans = query_recent_scans(database_path, _DASHBOARD_LOOKBACK_DAYS)
                last_scan = get_last_scan(database_path)
                category_totals = _aggregate_category_totals(recent_scans)
                layout = build_dashboard_layout(
                    recent_scans[:_DASHBOARD_HISTORY_COUNT],
                    category_totals,
                    last_scan,
                )
                live.update(layout)
                time.sleep(_DASHBOARD_REFRESH_SECONDS)
    except KeyboardInterrupt:
        # Ctrl+C is the standard exit for a live dashboard — caught here to
        # suppress the default traceback and allow Rich to close the screen buffer.
        raise typer.Exit(code=EXIT_CODE_CLEAN)


@config_app.command("init")
def initialize_config() -> None:
    """Generate a default .phi-scanner.yml configuration file."""
    config_file_path = Path(DEFAULT_CONFIG_FILENAME)
    if config_file_path.exists():
        typer.echo(_CONFIG_ALREADY_EXISTS_MESSAGE.format(path=config_file_path))
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    create_default_config(config_file_path)
    typer.echo(_CONFIG_CREATED_MESSAGE.format(path=config_file_path))
