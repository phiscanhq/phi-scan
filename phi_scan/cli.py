"""Typer CLI entry point for PhiScan."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, NoReturn

import pathspec
import typer
from rich.live import Live
from rich.progress import Progress, TaskID
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from phi_scan import __version__
from phi_scan.audit import (
    ChainVerifyResult,
    ensure_current_schema,
    get_last_scan,
    insert_scan_event,
    query_recent_scans,
    verify_audit_chain,
)
from phi_scan.baseline import (
    BaselineSnapshot,
    filter_baselined_findings,
    load_baseline,
)
from phi_scan.ci_integration import (
    CIIntegrationError,
    create_azure_boards_work_item,
    get_pr_context,
    import_findings_to_security_hub,
    post_bitbucket_code_insights,
    post_pr_comment,
    set_azure_build_tag,
    set_azure_pr_status,
    set_commit_status,
    upload_sarif_to_github,
)
from phi_scan.cli_baseline import baseline_app
from phi_scan.cli_config import config_app
from phi_scan.cli_explain import explain_app
from phi_scan.cli_scan_config import load_scan_config
from phi_scan.compliance import (
    ComplianceFramework,
    InvalidFrameworkError,
    annotate_findings,
    parse_framework_flag,
)
from phi_scan.constants import (
    BASELINE_LOAD_ERROR_MESSAGE,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_DATABASE_PATH,
    DEFAULT_IGNORE_FILENAME,
    DEFAULT_TEXT_ENCODING,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    EXIT_CODE_VIOLATION,
    IMPLEMENTED_OUTPUT_FORMATS,
    OutputFormat,
    PathspecMatchStyle,
)
from phi_scan.diff import get_changed_files_from_diff
from phi_scan.exceptions import (
    AuditKeyMissingError,
    AuditLogError,
    BaselineError,
    MissingOptionalDependencyError,
    NotificationError,
)
from phi_scan.fixer import (
    FixMode,
    FixReplacement,
    FixResult,
    apply_approved_replacements,
    collect_file_replacements,
    fix_file,
)
from phi_scan.logging_config import get_logger, replace_logger_handlers
from phi_scan.models import ScanConfig, ScanFinding, ScanResult
from phi_scan.notifier import (
    NotificationRequest,
    send_email_notification,
    send_webhook_notification,
)
from phi_scan.output import (
    WATCH_RESULT_CLEAN_TEXT,
    WATCH_RESULT_VIOLATION_FORMAT,
    WatchEvent,
    build_dashboard_layout,
    build_watch_layout,
    create_scan_progress,
    display_banner,
    display_baseline_scan_notice,
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
    format_codequality,
    format_csv,
    format_gitlab_sast,
    format_json,
    format_junit,
    format_sarif,
    get_console,
)
from phi_scan.report import generate_html_report, generate_pdf_report
from phi_scan.scanner import (
    MAX_WORKER_COUNT,
    build_scan_result,
    collect_scan_targets,
    execute_scan,
    is_path_excluded,
    load_ignore_patterns,
    scan_file,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from phi_scan.compliance import ComplianceControl

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

app.add_typer(config_app)
app.add_typer(explain_app)
app.add_typer(baseline_app)

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
_SCAN_OUTPUT_HELP: str = (
    "Output format: table (default), json, sarif, csv, junit, codequality, gitlab-sast."
)
_SCAN_CONFIG_HELP: str = "Path to .phi-scanner.yml. Defaults to .phi-scanner.yml in CWD."
_SCAN_SEVERITY_HELP: str = "Minimum severity threshold: info, low, medium, high."
_SCAN_LOG_LEVEL_HELP: str = "Logging verbosity: debug, info, warning, error."
_SCAN_LOG_FILE_HELP: str = "Write structured logs to this file in addition to stderr."
_SCAN_QUIET_HELP: str = "Suppress all terminal output. Exit code still reflects findings."
_SCAN_VERBOSE_HELP: str = (
    "Emit timestamped phase markers to stderr as the scan progresses. Implies --log-level debug."
)
_SCAN_REPORT_PATH_HELP: str = (
    "Write the serialized report to this file path instead of stdout. "
    "Requires a non-table output format."
)
_SCAN_NO_CACHE_HELP: str = "Bypass the content-hash scan cache. Forces a full re-scan of all files."
_FRAMEWORK_FLAG_NAME: str = "--framework"
# Example framework tokens reference enum values so they stay in sync with
# ComplianceFramework. If new frameworks are added, update the example list.
_SCAN_FRAMEWORK_HELP: str = (
    "Comma-separated compliance frameworks to annotate findings with "
    f"(e.g. {ComplianceFramework.GDPR},{ComplianceFramework.SOC2},{ComplianceFramework.HITRUST}). "
    f"{ComplianceFramework.HIPAA} is always active. "
    "Run `phi-scan explain frameworks` for all supported values."
)
# The {error} placeholder receives a ValueError from parse_framework_flag, whose
# message contains only the unrecognised framework name tokens the user supplied
# (e.g. "nonexistent"). It never carries PHI or scan-result content because
# parse_framework_flag operates solely on the --framework CLI flag string.
_FRAMEWORK_PARSE_ERROR: str = "Invalid --framework value: {error}"
_REPORT_PATH_TABLE_FORMAT_ERROR: str = (
    "--report-path requires a serialized output format. "
    "Use --output json, sarif, csv, junit, codequality, gitlab-sast, pdf, or html."
)
_REPORT_PATH_BINARY_FORMAT_REQUIRED_ERROR: str = (
    "--output {format} requires --report-path <file.{format}> "
    "-- binary formats cannot be written to stdout."
)
_UNEXPECTED_BINARY_FORMAT_ERROR: str = (
    "_generate_report_bytes received unexpected output format {format!r} — "
    "only OutputFormat.PDF and OutputFormat.HTML are supported"
)
_TREND_CHART_LOOKBACK_DAYS: int = 30
_REPORT_PATH_WRITE_ERROR: str = "Failed to write report to {path!r}: {error}"
_REPORT_PATH_WRITTEN_MESSAGE: str = "Report written to {path}"
_VERBOSE_TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S"
_VERBOSE_PHASE_PREFIX: str = "[{timestamp}] Phase: {message}"
_VERBOSE_PHASE_COLLECTING: str = "collecting scan targets"
_VERBOSE_PHASE_SCANNING: str = "scanning {count} file(s)"
_VERBOSE_PHASE_AUDIT: str = "writing audit record"
_VERBOSE_PHASE_REPORT: str = "rendering report"

# ---------------------------------------------------------------------------
# Watch command
# ---------------------------------------------------------------------------

_WATCH_PATH_HELP: str = "Directory to watch for file system changes."
_WATCH_POLL_INTERVAL_SECONDS: float = 1.0
_WATCH_LIVE_REFRESH_RATE: float = 4.0
_WATCH_LOG_MAX_EVENTS: int = 10
# Sentinel shown when a changed path cannot be relativised to watch_root (edge case).
# The bare filename is NOT used because filenames may contain PHI (patient IDs, MRNs).
_WATCH_PATH_OUTSIDE_ROOT_DISPLAY: str = "[outside watch root]"

# ---------------------------------------------------------------------------
# History command
# ---------------------------------------------------------------------------

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
# CWD-relative by design: hook commands are always run from the repo root.
_GIT_DIR_PATH: Path = Path(".git")
_GIT_DIR_NOT_FOUND_MESSAGE: str = "Not a git repository — .git directory not found."
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
# Stub messages for Phase 2+ features
# ---------------------------------------------------------------------------

_INIT_STUB_MESSAGE: str = (
    "phi-scan init: full guided setup wizard is coming in Phase 3. "
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

# ---------------------------------------------------------------------------
# Baseline-related scan command constants
# ---------------------------------------------------------------------------

_SCAN_BASELINE_HELP: str = (
    "Only report NEW findings not in the .phi-scanbaseline file. "
    "Exit code is based on new findings only."
)
_SCAN_POST_COMMENT_HELP: str = (
    "Post scan findings as a PR/MR comment. "
    "Auto-detects the CI platform from environment variables."
)
_SCAN_SET_STATUS_HELP: str = (
    "Set the commit status to PASS or FAIL based on scan results. "
    "Auto-detects the CI platform from environment variables."
)
_SCAN_UPLOAD_SARIF_HELP: str = (
    "Upload SARIF output to GitHub Code Scanning for inline PR annotations. "
    "Requires --output sarif and GITHUB_TOKEN. "
    "Each finding appears as an inline annotation on the exact line in the PR diff."
)
_SCAN_WORKERS_HELP: str = (
    f"Number of worker threads for parallel file scanning. Default 1 (sequential). "
    f"Values above 1 enable concurrent scanning up to {MAX_WORKER_COUNT}. "
    "Output ordering is deterministic regardless of thread completion order."
)

# Maximum characters of a file path shown in the progress bar description column.
# Longer paths are truncated with a leading ellipsis so the bar layout stays stable.
_PROGRESS_FILENAME_MAX_CHARS: int = 38
_PROGRESS_FILENAME_ELLIPSIS: str = "…"
# Label shown in the progress bar description column when parallel scanning is active.
# Replaces the per-file name shown in sequential mode (multiple files run simultaneously
# so a single filename would be misleading).
_PARALLEL_SCAN_PROGRESS_LABEL: str = "scanning..."
# Thread name prefix used by the CLI-side ThreadPoolExecutor (progress bar path).
_CLI_PARALLEL_THREAD_NAME_PREFIX: str = "phi-scan-worker"
# Default and minimum worker count accepted by the --workers option.
_DEFAULT_WORKER_COUNT: int = 1
_MIN_WORKER_COUNT: int = 1
# Error messages for out-of-range --workers values.
_WORKERS_BELOW_MINIMUM_ERROR: str = f"--workers must be at least {_MIN_WORKER_COUNT}"
_WORKERS_ABOVE_MAXIMUM_ERROR: str = f"--workers must not exceed {MAX_WORKER_COUNT}"

# ---------------------------------------------------------------------------
# Error and warning messages
# ---------------------------------------------------------------------------

_AUDIT_WRITE_FAILURE_WARNING: str = "Audit log write failed — scan result not persisted: {error}"
_AUDIT_KEY_MISSING_DEBUG: str = (
    "Audit log skipped — encryption key not found. Run 'phi-scan setup' to generate it."
)
_NOTIFICATION_EMAIL_FAILURE_WARNING: str = "Email notification failed: {error}"
_NOTIFICATION_WEBHOOK_FAILURE_WARNING: str = "Webhook notification failed: {error}"
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
_SPINNER_NOTIFY_MESSAGE: str = "Sending notifications…"
_IMPLEMENTED_FORMAT_NAMES: str = ", ".join(sorted(fmt.value for fmt in IMPLEMENTED_OUTPUT_FORMATS))
_UNSUPPORTED_OUTPUT_FORMAT_ERROR: str = (
    "Output format {fmt!r} is not yet implemented. "
    f"Currently supported: {_IMPLEMENTED_FORMAT_NAMES}. "
    "Additional formats are not yet available."
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

# Must stay in sync with IMPLEMENTED_OUTPUT_FORMATS - {OutputFormat.TABLE}.
# TABLE is handled before this dict is consulted (_emit_scan_output checks it
# first as a special case). Using .get() on this dict is the runtime gate —
# a missing key means the format is not yet implemented.
_FORMAT_SERIALIZERS: dict[OutputFormat, Callable[[ScanResult], str]] = {
    OutputFormat.JSON: format_json,
    OutputFormat.CSV: format_csv,
    OutputFormat.SARIF: format_sarif,
    OutputFormat.JUNIT: format_junit,
    OutputFormat.CODEQUALITY: format_codequality,
    OutputFormat.GITLAB_SAST: format_gitlab_sast,
}

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


@dataclass(frozen=True)
class _WatchScanOutcome:
    """The outcome of scanning one file during watch mode.

    Carries the human-readable result text and a typed boolean that
    output.py uses to derive the Rich style for the rolling event table.
    """

    result_text: str
    is_clean: bool


@dataclass
@dataclass(frozen=True)
class _WatchConfig:
    """Immutable configuration shared between watch() and _FileChangeMonitor.

    Frozen enforces the invariant that watch_root and scan_config are read-only
    once constructed — mutation on the watchdog background thread would be an
    unsynchronized write with no lock protection.
    The mutable watch_events deque is kept separate and passed explicitly so
    that immutable and mutable state are never mixed in one dataclass.
    """

    watch_root: Path
    scan_config: ScanConfig


class _FileChangeMonitor(FileSystemEventHandler):
    """Watchdog event handler — appends a watch event to the rolling log on each file change.

    Each file-change event triggers a full scan of the changed file. Findings are
    displayed inline; the watch header shows cumulative session state.
    """

    def __init__(self, watch_config: _WatchConfig, watch_events: deque[WatchEvent]) -> None:
        """Bind the immutable watch configuration and the mutable event buffer.

        watch_config and watch_events are kept separate so that frozen=True on
        _WatchConfig enforces the read-only invariant — scan_config must not be
        mutated on the watchdog background thread.

        Args:
            watch_config: Frozen config holding watch_root and scan_config.
            watch_events: Shared rolling deque appended to on each file change.
        """
        super().__init__()
        self._watch_config = watch_config
        self._watch_events = watch_events

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
        scan_outcome = _scan_changed_file(changed_path, self._watch_config)
        if scan_outcome is not None:
            _append_watch_event(changed_path, scan_outcome, self._watch_config, self._watch_events)


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


@dataclass(frozen=True)
class _ScanOutputOptions:
    """Options controlling how scan results are rendered or serialized.

    Groups output-rendering flags passed to _emit_scan_output and its helpers.
    Execution-phase flags (verbosity, baseline mode) live in _ScanPhaseOptions.
    """

    output_format: OutputFormat
    is_rich_mode: bool
    report_path: Path | None
    scan_target: Path = field(default_factory=lambda: Path("."))
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None = None


@dataclass(frozen=True)
class _ScanPhaseOptions:
    """Execution-phase flags controlling phase headers and data selection.

    Kept separate from _ScanOutputOptions because these flags control when and
    how scan phases execute, not how results are rendered.
    """

    is_verbose: bool = False
    should_use_baseline: bool = False


@dataclass(frozen=True)
class _ScanExecutionOptions:
    """Execution parameters threaded from the scan command into the scan loop.

    Bundles worker_count and should_show_progress so _execute_scan_with_progress
    stays within the three-argument limit required by CLAUDE.md.
    """

    worker_count: int = _DEFAULT_WORKER_COUNT
    should_show_progress: bool = False


@dataclass
class _ParallelProgressScan:
    """Arguments for _scan_files_with_progress and its sequential/parallel sub-helpers.

    Bundles all five inputs required by the progress-bar scan path into a single
    object so each helper stays within the three-argument limit.
    """

    scan_targets: list[Path]
    config: ScanConfig
    worker_count: int
    progress: Progress
    task_id: TaskID


def _configure_logging(log_level: str, log_file: Path | None, is_quiet: bool) -> None:
    """Apply logging configuration from CLI flags.

    Args:
        log_level: One of debug, info, warning, error.
        log_file: Optional path for a rotating file handler.
        is_quiet: Suppress console output when True.
    """
    level = _LOG_LEVEL_MAP.get(log_level.lower(), logging.WARNING)
    replace_logger_handlers(console_level=level, log_file_path=log_file, is_quiet=is_quiet)


def _load_combined_ignore_patterns(scan_config: ScanConfig) -> list[str]:
    """Return .phi-scanignore patterns merged with any config-level exclude_paths.

    Args:
        scan_config: Active scan configuration (provides optional exclude_paths).

    Returns:
        Flat list of gitignore-style exclusion patterns ready for pathspec.
    """
    ignore_patterns = load_ignore_patterns(Path(DEFAULT_IGNORE_FILENAME))
    if scan_config.exclude_paths:
        ignore_patterns.extend(scan_config.exclude_paths)
    return ignore_patterns


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
    ignore_patterns = _load_combined_ignore_patterns(options.config)
    if options.diff_ref is not None:
        exclusion_spec = pathspec.PathSpec.from_lines(PathspecMatchStyle.GITIGNORE, ignore_patterns)
        scan_root = options.scan_root.resolve()
        return [
            diff_file
            for diff_file in get_changed_files_from_diff(options.diff_ref)
            if not is_path_excluded(_normalize_diff_path(diff_file, scan_root), exclusion_spec)
        ]
    return collect_scan_targets(options.scan_root, ignore_patterns, options.config)


def _normalize_diff_path(diff_file: Path, scan_root: Path) -> Path:
    """Return diff_file as a path relative to scan_root for exclusion matching.

    get_changed_files_from_diff returns absolute paths. Gitignore-style exclusion
    patterns require relative paths to match correctly — an absolute path like
    /home/user/project/tests/test_audit.py will never match the pattern
    tests/test_audit.py. Falling back to the absolute path preserves behaviour
    for files outside the scan root.

    Args:
        diff_file: Absolute path returned by get_changed_files_from_diff.
        scan_root: Resolved absolute scan root used to make the path relative.

    Returns:
        Path relative to scan_root when diff_file is inside it, otherwise diff_file.
    """
    if diff_file.is_relative_to(scan_root):
        return diff_file.relative_to(scan_root)
    return diff_file


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


def _validate_worker_count(worker_count: int) -> None:
    """Raise typer.BadParameter if worker_count is outside the permitted range.

    Args:
        worker_count: Value supplied by the --workers CLI option.

    Raises:
        typer.BadParameter: If worker_count < _MIN_WORKER_COUNT or > MAX_WORKER_COUNT.
    """
    if worker_count < _MIN_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_BELOW_MINIMUM_ERROR)
    if worker_count > MAX_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_ABOVE_MAXIMUM_ERROR)


def _scan_files_sequential_with_progress(
    scan: _ParallelProgressScan,
) -> list[ScanFinding]:
    """Scan files one at a time, advancing the progress bar after each file.

    Args:
        scan: Bundled scan targets, config, and progress bar state.

    Returns:
        All findings in scan_targets order.
    """
    all_findings: list[ScanFinding] = []
    for file_path in scan.scan_targets:
        progress_label = _truncate_filename_for_progress(file_path)
        scan.progress.update(scan.task_id, description=progress_label, advance=1)
        all_findings.extend(scan_file(file_path, scan.config))
    return all_findings


def _scan_files_parallel_with_progress(
    scan: _ParallelProgressScan,
) -> list[ScanFinding]:
    """Scan files concurrently, advancing the progress bar as each file completes.

    Uses as_completed() so the progress bar fires on actual completion rather than
    submission order. Results are re-sorted by original scan_targets index before
    returning to ensure deterministic output ordering.

    Args:
        scan: Bundled scan targets, config, worker count, and progress bar state.

    Returns:
        All findings in scan_targets order.
    """
    indexed_results: dict[int, list[ScanFinding]] = {}
    future_to_index: dict[Future[list[ScanFinding]], int] = {}
    with ThreadPoolExecutor(
        max_workers=scan.worker_count,
        thread_name_prefix=_CLI_PARALLEL_THREAD_NAME_PREFIX,
    ) as executor:
        for index, file_path in enumerate(scan.scan_targets):
            future_to_index[executor.submit(scan_file, file_path, scan.config)] = index
        for completed_future in as_completed(future_to_index):
            original_index = future_to_index[completed_future]
            indexed_results[original_index] = completed_future.result()
            scan.progress.update(scan.task_id, description=_PARALLEL_SCAN_PROGRESS_LABEL, advance=1)
    ordered_per_file = [indexed_results[i] for i in range(len(scan.scan_targets))]
    return [finding for file_findings in ordered_per_file for finding in file_findings]


def _scan_files_with_progress(
    scan: _ParallelProgressScan,
) -> list[ScanFinding]:
    """Dispatch to sequential or parallel progress scanning based on worker_count.

    Args:
        scan: Bundled scan targets, config, worker count, and progress bar state.

    Returns:
        All findings in scan_targets order.
    """
    if scan.worker_count > _MIN_WORKER_COUNT:
        return _scan_files_parallel_with_progress(scan)
    return _scan_files_sequential_with_progress(scan)


def _execute_scan_with_progress(
    scan_targets: list[Path],
    config: ScanConfig,
    execution_options: _ScanExecutionOptions,
) -> ScanResult:
    """Run the scan loop, showing a Rich progress bar when should_show_progress is True.

    The progress bar is suppressed for machine-readable output formats (json/csv/sarif)
    and for --quiet mode, since terminal decoration must not appear in serialized output.

    Args:
        scan_targets: Files to scan, as returned by _resolve_scan_targets.
        config: Active scan configuration.
        execution_options: Worker count and progress bar visibility settings.

    Returns:
        Aggregated ScanResult for all scanned files.
    """
    if not execution_options.should_show_progress:
        return execute_scan(scan_targets, config, execution_options.worker_count)
    scan_start = time.monotonic()
    with create_scan_progress(total_files=len(scan_targets)) as (progress, task_id):
        parallel_scan = _ParallelProgressScan(
            scan_targets=scan_targets,
            config=config,
            worker_count=execution_options.worker_count,
            progress=progress,
            task_id=task_id,
        )
        all_findings = _scan_files_with_progress(parallel_scan)
    scan_duration = time.monotonic() - scan_start
    return build_scan_result(tuple(all_findings), len(scan_targets), scan_duration)


def _write_audit_record(
    scan_result: ScanResult,
    database_path: Path,
    notifications_sent: list[str] | None = None,
) -> None:
    """Persist the scan result to the SQLite audit log.

    Audit failures are logged as warnings and do not abort the scan.
    HIPAA §164.530(j) requires best-effort audit retention — a write failure
    must be surfaced to operators but must not block the CI gate decision.

    Args:
        scan_result: The completed scan result to persist.
        database_path: Path to the SQLite audit database (may include ~).
        notifications_sent: Channel names delivered before this write.
    """
    resolved_path = database_path.expanduser()
    try:
        ensure_current_schema(resolved_path)
        insert_scan_event(resolved_path, scan_result, notifications_sent)
    except AuditKeyMissingError:
        _logger.debug(_AUDIT_KEY_MISSING_DEBUG)
    except AuditLogError as audit_error:
        _logger.warning(_AUDIT_WRITE_FAILURE_WARNING.format(error=audit_error))


def _dispatch_notifications(
    scan_result: ScanResult,
    scan_config: ScanConfig,
    report_path: Path | None = None,
) -> list[str]:
    """Send email and/or webhook notifications if configured and triggered.

    Best-effort: failures are logged as warnings and do not abort the scan.

    Args:
        scan_result: Completed scan result to notify about.
        scan_config: Loaded config containing notification_config.
        report_path: Optional path to attach to the email.

    Returns:
        List of channel name strings that were successfully delivered,
        e.g. ["email", "webhook-slack"].
    """
    config = scan_config.notification_config
    should_notify = not config.notify_on_violation_only or not scan_result.is_clean
    if not should_notify:
        return []
    from phi_scan.audit import _get_current_branch, _get_current_repository_path

    repository = _get_current_repository_path()
    branch = _get_current_branch()
    notification_request = NotificationRequest(
        scan_result=scan_result,
        repository=repository,
        branch=branch,
        scanner_version=__version__,
        report_path=report_path,
    )
    sent_channels: list[str] = []
    if config.is_email_enabled:
        try:
            send_email_notification(config, notification_request)
            sent_channels.append("email")
        except NotificationError as email_error:
            _logger.warning(_NOTIFICATION_EMAIL_FAILURE_WARNING.format(error=email_error))
    if config.is_webhook_enabled:
        try:
            send_webhook_notification(config, notification_request)
            sent_channels.append(f"webhook-{config.webhook_type.value}")
        except NotificationError as webhook_error:
            _logger.warning(_NOTIFICATION_WEBHOOK_FAILURE_WARNING.format(error=webhook_error))
    return sent_channels


def _resolve_output_format(output_format: str) -> OutputFormat:
    """Parse the output format string and exit with an error on unknown values.

    Args:
        output_format: Raw string value of the --output flag.

    Returns:
        The matching OutputFormat enum member.

    Raises:
        typer.Exit: If output_format does not match any OutputFormat member.
    """
    try:
        return OutputFormat(output_format)
    except ValueError as value_error:
        typer.echo(_UNSUPPORTED_OUTPUT_FORMAT_ERROR.format(fmt=output_format), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from value_error


def _resolve_framework_flag(framework_flag_value: str | None) -> frozenset[ComplianceFramework]:
    """Parse the --framework flag and exit with an error on unknown framework names.

    Args:
        framework_flag_value: Comma-separated framework string from the CLI, or None.

    Returns:
        frozenset of ComplianceFramework members; empty when framework_flag_value is None.

    Raises:
        typer.Exit: If any framework token is not a valid ComplianceFramework value.
    """
    try:
        return parse_framework_flag(framework_flag_value)
    except InvalidFrameworkError as framework_error:
        typer.echo(_FRAMEWORK_PARSE_ERROR.format(error=framework_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from framework_error


def _prepare_scan_phase(
    target_options: _ScanTargetOptions,
    is_rich_mode: bool,
    is_verbose: bool,
) -> list[Path]:
    """Emit collection-phase feedback and return the resolved scan target list.

    Displays the collecting phase, resolves which files to scan, then displays
    the file-type summary and announces the scanning phase. The return value
    is ready to pass directly to _execute_scan_with_progress.

    Args:
        target_options: Scan root, diff ref, single file, and config.
        is_rich_mode: Whether Rich terminal display is active.
        is_verbose: Whether to emit verbose phase messages to stderr.

    Returns:
        Ordered list of file paths selected for scanning.
    """
    if is_rich_mode:
        display_phase_collecting()
    _emit_verbose_phase(_VERBOSE_PHASE_COLLECTING, is_verbose)
    scan_targets = _resolve_scan_targets(target_options)
    if is_rich_mode:
        display_file_type_summary(scan_targets)
        display_phase_scanning()
    _emit_verbose_phase(_VERBOSE_PHASE_SCANNING.format(count=len(scan_targets)), is_verbose)
    return scan_targets


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


def _emit_verbose_phase(message: str, is_verbose: bool) -> None:
    """Write a timestamped phase marker to stderr when verbose mode is active.

    Args:
        message: Short description of the current scan phase.
        is_verbose: When False this function is a no-op.
    """
    if not is_verbose:
        return
    timestamp = datetime.now().strftime(_VERBOSE_TIMESTAMP_FORMAT)
    typer.echo(_VERBOSE_PHASE_PREFIX.format(timestamp=timestamp, message=message), err=True)


def _invoke_report_writer(write_callable: Callable[[Path], object], report_path: Path) -> None:
    try:
        write_callable(report_path)
    except OSError as write_error:
        typer.echo(_REPORT_PATH_WRITE_ERROR.format(path=report_path, error=write_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from write_error
    typer.echo(_REPORT_PATH_WRITTEN_MESSAGE.format(path=report_path), err=True)


def _write_report_to_file(content: str, report_path: Path) -> None:
    """Write serialized report content to a file and confirm on stderr.

    Args:
        content: The serialized report string (JSON, XML, CSV, etc.).
        report_path: Destination file path.

    Raises:
        typer.Exit: If the file cannot be written (e.g. permission error).
    """
    _invoke_report_writer(
        lambda p: p.write_text(content, encoding=DEFAULT_TEXT_ENCODING), report_path
    )


def _write_report_bytes_to_file(content: bytes, report_path: Path) -> None:
    """Write binary report content (PDF or HTML) to a file and confirm on stderr.

    Args:
        content: Raw bytes to write (PDF or UTF-8 HTML).
        report_path: Destination file path.

    Raises:
        typer.Exit: If the file cannot be written (e.g. permission error).
    """
    _invoke_report_writer(lambda p: p.write_bytes(content), report_path)


def _generate_report_bytes(
    scan_result: ScanResult,
    options: _ScanOutputOptions,
    audit_rows: list[dict[str, object]],
) -> bytes:
    """Generate PDF or HTML report bytes from a scan result.

    Args:
        scan_result: The completed scan result.
        options: Must have output_format in (OutputFormat.PDF, OutputFormat.HTML).
            scan_target defaults to Path(".") when not supplied by the caller.
        audit_rows: Recent audit rows for the trend chart.

    Returns:
        Raw bytes of the generated report (PDF or UTF-8 HTML).
    """
    if options.output_format not in {OutputFormat.PDF, OutputFormat.HTML}:
        raise ValueError(_UNEXPECTED_BINARY_FORMAT_ERROR.format(format=options.output_format))
    if options.output_format == OutputFormat.PDF:
        return generate_pdf_report(
            scan_result,
            options.scan_target,
            audit_rows,
            options.framework_annotations,
        )
    return generate_html_report(
        scan_result,
        options.scan_target,
        audit_rows,
        options.framework_annotations,
    )


def _fetch_report_audit_rows() -> list[dict[str, object]]:
    """Return recent audit rows for the binary report trend chart."""
    database_path = Path(DEFAULT_DATABASE_PATH).expanduser()
    return query_recent_scans(database_path, _TREND_CHART_LOOKBACK_DAYS)


def _write_binary_report(scan_result: ScanResult, options: _ScanOutputOptions) -> None:
    """Write the rendered binary report to the path specified in options.

    Args:
        scan_result: The completed scan result.
        options: Must have output_format in (pdf, html) and a non-None report_path.

    Raises:
        typer.Exit: If report_path is missing or the file cannot be written.
    """
    if options.report_path is None:
        typer.echo(
            _REPORT_PATH_BINARY_FORMAT_REQUIRED_ERROR.format(format=options.output_format.value),
            err=True,
        )
        raise typer.Exit(code=EXIT_CODE_ERROR)
    audit_rows = _fetch_report_audit_rows()
    report_bytes = _generate_report_bytes(scan_result, options, audit_rows)
    _write_report_bytes_to_file(report_bytes, options.report_path)


def _emit_scan_output(scan_result: ScanResult, options: _ScanOutputOptions) -> None:
    """Render or serialize scan results in the requested output format.

    For table format in Rich mode, delegates to _display_rich_scan_results.
    For serialized formats, writes to options.report_path when set, or stdout.

    Args:
        scan_result: The completed scan result.
        options: Output format, Rich mode flag, and optional report file path.

    Raises:
        typer.Exit: If the format is not implemented or report file cannot be written.
    """
    if options.output_format == OutputFormat.TABLE:
        if options.report_path is not None:
            typer.echo(_REPORT_PATH_TABLE_FORMAT_ERROR, err=True)
            raise typer.Exit(code=EXIT_CODE_ERROR)
        if options.is_rich_mode:
            _display_rich_scan_results(scan_result)
        return
    if options.output_format in (OutputFormat.PDF, OutputFormat.HTML):
        _write_binary_report(scan_result, options)
        return
    serializer = _FORMAT_SERIALIZERS.get(options.output_format)
    if serializer is None:
        error_message = _UNSUPPORTED_OUTPUT_FORMAT_ERROR.format(fmt=options.output_format.value)
        typer.echo(error_message, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    serialized = serializer(scan_result)
    if options.report_path is not None:
        _write_report_to_file(serialized, options.report_path)
    else:
        typer.echo(serialized)


# ---------------------------------------------------------------------------
# Internal helpers — baseline-aware scan output
# ---------------------------------------------------------------------------


def _load_optional_baseline(baseline_path: Path) -> BaselineSnapshot | None:
    """Load a baseline snapshot, returning None and printing a warning on failure.

    Args:
        baseline_path: Path to the .phi-scanbaseline file.

    Returns:
        Loaded snapshot, or None when the file is missing or unreadable.
    """
    try:
        return load_baseline(baseline_path=baseline_path)
    except BaselineError as baseline_load_error:
        typer.echo(BASELINE_LOAD_ERROR_MESSAGE.format(error=baseline_load_error), err=True)
        return None


def _emit_scan_output_with_baseline(
    scan_result: ScanResult, output_options: _ScanOutputOptions
) -> NoReturn:
    """Apply baseline filtering and emit output; always raises typer.Exit.

    Every code path terminates with raise typer.Exit — the NoReturn annotation
    is accurate. When no baseline file exists, emits standard scan output then
    raises; when a baseline is found, emits new-findings output then raises.
    The exit code reflects new (non-baselined) findings only.

    Args:
        scan_result: The completed scan result from the full detection pass.
        output_options: Output format, rich-mode flag, and report path.
    """
    baseline_path = Path(DEFAULT_BASELINE_FILENAME)
    snapshot = _load_optional_baseline(baseline_path)
    if snapshot is None:
        _emit_scan_output(scan_result, output_options)
        raise typer.Exit(code=EXIT_CODE_CLEAN if scan_result.is_clean else EXIT_CODE_VIOLATION)
    new_findings, baselined_findings = filter_baselined_findings(scan_result.findings, snapshot)
    if output_options.is_rich_mode:
        _display_rich_baseline_results(scan_result, new_findings, len(baselined_findings))
    else:
        _emit_scan_output(scan_result, output_options)
    raise typer.Exit(code=EXIT_CODE_CLEAN if not new_findings else EXIT_CODE_VIOLATION)


def _display_rich_baseline_results(
    scan_result: ScanResult,
    new_findings: list[ScanFinding],
    baselined_count: int,
) -> None:
    """Render rich output for a baseline-filtered scan.

    New findings are displayed with the standard violation UI. A baseline notice
    panel is always shown to communicate how many findings were suppressed.

    Args:
        scan_result: Full scan result (used for the summary panel metadata).
        new_findings: Findings not covered by any active baseline entry.
        baselined_count: Count of findings suppressed by the baseline.
    """
    if new_findings:
        display_violation_alert(scan_result)
        display_findings_table(tuple(new_findings))
    else:
        display_clean_result()
    display_baseline_scan_notice(len(new_findings), baselined_count)


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
            raise typer.Exit(code=EXIT_CODE_ERROR)


def _reject_missing_git_directory() -> None:
    """Reject if the .git directory is absent in the current working directory.

    Hook operations require a .git directory — running install-hook or
    uninstall-hook outside a git repository would silently write into a
    non-standard path. This guard catches that before any read or write occurs.

    Note: git worktrees replace .git with a plain file (gitdir: ...);
    is_dir() returns False in that case, so hook commands are intentionally
    unsupported in worktrees until the guard is extended.

    Raises:
        typer.Exit: If _GIT_DIR_PATH does not exist as a directory.
    """
    if not _GIT_DIR_PATH.is_dir():
        typer.echo(_GIT_DIR_NOT_FOUND_MESSAGE, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)


# ---------------------------------------------------------------------------
# Internal helpers — watch command
# ---------------------------------------------------------------------------


def _build_relative_display_path(changed_path: Path, watch_root: Path) -> str:
    """Return changed_path relative to watch_root for PHI-safe display.

    File paths can contain PHI (patient IDs, names) in directory components.
    Storing the absolute path verbatim would persist raw PHI in the shared deque.
    Converting to a watch-root-relative path removes the sensitive prefix that
    appears in deep patient-directory structures. If relativisation fails (edge
    case where the path is outside watch_root), a safe sentinel is returned —
    the bare filename is NOT used because filenames themselves may contain PHI
    (e.g. john_doe_mrn_123456.hl7).

    Args:
        changed_path: Absolute path to the changed file.
        watch_root: The watched directory root.

    Returns:
        A relative path string safe for terminal display, or a fixed sentinel
        when the path cannot be relativised.
    """
    try:
        return str(changed_path.relative_to(watch_root))
    except ValueError:
        return _WATCH_PATH_OUTSIDE_ROOT_DISPLAY


def _scan_changed_file(changed_path: Path, watch_config: _WatchConfig) -> _WatchScanOutcome | None:
    """Run scan_file on a watchdog-reported path and return a structured outcome.

    Returns None when the file cannot be read (deleted or permissions changed between
    the watchdog event and the scan call) — caller skips appending to the deque.

    Args:
        changed_path: The file that changed, already confirmed non-symlink.
        watch_config: Immutable watch configuration; provides the scan config.

    Returns:
        _WatchScanOutcome with result text and is_clean flag, or None on I/O error.
    """
    try:
        findings = scan_file(changed_path, watch_config.scan_config)
    except (PermissionError, FileNotFoundError):
        # File deleted or permissions revoked between watchdog event and scan call —
        # log and signal skip rather than crashing the watchdog background thread.
        _logger.warning("Skipping unreadable or deleted file during watch: %s", changed_path.name)
        return None
    return _build_watch_result(findings)


def _append_watch_event(
    changed_path: Path,
    scan_outcome: _WatchScanOutcome,
    watch_config: _WatchConfig,
    watch_events: deque[WatchEvent],
) -> None:
    """Build a WatchEvent from the scan outcome and append it to the rolling deque.

    Args:
        changed_path: The file that changed; used to compute the display path.
        scan_outcome: Structured result from _scan_changed_file.
        watch_config: Immutable watch configuration; provides the watch root path.
        watch_events: Mutable rolling event buffer; receives the new WatchEvent.
    """
    # deque.append is atomic under CPython's GIL, so no explicit lock is needed here.
    # The main thread reads the deque via list(watch_events) (also atomic), making
    # this cross-thread access safe without threading.Lock for CPython.
    watch_events.append(
        WatchEvent(
            event_time=datetime.now(),
            file_path=_build_relative_display_path(changed_path, watch_config.watch_root),
            result_text=scan_outcome.result_text,
            is_clean=scan_outcome.is_clean,
        )
    )


def _build_watch_result(findings: list[ScanFinding]) -> _WatchScanOutcome:
    """Return a structured scan outcome for a per-file watch event.

    Maps the finding list to a display-ready outcome and clean/not-clean flag.

    Args:
        findings: Findings returned by scan_file for the changed file.

    Returns:
        _WatchScanOutcome with display text and a typed is_clean boolean.
    """
    if findings:
        return _WatchScanOutcome(
            result_text=WATCH_RESULT_VIOLATION_FORMAT.format(count=len(findings)),
            is_clean=False,
        )
    return _WatchScanOutcome(result_text=WATCH_RESULT_CLEAN_TEXT, is_clean=True)


def _display_watch_live_screen(
    watch_path: Path,
    watch_events: deque[WatchEvent],
) -> None:
    """Drive the Rich Live render loop, refreshing until the caller's context ends.

    Single responsibility: render only. KeyboardInterrupt is not caught here —
    it propagates naturally to watch(), which translates it to a clean exit code.
    Rich's Live context manager handles alternate-screen teardown via __exit__
    when any exception (including KeyboardInterrupt) unwinds the with block.

    Args:
        watch_path: The watched directory, shown in the persistent header.
        watch_events: Shared deque updated by _FileChangeMonitor on the watchdog thread.
    """
    with Live(refresh_per_second=_WATCH_LIVE_REFRESH_RATE, screen=True) as live:
        while True:
            live.update(build_watch_layout(watch_path, list(watch_events)))
            time.sleep(_WATCH_POLL_INTERVAL_SECONDS)


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


def _display_audit_phase_header(
    output_options: _ScanOutputOptions,
    phase_options: _ScanPhaseOptions,
) -> None:
    """Display the audit phase Rich banner and verbose marker."""
    if output_options.is_rich_mode:
        display_phase_audit()
    _emit_verbose_phase(_VERBOSE_PHASE_AUDIT, phase_options.is_verbose)


def _persist_audit_record(
    scan_result: ScanResult,
    scan_config: ScanConfig,
    output_options: _ScanOutputOptions,
) -> None:
    """Dispatch notifications then persist the scan result with audit metadata.

    Notifications are sent first (best-effort) so the channel list can be
    recorded in the audit row for compliance reporting.

    Args:
        scan_result: Completed scan result from _execute_scan_with_progress.
        scan_config: Loaded scan configuration (audit DB path + notifications).
        output_options: Controls Rich spinner activation and report path.
    """
    with display_status_spinner(_SPINNER_NOTIFY_MESSAGE, is_active=output_options.is_rich_mode):
        sent_channels = _dispatch_notifications(
            scan_result, scan_config, output_options.report_path
        )
    with display_status_spinner(
        _SPINNER_AUDIT_WRITE_MESSAGE, is_active=output_options.is_rich_mode
    ):
        _write_audit_record(scan_result, scan_config.database_path, sent_channels)


def _run_ci_integration(
    scan_result: ScanResult,
    should_post_comment: bool,
    should_set_status: bool,
    should_upload_sarif: bool,
    is_rich_mode: bool,
) -> None:
    """Run all enabled CI/CD platform integrations after a scan completes.

    All CI platform API errors are caught and logged as warnings — a failed
    comment or status call must never change the scan exit code.

    Args:
        scan_result:          The completed scan result.
        should_post_comment:  When True, post a PR/MR comment with findings.
        should_set_status:    When True, set commit status PASS/FAIL.
        should_upload_sarif:  When True, upload SARIF to GitHub Code Scanning.
        is_rich_mode:         When True, emit Rich-formatted warnings to terminal.
    """
    if not any([should_post_comment, should_set_status, should_upload_sarif]):
        return

    pr_context = get_pr_context()

    if should_post_comment:
        _call_ci_integration(
            lambda: post_pr_comment(scan_result, pr_context),
            "PR comment",
            is_rich_mode,
        )

    if should_set_status:
        _call_ci_integration(
            lambda: set_commit_status(scan_result, pr_context),
            "commit status",
            is_rich_mode,
        )
        # Azure DevOps: also set PR status policy + build tag
        from phi_scan.ci_integration import CIPlatform

        if pr_context.platform is CIPlatform.AZURE_DEVOPS:
            _call_ci_integration(
                lambda: set_azure_pr_status(scan_result, pr_context),
                "Azure PR status",
                is_rich_mode,
            )
            _call_ci_integration(
                lambda: set_azure_build_tag(scan_result, pr_context),
                "Azure build tag",
                is_rich_mode,
            )
            _call_ci_integration(
                lambda: create_azure_boards_work_item(scan_result, pr_context),
                "Azure Boards work item",
                is_rich_mode,
            )

        if pr_context.platform is CIPlatform.BITBUCKET:
            _call_ci_integration(
                lambda: post_bitbucket_code_insights(scan_result, pr_context),
                "Bitbucket Code Insights",
                is_rich_mode,
            )

    if should_upload_sarif:
        _call_ci_integration(
            lambda: upload_sarif_to_github(scan_result, pr_context),
            "SARIF upload",
            is_rich_mode,
        )

    # AWS Security Hub — runs when AWS_SECURITY_HUB=true regardless of other flags
    _call_ci_integration(
        lambda: import_findings_to_security_hub(scan_result, pr_context),
        "Security Hub import",
        is_rich_mode,
    )


def _call_ci_integration(
    operation: Any,
    label: str,
    is_rich_mode: bool,
) -> None:
    """Execute a CI integration operation, logging warnings on failure.

    Args:
        operation:   Zero-argument callable wrapping the integration call.
        label:       Human-readable name for the operation (used in warnings).
        is_rich_mode: When True, also print a Rich-formatted warning to the console.
    """
    try:
        operation()
    except CIIntegrationError as integration_error:
        _logger.warning("CI integration (%s) failed: %s", label, integration_error)
        if is_rich_mode:
            get_console().print(f"[yellow]Warning:[/yellow] {label} failed — {integration_error}")


def _display_report_phase_header(
    output_options: _ScanOutputOptions,
    phase_options: _ScanPhaseOptions,
) -> None:
    """Display the report phase Rich banner and verbose marker."""
    if output_options.is_rich_mode:
        display_phase_report()
    _emit_verbose_phase(_VERBOSE_PHASE_REPORT, phase_options.is_verbose)


def _emit_report_output(
    scan_result: ScanResult,
    output_options: _ScanOutputOptions,
    phase_options: _ScanPhaseOptions,
) -> NoReturn:
    """Emit scan output via the appropriate path; always raises typer.Exit.

    Both branches terminate via typer.Exit: the baseline path delegates to
    _emit_scan_output_with_baseline, which raises before returning; the
    standard path raises explicitly below.

    Args:
        scan_result: Completed scan result from _execute_scan_with_progress.
        output_options: Controls output format, rich mode, and report path.
        phase_options: Controls baseline mode selection.
    """
    if phase_options.should_use_baseline:
        _emit_scan_output_with_baseline(scan_result, output_options)
    else:
        _emit_scan_output(scan_result, output_options)
        raise typer.Exit(code=EXIT_CODE_CLEAN if scan_result.is_clean else EXIT_CODE_VIOLATION)


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
    is_verbose: Annotated[bool, typer.Option("--verbose", "-v", help=_SCAN_VERBOSE_HELP)] = False,
    report_path: Annotated[
        Path | None, typer.Option("--report-path", help=_SCAN_REPORT_PATH_HELP)
    ] = None,
    should_bypass_cache: Annotated[
        bool, typer.Option("--no-cache", help=_SCAN_NO_CACHE_HELP)
    ] = False,
    should_use_baseline: Annotated[
        bool, typer.Option("--baseline", help=_SCAN_BASELINE_HELP)
    ] = False,
    framework: Annotated[
        str | None, typer.Option(_FRAMEWORK_FLAG_NAME, help=_SCAN_FRAMEWORK_HELP)
    ] = None,
    should_post_comment: Annotated[
        bool, typer.Option("--post-comment", help=_SCAN_POST_COMMENT_HELP)
    ] = False,
    should_set_status: Annotated[
        bool, typer.Option("--set-status", help=_SCAN_SET_STATUS_HELP)
    ] = False,
    should_upload_sarif: Annotated[
        bool, typer.Option("--upload-sarif", help=_SCAN_UPLOAD_SARIF_HELP)
    ] = False,
    worker_count: Annotated[
        int, typer.Option("--workers", help=_SCAN_WORKERS_HELP)
    ] = _DEFAULT_WORKER_COUNT,
) -> None:
    """Scan a directory or file for PHI/PII.

    Parameters are Typer CLI declarations, not regular call-site arguments — the
    3-argument rule from CLAUDE.md applies to regular functions, not CLI commands
    whose parameters are read by Typer introspection. Scan target parameters are
    immediately packed into _ScanTargetOptions. Rich UI (banner, progress, results
    table) is suppressed for serialised formats (json/csv/sarif) to keep stdout
    clean for pipe and file consumption.
    """
    _validate_worker_count(worker_count)
    effective_log_level = _LOG_LEVEL_DEBUG if is_verbose else log_level
    _configure_logging(effective_log_level, log_file, is_quiet)
    output_format_enum = _resolve_output_format(output_format)
    enabled_frameworks = _resolve_framework_flag(framework)
    is_rich_mode = not is_quiet and output_format_enum is OutputFormat.TABLE
    with display_status_spinner(_SPINNER_CONFIG_LOAD_MESSAGE, is_active=is_rich_mode):
        scan_config = load_scan_config(config_path, severity_threshold)
    if is_rich_mode:
        display_banner()
        display_scan_header(path, scan_config)
    target_options = _ScanTargetOptions(
        scan_root=path, diff_ref=diff_ref, single_file=single_file, config=scan_config
    )
    scan_targets = _prepare_scan_phase(target_options, is_rich_mode, is_verbose)
    # Intentional ordering: scan runs before output_options is constructed because
    # framework_annotations depend on scan_result.findings. Any error raised by
    # _execute_scan_with_progress will propagate before output_options is configured,
    # which is acceptable — output_options has no effect until _emit_scan_output is called.
    execution_options = _ScanExecutionOptions(
        worker_count=worker_count,
        should_show_progress=is_rich_mode,
    )
    scan_result = _execute_scan_with_progress(scan_targets, scan_config, execution_options)
    framework_annotations = (
        annotate_findings(scan_result.findings, enabled_frameworks) if enabled_frameworks else None
    )
    output_options = _ScanOutputOptions(
        output_format=output_format_enum,
        is_rich_mode=is_rich_mode,
        report_path=report_path,
        scan_target=path,
        framework_annotations=framework_annotations,
    )
    phase_options = _ScanPhaseOptions(
        is_verbose=is_verbose,
        should_use_baseline=should_use_baseline,
    )
    _display_audit_phase_header(output_options, phase_options)
    _persist_audit_record(scan_result, scan_config, output_options)
    _run_ci_integration(
        scan_result,
        should_post_comment,
        should_set_status,
        should_upload_sarif,
        is_rich_mode,
    )
    _display_report_phase_header(output_options, phase_options)
    _emit_report_output(scan_result, output_options, phase_options)


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
    watch_config = _WatchConfig(watch_root=watch_path, scan_config=ScanConfig())
    watch_events: deque[WatchEvent] = deque(maxlen=_WATCH_LOG_MAX_EVENTS)
    event_handler = _FileChangeMonitor(watch_config, watch_events)
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)  # type: ignore[no-untyped-call]
    observer.start()  # type: ignore[no-untyped-call]
    try:
        _display_watch_live_screen(watch_path, watch_events)
    except KeyboardInterrupt:
        # Ctrl+C is the standard exit for watch mode. Translate the BaseException
        # into a clean exit code before the finally block tears down the observer.
        raise typer.Exit(code=EXIT_CODE_CLEAN)
    finally:
        observer.stop()  # type: ignore[no-untyped-call]
        observer.join()


@app.command("report")
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


@app.command("history")
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


@app.command("install-hook")
def install_hook() -> None:
    """Install phi-scan as a git pre-commit hook."""
    hook_path = Path(_PRE_COMMIT_HOOK_PATH)
    _reject_missing_git_directory()
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
    _reject_missing_git_directory()
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


# ---------------------------------------------------------------------------
# Fix command
# ---------------------------------------------------------------------------

_FIX_PATH_HELP: str = "File or directory to fix. Scans recursively when a directory is given."
_FIX_DRY_RUN_HELP: str = "Preview replacements as a unified diff without modifying files."
_FIX_APPLY_HELP: str = "Apply replacements in place after confirmation."
_FIX_PATCH_HELP: str = "Write a .patch file for each modified file instead of editing in place."
_FIX_INTERACTIVE_HELP: str = "Prompt for each replacement: Replace? [y/n/a(ll)/s(kip file)]"
_FIX_NO_MODE_ERROR: str = "Specify exactly one mode: --dry-run, --apply, --patch, or --interactive."
_FIX_MULTI_MODE_ERROR: str = (
    "Only one of --dry-run, --apply, --patch, or --interactive may be given at a time."
)
_FIX_CONFIRM_PROMPT: str = "Apply {count} replacement(s) to {path}? [y/N]"
_FIX_NO_FINDINGS_MESSAGE: str = "No PHI found in {path} — nothing to fix."
_FIX_PATCH_WRITTEN_MESSAGE: str = "Patch written: {path}"
_FIX_APPLIED_MESSAGE: str = "Applied {count} replacement(s) to {path}."
_FIX_SKIPPED_DRY_RUN_MESSAGE: str = "(dry-run) {count} replacement(s) found in {path}."
_FIX_INTERACTIVE_PROMPT: str = "[{index}/{total}] {path}:{line} — {category} — Replace? [y/n/a/s]: "
_FIX_INTERACTIVE_APPLY_ALL: str = "a"
_FIX_INTERACTIVE_SKIP_FILE: str = "s"
_FIX_INTERACTIVE_YES: str = "y"
_FIX_INTERACTIVE_NO: str = "n"
_FIX_FAKER_MISSING_MESSAGE: str = (
    "faker is required for `phi-scan fix`. Install it with: pip install phi-scan[dev]"
)
_FIX_RGLOB_PATTERN: str = "*"
# Starting index for enumerate() in the interactive per-replacement loop.
_FIX_ENUMERATE_START: int = 1


def _collect_target_files(path: Path) -> list[Path]:
    """Return scannable files under path (recursive) or [path] when path is a file.

    Args:
        path: File or directory to collect from.

    Returns:
        List of regular, non-symlink file paths.
    """
    if path.is_file() and not path.is_symlink():
        return [path]
    return [
        candidate
        for candidate in path.rglob(_FIX_RGLOB_PATTERN)
        if candidate.is_file() and not candidate.is_symlink()
    ]


def _print_fix_result(fix_result: FixResult, mode: FixMode) -> None:
    """Print a human-readable summary of a fix operation for one file.

    Args:
        fix_result: The result of the fix operation.
        mode: The mode under which the fix was run.
    """
    console = get_console()
    file_path = fix_result.file_path
    count = len(fix_result.replacements_applied)
    if count == 0:
        console.print(_FIX_NO_FINDINGS_MESSAGE.format(path=file_path))
        return
    if mode == FixMode.DRY_RUN:
        console.print(fix_result.unified_diff)
        console.print(_FIX_SKIPPED_DRY_RUN_MESSAGE.format(count=count, path=file_path))
    elif mode == FixMode.APPLY:
        console.print(_FIX_APPLIED_MESSAGE.format(count=count, path=file_path))
    elif mode == FixMode.PATCH and fix_result.patch_path is not None:
        console.print(_FIX_PATCH_WRITTEN_MESSAGE.format(path=fix_result.patch_path))


def _run_interactive_fix(file_path: Path) -> None:
    """Prompt the user for each replacement in file_path and apply approved ones.

    Args:
        file_path: File to interactively fix.
    """
    console = get_console()
    try:
        replacements = collect_file_replacements(file_path)
    except MissingOptionalDependencyError:
        typer.echo(_FIX_FAKER_MISSING_MESSAGE, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from None
    if not replacements:
        console.print(_FIX_NO_FINDINGS_MESSAGE.format(path=file_path))
        return
    approved: list[FixReplacement] = []
    total = len(replacements)
    for index, replacement in enumerate(replacements, start=_FIX_ENUMERATE_START):
        prompt = _FIX_INTERACTIVE_PROMPT.format(
            index=index,
            total=total,
            path=file_path,
            line=replacement.line_number,
            category=replacement.hipaa_category,
        )
        raw_answer = typer.prompt(prompt, default=_FIX_INTERACTIVE_NO).strip().lower()
        if raw_answer == _FIX_INTERACTIVE_APPLY_ALL:
            approved.extend(replacements[index - _FIX_ENUMERATE_START :])
            break
        if raw_answer == _FIX_INTERACTIVE_SKIP_FILE:
            return
        if raw_answer == _FIX_INTERACTIVE_YES:
            approved.append(replacement)
    if approved:
        fix_result = apply_approved_replacements(file_path, approved)
        console.print(
            _FIX_APPLIED_MESSAGE.format(count=len(fix_result.replacements_applied), path=file_path)
        )


@app.command("fix")
def fix_command(
    path: Annotated[Path, typer.Argument(help=_FIX_PATH_HELP)] = Path("."),
    dry_run: Annotated[bool, typer.Option("--dry-run", help=_FIX_DRY_RUN_HELP)] = False,
    apply: Annotated[bool, typer.Option("--apply", help=_FIX_APPLY_HELP)] = False,
    patch: Annotated[bool, typer.Option("--patch", help=_FIX_PATCH_HELP)] = False,
    interactive: Annotated[bool, typer.Option("--interactive", help=_FIX_INTERACTIVE_HELP)] = False,
) -> None:
    """Replace detected PHI with synthetic data (dry-run, apply, patch, or interactive)."""
    selected_modes = [dry_run, apply, patch, interactive]
    mode_count = sum(selected_modes)
    if mode_count == 0:
        typer.echo(_FIX_NO_MODE_ERROR, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    if mode_count > 1:
        typer.echo(_FIX_MULTI_MODE_ERROR, err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR)
    target_files = _collect_target_files(path)
    if interactive:
        for target_file in target_files:
            _run_interactive_fix(target_file)
        return
    if dry_run:
        fix_mode = FixMode.DRY_RUN
    elif apply:
        fix_mode = FixMode.APPLY
    else:
        fix_mode = FixMode.PATCH
    for target_file in target_files:
        try:
            fix_result = fix_file(target_file, fix_mode)
        except MissingOptionalDependencyError:
            typer.echo(_FIX_FAKER_MISSING_MESSAGE, err=True)
            raise typer.Exit(code=EXIT_CODE_ERROR) from None
        _print_fix_result(fix_result, fix_mode)
