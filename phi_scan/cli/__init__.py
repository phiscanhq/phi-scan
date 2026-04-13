"""Typer CLI entry point for PhiScan."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import pathspec
import typer
from rich.live import Live
from rich.progress import Progress, TaskID
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
from phi_scan.cli.baseline import baseline_app
from phi_scan.cli.config import config_app
from phi_scan.cli.explain import explain_app
from phi_scan.cli.plugins import plugins_app
from phi_scan.cli.report import (
    ScanOutputOptions,
    display_report_phase_header,
    emit_report_output,
    emit_verbose_phase,
    resolve_output_format,
)
from phi_scan.cli.scan_config import load_scan_config
from phi_scan.cli.watch import (
    WATCH_LOG_MAX_EVENTS,
    FileChangeMonitor,
    WatchConfig,
    display_watch_live_screen,
)
from phi_scan.compliance import (
    ComplianceFramework,
    InvalidFrameworkError,
    annotate_findings,
    parse_framework_flag,
)
from phi_scan.constants import (
    DEFAULT_DATABASE_PATH,
    DEFAULT_IGNORE_FILENAME,
    DEFAULT_TEXT_ENCODING,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    EXIT_CODE_VIOLATION,
    OutputFormat,
    PathspecMatchStyle,
)
from phi_scan.diff import get_changed_files_from_diff
from phi_scan.exceptions import (
    AuditKeyMissingError,
    AuditLogError,
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
    WatchEvent,
    build_dashboard_layout,
    create_scan_progress,
    display_banner,
    display_file_type_summary,
    display_phase_audit,
    display_phase_collecting,
    display_phase_scanning,
    display_scan_header,
    display_status_spinner,
    get_console,
)
from phi_scan.scanner import (
    MAX_WORKER_COUNT,
    MIN_WORKER_COUNT,
    build_scan_result,
    collect_scan_targets,
    execute_scan,
    is_path_excluded,
    load_ignore_patterns,
    run_parallel_scan,
    scan_file,
)

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
app.add_typer(plugins_app)

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

# ---------------------------------------------------------------------------
# Watch command
# ---------------------------------------------------------------------------

_WATCH_PATH_HELP: str = "Directory to watch for file system changes."

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
_PARALLEL_SCAN_PROGRESS_LABEL: str = f"scanning{_PROGRESS_FILENAME_ELLIPSIS}"
# Default worker count accepted by the --workers option.
_DEFAULT_WORKER_COUNT: int = MIN_WORKER_COUNT
# Error messages for out-of-range --workers values.
_WORKERS_BELOW_MINIMUM_ERROR: str = f"--workers must be at least {MIN_WORKER_COUNT}"
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
# Verbose phase messages (kept here — used by scan command orchestration)
# ---------------------------------------------------------------------------

_VERBOSE_PHASE_COLLECTING: str = "collecting scan targets"
_VERBOSE_PHASE_SCANNING: str = "scanning {count} file(s)"
_VERBOSE_PHASE_AUDIT: str = "writing audit record"

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
class _ScanPhaseOptions:
    """Execution-phase flags controlling phase headers and data selection.

    Kept separate from ScanOutputOptions because these flags control when and
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


@dataclass(frozen=True)
class _ProgressScanContext:
    """Arguments for _run_scan_with_progress and its sequential/parallel sub-helpers.

    Bundles all five inputs required by the progress-bar scan path into a single
    object so each helper stays within the three-argument limit. ``scan_targets``
    is stored as a tuple so the frozen=True guarantee extends to the ordered
    collection itself — preventing in-place mutation of the scan target list
    after the context has been constructed.
    """

    scan_targets: tuple[Path, ...]
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
        typer.BadParameter: If worker_count < MIN_WORKER_COUNT or > MAX_WORKER_COUNT.
    """
    if worker_count < MIN_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_BELOW_MINIMUM_ERROR)
    if worker_count > MAX_WORKER_COUNT:
        raise typer.BadParameter(_WORKERS_ABOVE_MAXIMUM_ERROR)


def _run_sequential_scan_with_progress(
    scan: _ProgressScanContext,
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
        scan.progress.update(scan.task_id, description=progress_label)
        all_findings.extend(scan_file(file_path, scan.config))
        scan.progress.update(scan.task_id, advance=1)
    return all_findings


def _run_parallel_scan_with_progress(
    scan: _ProgressScanContext,
) -> list[ScanFinding]:
    """Scan files concurrently, advancing the progress bar as each file completes.

    Delegates the thread pool and ordering logic to ``scanner.run_parallel_scan``
    and supplies a per-file completion callback that ticks the Rich progress
    bar. Keeping a single parallel executor implementation prevents the CLI and
    scanner paths from diverging in thread safety, error handling, or ordering.

    Args:
        scan: Bundled scan targets, config, worker count, and progress bar state.

    Returns:
        All findings in scan_targets order.
    """

    def _advance_progress_bar(completed_file_path: Path) -> None:
        # completed_file_path is supplied by the run_parallel_scan callback
        # contract but deliberately not displayed: the parallel progress
        # label is a fixed string, because completion order is
        # nondeterministic and showing file names mid-scan would cause the
        # label to jitter across threads.
        scan.progress.update(
            scan.task_id,
            description=_PARALLEL_SCAN_PROGRESS_LABEL,
            advance=1,
        )

    return run_parallel_scan(
        list(scan.scan_targets),
        scan.config,
        scan.worker_count,
        on_file_complete=_advance_progress_bar,
    )


def _run_scan_with_progress(
    scan: _ProgressScanContext,
) -> list[ScanFinding]:
    """Dispatch to sequential or parallel progress scanning based on worker_count.

    Args:
        scan: Bundled scan targets, config, worker count, and progress bar state.

    Returns:
        All findings in scan_targets order.
    """
    if scan.worker_count > MIN_WORKER_COUNT:
        return _run_parallel_scan_with_progress(scan)
    return _run_sequential_scan_with_progress(scan)


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
        progress_scan_context = _ProgressScanContext(
            scan_targets=tuple(scan_targets),
            config=config,
            worker_count=execution_options.worker_count,
            progress=progress,
            task_id=task_id,
        )
        all_findings = _run_scan_with_progress(progress_scan_context)
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
    emit_verbose_phase(_VERBOSE_PHASE_COLLECTING, is_verbose)
    scan_targets = _resolve_scan_targets(target_options)
    if is_rich_mode:
        display_file_type_summary(scan_targets)
        display_phase_scanning()
    emit_verbose_phase(_VERBOSE_PHASE_SCANNING.format(count=len(scan_targets)), is_verbose)
    return scan_targets


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
    output_options: ScanOutputOptions,
    phase_options: _ScanPhaseOptions,
) -> None:
    """Display the audit phase Rich banner and verbose marker."""
    if output_options.is_rich_mode:
        display_phase_audit()
    emit_verbose_phase(_VERBOSE_PHASE_AUDIT, phase_options.is_verbose)


def _persist_audit_record(
    scan_result: ScanResult,
    scan_config: ScanConfig,
    output_options: ScanOutputOptions,
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
    output_format_enum = resolve_output_format(output_format)
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
    # which is acceptable — output_options has no effect until emit_scan_output is called.
    execution_options = _ScanExecutionOptions(
        worker_count=worker_count,
        should_show_progress=is_rich_mode,
    )
    scan_result = _execute_scan_with_progress(scan_targets, scan_config, execution_options)
    framework_annotations = (
        annotate_findings(scan_result.findings, enabled_frameworks) if enabled_frameworks else None
    )
    output_options = ScanOutputOptions(
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
    display_report_phase_header(output_options, phase_options.is_verbose)
    emit_report_output(scan_result, output_options, phase_options.should_use_baseline)


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
    watch_config = WatchConfig(watch_root=watch_path, scan_config=ScanConfig())
    watch_events: deque[WatchEvent] = deque(maxlen=WATCH_LOG_MAX_EVENTS)
    event_handler = FileChangeMonitor(watch_config, watch_events)
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)  # type: ignore[no-untyped-call]
    observer.start()  # type: ignore[no-untyped-call]
    try:
        display_watch_live_screen(watch_path, watch_events)
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
