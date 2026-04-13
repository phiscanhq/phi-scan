"""Typer CLI entry point for PhiScan."""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.live import Live
from watchdog.observers import Observer

from phi_scan import __version__
from phi_scan.audit import (
    ensure_current_schema,
    get_last_scan,
    insert_scan_event,
    query_recent_scans,
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
from phi_scan.cli._shared import (
    _DEFAULT_WORKER_COUNT,
    _GIT_DIR_NOT_FOUND_MESSAGE,
    _GIT_DIR_PATH,
    _HOOK_SYMLINKED_COMPONENT_ERROR,
    _LOG_LEVEL_DEBUG,
    _LOG_LEVEL_ERROR,
    _LOG_LEVEL_INFO,
    _LOG_LEVEL_MAP,
    _LOG_LEVEL_WARNING,
    _PARALLEL_SCAN_PROGRESS_LABEL,
    _PROGRESS_FILENAME_ELLIPSIS,
    _PROGRESS_FILENAME_MAX_CHARS,
    _VERSION_FLAG_HELP,
    _VERSION_OUTPUT_FORMAT,
    _WORKERS_ABOVE_MAXIMUM_ERROR,
    _WORKERS_BELOW_MINIMUM_ERROR,
    _configure_logging,
    _echo_version,
    _load_combined_ignore_patterns,
    _normalize_diff_path,
    _ProgressScanContext,
    _reject_hook_path_with_symlinked_component,
    _reject_missing_git_directory,
    _resolve_scan_targets,
    _ScanExecutionOptions,
    _ScanPhaseOptions,
    _ScanTargetOptions,
    _truncate_filename_for_progress,
    _validate_worker_count,
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
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    OutputFormat,
)
from phi_scan.exceptions import (
    AuditKeyMissingError,
    AuditLogError,
    NotificationError,
)
from phi_scan.logging_config import get_logger
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
    execute_scan,
    run_parallel_scan,
    scan_file,
)

# Private helpers re-exported for backwards-compatible imports from
# ``phi_scan.cli`` (tests and historical callers reach for these names).
__all__ = [
    "_DEFAULT_WORKER_COUNT",
    "_GIT_DIR_NOT_FOUND_MESSAGE",
    "_GIT_DIR_PATH",
    "_HOOK_SYMLINKED_COMPONENT_ERROR",
    "_LOG_LEVEL_DEBUG",
    "_LOG_LEVEL_ERROR",
    "_LOG_LEVEL_INFO",
    "_LOG_LEVEL_MAP",
    "_LOG_LEVEL_WARNING",
    "_PARALLEL_SCAN_PROGRESS_LABEL",
    "_PROGRESS_FILENAME_ELLIPSIS",
    "_PROGRESS_FILENAME_MAX_CHARS",
    "_ProgressScanContext",
    "_ScanExecutionOptions",
    "_ScanPhaseOptions",
    "_ScanTargetOptions",
    "_VERSION_FLAG_HELP",
    "_VERSION_OUTPUT_FORMAT",
    "_WORKERS_ABOVE_MAXIMUM_ERROR",
    "_WORKERS_BELOW_MINIMUM_ERROR",
    "_configure_logging",
    "_echo_version",
    "_load_combined_ignore_patterns",
    "_normalize_diff_path",
    "_reject_hook_path_with_symlinked_component",
    "_reject_missing_git_directory",
    "_resolve_scan_targets",
    "_truncate_filename_for_progress",
    "_validate_worker_count",
    "app",
]

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
# Dashboard
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Error and warning messages
# ---------------------------------------------------------------------------

_AUDIT_WRITE_FAILURE_WARNING: str = "Audit log write failed — scan result not persisted: {error}"
_AUDIT_KEY_MISSING_DEBUG: str = (
    "Audit log skipped — encryption key not found. Run 'phi-scan setup' to generate it."
)
_NOTIFICATION_EMAIL_FAILURE_WARNING: str = "Email notification failed: {error}"
_NOTIFICATION_WEBHOOK_FAILURE_WARNING: str = "Webhook notification failed: {error}"
_SPINNER_NOTIFY_MESSAGE: str = "Sending notifications…"

# ---------------------------------------------------------------------------
# Verbose phase messages (kept here — used by scan command orchestration)
# ---------------------------------------------------------------------------

_VERBOSE_PHASE_COLLECTING: str = "collecting scan targets"
_VERBOSE_PHASE_SCANNING: str = "scanning {count} file(s)"
_VERBOSE_PHASE_AUDIT: str = "writing audit record"

# ---------------------------------------------------------------------------
# Internal helpers — scan command
# ---------------------------------------------------------------------------


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
# Internal helpers — install-hook / uninstall-hook
# ---------------------------------------------------------------------------


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


from phi_scan.cli.history import display_history, display_last_scan  # noqa: E402
from phi_scan.cli.hooks import (  # noqa: E402
    download_models,
    initialize_project,
    install_hook,
    uninstall_hook,
)

app.command("report")(display_last_scan)
app.command("history")(display_history)
app.command("install-hook")(install_hook)
app.command("uninstall-hook")(uninstall_hook)
app.command("init")(initialize_project)
app.command("setup")(download_models)


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
# Fix command — registered from phi_scan.cli.fix
# ---------------------------------------------------------------------------

from phi_scan.cli.fix import fix_command  # noqa: E402

app.command("fix")(fix_command)
