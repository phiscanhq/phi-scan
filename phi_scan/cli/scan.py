"""`phi-scan scan` command. The `watch` command now lives in `phi_scan.cli.watch`."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from phi_scan import __version__
from phi_scan.audit import (
    _get_current_branch,
    _get_current_repository_path,
    ensure_current_schema,
    insert_scan_event,
)
from phi_scan.cli._shared import (
    _DEFAULT_WORKER_COUNT,
    _LOG_LEVEL_DEBUG,
    _LOG_LEVEL_WARNING,
    _configure_logging,
    _resolve_scan_targets,
    _ScanExecutionOptions,
    _ScanPhaseOptions,
    _ScanTargetOptions,
    _validate_worker_count,
)
from phi_scan.cli.ci_dispatch import CIIntegrationOptions, dispatch_ci_integrations
from phi_scan.cli.report import (
    ScanOutputOptions,
    display_report_phase_header,
    emit_report_output,
    emit_verbose_phase,
    resolve_output_format,
)
from phi_scan.cli.scan_config import load_scan_config
from phi_scan.cli.scan_progress import execute_scan_with_progress
from phi_scan.compliance import (
    ComplianceFramework,
    InvalidFrameworkError,
    annotate_findings,
    parse_framework_flag,
)
from phi_scan.constants import EXIT_CODE_ERROR, OutputFormat
from phi_scan.exceptions import AuditKeyMissingError, AuditLogError, NotificationError
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanConfig, ScanResult
from phi_scan.notifier import (
    NotificationRequest,
    send_email_notification,
    send_webhook_notification,
)
from phi_scan.output import (
    display_banner,
    display_file_type_summary,
    display_phase_audit,
    display_phase_collecting,
    display_phase_scanning,
    display_scan_header,
    display_status_spinner,
)
from phi_scan.scanner import MAX_WORKER_COUNT

_logger = get_logger("cli")

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
_SCAN_FRAMEWORK_HELP: str = (
    "Comma-separated compliance frameworks to annotate findings with "
    f"(e.g. {ComplianceFramework.GDPR},{ComplianceFramework.SOC2},{ComplianceFramework.HITRUST}). "
    f"{ComplianceFramework.HIPAA} is always active. "
    "Run `phi-scan explain frameworks` for all supported values."
)
_FRAMEWORK_PARSE_ERROR: str = "Invalid --framework value: {error}"

_SPINNER_CONFIG_LOAD_MESSAGE: str = "Loading configuration…"
_SPINNER_AUDIT_WRITE_MESSAGE: str = "Writing audit log…"
_SPINNER_NOTIFY_MESSAGE: str = "Sending notifications…"

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
_SCAN_IMPORT_SECURITY_HUB_HELP: str = (
    "Import findings to AWS Security Hub as ASFF. "
    "Requires AWS_SECURITY_HUB=true, AWS_ACCOUNT_ID, and the AWS CLI. "
    "Transmits classification metadata only — never raw PHI values or value hashes."
)
_SCAN_WORKERS_HELP: str = (
    f"Number of worker threads for parallel file scanning. Default 1 (sequential). "
    f"Values above 1 enable concurrent scanning up to {MAX_WORKER_COUNT}. "
    "Output ordering is deterministic regardless of thread completion order."
)
_SCAN_REPORT_FORMAT_HELP: str = (
    "Terminal report format: v1 (current default) or v2 (redesigned grouped output). "
    "Also settable via PHI_SCAN_REPORT_V2=1 environment variable."
)
_REPORT_FORMAT_V2: str = "v2"
_REPORT_FORMAT_V1: str = "v1"
_REPORT_FORMAT_ENV_VAR: str = "PHI_SCAN_REPORT_V2"
_REPORT_FORMAT_ENV_TRUTHY: str = "1"

_AUDIT_WRITE_FAILURE_WARNING: str = "Audit log write failed — scan result not persisted: {error}"
_AUDIT_KEY_MISSING_DEBUG: str = (
    "Audit log skipped — encryption key not found. Run 'phi-scan setup' to generate it."
)
_NOTIFICATION_EMAIL_FAILURE_WARNING: str = "Email notification failed: {error}"
_NOTIFICATION_WEBHOOK_FAILURE_WARNING: str = "Webhook notification failed: {error}"

_VERBOSE_PHASE_COLLECTING: str = "collecting scan targets"
_VERBOSE_PHASE_SCANNING: str = "scanning {count} file(s)"
_VERBOSE_PHASE_AUDIT: str = "writing audit record"


def _write_audit_record(
    scan_result: ScanResult,
    database_path: Path,
    notifications_sent: list[str] | None = None,
) -> None:
    """Persist the scan result to the SQLite audit log.

    Audit failures are logged as warnings and do not abort the scan.
    HIPAA §164.530(j) requires best-effort audit retention — a write failure
    must be surfaced to operators but must not block the CI gate decision.
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
    """
    config = scan_config.notification_config
    should_notify = not config.notify_on_violation_only or not scan_result.is_clean
    if not should_notify:
        return []
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
    """Parse the --framework flag and exit with an error on unknown framework names."""
    try:
        return parse_framework_flag(framework_flag_value)
    except InvalidFrameworkError as framework_error:
        typer.echo(_FRAMEWORK_PARSE_ERROR.format(error=framework_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from framework_error


def _collect_scan_targets_for_phase(
    target_options: _ScanTargetOptions,
    is_rich_mode: bool,
    is_verbose: bool,
) -> list[Path]:
    """Emit collection-phase feedback and return the resolved scan target list."""
    if is_rich_mode:
        display_phase_collecting()
    emit_verbose_phase(_VERBOSE_PHASE_COLLECTING, is_verbose)
    scan_targets = _resolve_scan_targets(target_options)
    if is_rich_mode:
        display_file_type_summary(scan_targets)
        display_phase_scanning()
    emit_verbose_phase(_VERBOSE_PHASE_SCANNING.format(count=len(scan_targets)), is_verbose)
    return scan_targets


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
    """Dispatch notifications then persist the scan result with audit metadata."""
    with display_status_spinner(_SPINNER_NOTIFY_MESSAGE, is_active=output_options.is_rich_mode):
        sent_channels = _dispatch_notifications(
            scan_result, scan_config, output_options.report_path
        )
    with display_status_spinner(
        _SPINNER_AUDIT_WRITE_MESSAGE, is_active=output_options.is_rich_mode
    ):
        _write_audit_record(scan_result, scan_config.database_path, sent_channels)


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
    should_import_to_security_hub: Annotated[
        bool, typer.Option("--import-security-hub", help=_SCAN_IMPORT_SECURITY_HUB_HELP)
    ] = False,
    worker_count: Annotated[
        int, typer.Option("--workers", help=_SCAN_WORKERS_HELP)
    ] = _DEFAULT_WORKER_COUNT,
    report_format: Annotated[
        str, typer.Option("--report-format", help=_SCAN_REPORT_FORMAT_HELP)
    ] = _REPORT_FORMAT_V1,
) -> None:
    """Scan a directory or file for PHI/PII.

    Parameters are Typer CLI declarations, not regular call-site arguments — the
    3-argument rule from CLAUDE.md applies to regular functions, not CLI commands
    whose parameters are read by Typer introspection.
    """
    _validate_worker_count(worker_count)
    effective_log_level = _LOG_LEVEL_DEBUG if is_verbose else log_level
    _configure_logging(effective_log_level, log_file, is_quiet)
    output_format_enum = resolve_output_format(output_format)
    enabled_frameworks = _resolve_framework_flag(framework)
    is_rich_mode = not is_quiet and output_format_enum is OutputFormat.TABLE
    is_v2 = (
        report_format == _REPORT_FORMAT_V2
        or os.environ.get(_REPORT_FORMAT_ENV_VAR) == _REPORT_FORMAT_ENV_TRUTHY
    )
    with display_status_spinner(_SPINNER_CONFIG_LOAD_MESSAGE, is_active=is_rich_mode):
        scan_config = load_scan_config(config_path, severity_threshold)
    if is_rich_mode and not is_v2:
        display_banner()
        display_scan_header(path, scan_config)
    if single_file is None and path.is_file():
        single_file = path
    target_options = _ScanTargetOptions(
        scan_root=path, diff_ref=diff_ref, single_file=single_file, config=scan_config
    )
    scan_targets = _collect_scan_targets_for_phase(target_options, is_rich_mode, is_verbose)
    execution_options = _ScanExecutionOptions(
        worker_count=worker_count,
        should_show_progress=is_rich_mode,
    )
    scan_result = execute_scan_with_progress(scan_targets, scan_config, execution_options)
    framework_annotations = (
        annotate_findings(scan_result.findings, enabled_frameworks) if enabled_frameworks else None
    )
    effective_threshold = severity_threshold if severity_threshold is not None else "low"
    output_options = ScanOutputOptions(
        output_format=output_format_enum,
        is_rich_mode=is_rich_mode,
        report_path=report_path,
        scan_target=path,
        framework_annotations=framework_annotations,
        is_v2=is_v2,
        is_verbose=is_verbose,
        severity_threshold_value=effective_threshold,
    )
    phase_options = _ScanPhaseOptions(
        is_verbose=is_verbose,
        should_use_baseline=should_use_baseline,
    )
    _display_audit_phase_header(output_options, phase_options)
    _persist_audit_record(scan_result, scan_config, output_options)
    integration_options = CIIntegrationOptions(
        should_post_comment=should_post_comment,
        should_set_status=should_set_status,
        should_upload_sarif=should_upload_sarif,
        should_import_to_security_hub=should_import_to_security_hub,
    )
    dispatch_ci_integrations(scan_result, integration_options, is_rich_mode)
    if not is_v2:
        display_report_phase_header(output_options, phase_options.is_verbose)
    emit_report_output(scan_result, output_options, phase_options.should_use_baseline)
