"""Scan output and report domain: format dispatch, file writing, baseline output.

Extracted from ``cli.py`` to isolate the report rendering and serialization
logic from the main CLI wiring and command orchestration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import typer

from phi_scan.audit import query_recent_scans
from phi_scan.baseline import (
    BaselineSnapshot,
    filter_baselined_findings,
    load_baseline,
)
from phi_scan.constants import (
    BASELINE_LOAD_ERROR_MESSAGE,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_DATABASE_PATH,
    DEFAULT_TEXT_ENCODING,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    EXIT_CODE_VIOLATION,
    IMPLEMENTED_OUTPUT_FORMATS,
    OutputFormat,
)
from phi_scan.exceptions import BaselineError
from phi_scan.output import (
    display_baseline_scan_notice,
    display_category_breakdown,
    display_clean_result,
    display_clean_summary_panel,
    display_code_context_panel,
    display_exit_code_message,
    display_file_tree,
    display_findings_table,
    display_phase_report,
    display_risk_level_badge,
    display_severity_inline,
    display_violation_alert,
    display_violation_summary_panel,
    format_codequality,
    format_csv,
    format_gitlab_sast,
    format_json,
    format_junit,
    format_sarif,
)
from phi_scan.report import generate_html_report, generate_pdf_report

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from phi_scan.compliance import ComplianceControl
    from phi_scan.models import ScanFinding, ScanResult

__all__ = [
    "ScanOutputOptions",
    "display_rich_scan_results",
    "emit_report_output",
    "emit_scan_output",
    "emit_scan_output_with_baseline",
    "emit_verbose_phase",
    "generate_report_bytes",
    "resolve_output_format",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IMPLEMENTED_FORMAT_NAMES: str = ", ".join(sorted(fmt.value for fmt in IMPLEMENTED_OUTPUT_FORMATS))
_UNSUPPORTED_OUTPUT_FORMAT_ERROR: str = (
    "Output format {fmt!r} is not yet implemented. "
    f"Currently supported: {_IMPLEMENTED_FORMAT_NAMES}. "
    "Additional formats are not yet available."
)
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
_REPORT_PATH_WRITE_ERROR: str = "Failed to write report to {path!r}: {error}"
_REPORT_PATH_WRITTEN_MESSAGE: str = "Report written to {path}"
_VERBOSE_TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S"
_VERBOSE_PHASE_PREFIX: str = "[{timestamp}] Phase: {message}"
_VERBOSE_PHASE_REPORT: str = "rendering report"
_TREND_CHART_LOOKBACK_DAYS: int = 30

# ---------------------------------------------------------------------------
# Output format serializer dispatch table
# ---------------------------------------------------------------------------

# Must stay in sync with IMPLEMENTED_OUTPUT_FORMATS - {OutputFormat.TABLE}.
# TABLE is handled before this dict is consulted (emit_scan_output checks it
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

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanOutputOptions:
    """Options controlling how scan results are rendered or serialized.

    Groups output-rendering flags passed to emit_scan_output and its helpers.
    Execution-phase flags (verbosity, baseline mode) live in _ScanPhaseOptions.
    """

    output_format: OutputFormat
    is_rich_mode: bool
    report_path: Path | None
    scan_target: Path = field(default_factory=lambda: Path("."))
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None = None


# ---------------------------------------------------------------------------
# Output format resolution
# ---------------------------------------------------------------------------


def resolve_output_format(output_format: str) -> OutputFormat:
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


# ---------------------------------------------------------------------------
# Verbose phase marker
# ---------------------------------------------------------------------------


def emit_verbose_phase(message: str, is_verbose: bool) -> None:
    """Write a timestamped phase marker to stderr when verbose mode is active.

    Args:
        message: Short description of the current scan phase.
        is_verbose: When False this function is a no-op.
    """
    if not is_verbose:
        return
    timestamp = datetime.now().strftime(_VERBOSE_TIMESTAMP_FORMAT)
    typer.echo(_VERBOSE_PHASE_PREFIX.format(timestamp=timestamp, message=message), err=True)


# ---------------------------------------------------------------------------
# Rich scan results display
# ---------------------------------------------------------------------------


def display_rich_scan_results(scan_result: ScanResult) -> None:
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


# ---------------------------------------------------------------------------
# Report file writing
# ---------------------------------------------------------------------------


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


def generate_report_bytes(
    scan_result: ScanResult,
    options: ScanOutputOptions,
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


def _write_binary_report(scan_result: ScanResult, options: ScanOutputOptions) -> None:
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
    report_bytes = generate_report_bytes(scan_result, options, audit_rows)
    _write_report_bytes_to_file(report_bytes, options.report_path)


# ---------------------------------------------------------------------------
# Scan output dispatch
# ---------------------------------------------------------------------------


def emit_scan_output(scan_result: ScanResult, options: ScanOutputOptions) -> None:
    """Render or serialize scan results in the requested output format.

    For table format in Rich mode, delegates to display_rich_scan_results.
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
            display_rich_scan_results(scan_result)
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
# Baseline-aware scan output
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


def emit_scan_output_with_baseline(
    scan_result: ScanResult, output_options: ScanOutputOptions
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
        emit_scan_output(scan_result, output_options)
        raise typer.Exit(code=EXIT_CODE_CLEAN if scan_result.is_clean else EXIT_CODE_VIOLATION)
    new_findings, baselined_findings = filter_baselined_findings(scan_result.findings, snapshot)
    if output_options.is_rich_mode:
        _display_rich_baseline_results(scan_result, new_findings, len(baselined_findings))
    else:
        emit_scan_output(scan_result, output_options)
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
# Report phase orchestration helpers
# ---------------------------------------------------------------------------


def display_report_phase_header(
    output_options: ScanOutputOptions,
    is_verbose: bool,
) -> None:
    """Display the report phase Rich banner and verbose marker."""
    if output_options.is_rich_mode:
        display_phase_report()
    emit_verbose_phase(_VERBOSE_PHASE_REPORT, is_verbose)


def emit_report_output(
    scan_result: ScanResult,
    output_options: ScanOutputOptions,
    should_use_baseline: bool,
) -> NoReturn:
    """Emit scan output via the appropriate path; always raises typer.Exit.

    Both branches terminate via typer.Exit: the baseline path delegates to
    emit_scan_output_with_baseline, which raises before returning; the
    standard path raises explicitly below.

    Args:
        scan_result: Completed scan result from _execute_scan_with_progress.
        output_options: Controls output format, rich mode, and report path.
        should_use_baseline: Whether to apply baseline filtering.
    """
    if should_use_baseline:
        emit_scan_output_with_baseline(scan_result, output_options)
    else:
        emit_scan_output(scan_result, output_options)
        raise typer.Exit(code=EXIT_CODE_CLEAN if scan_result.is_clean else EXIT_CODE_VIOLATION)
