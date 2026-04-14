"""Report file-writing helpers for the `phi-scan scan` command.

Isolates OS-facing file writes (text and binary) and binary-report
generation (PDF / HTML) from the format dispatch logic in
``cli/report.py``. Split out so that the text-format serializer path
and the binary-report trend-chart path do not share a module with the
higher-level dispatch function.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from phi_scan.audit import query_recent_scans
from phi_scan.constants import (
    DEFAULT_DATABASE_PATH,
    DEFAULT_TEXT_ENCODING,
    EXIT_CODE_ERROR,
    OutputFormat,
)
from phi_scan.report import generate_html_report, generate_pdf_report

if TYPE_CHECKING:
    from collections.abc import Callable

    from phi_scan.cli.report import ScanOutputOptions
    from phi_scan.models import ScanResult

__all__ = [
    "generate_report_bytes",
    "write_binary_report",
    "write_report_text_to_file",
]

_UNEXPECTED_BINARY_FORMAT_ERROR: str = (
    "generate_report_bytes received unexpected output format {format!r} — "
    "only OutputFormat.PDF and OutputFormat.HTML are supported"
)
_REPORT_PATH_BINARY_FORMAT_REQUIRED_ERROR: str = (
    "--output {format} requires --report-path <file.{format}> "
    "-- binary formats cannot be written to stdout."
)
_REPORT_PATH_WRITE_ERROR: str = "Failed to write report to {path!r}: {error}"
_REPORT_PATH_WRITTEN_MESSAGE: str = "Report written to {path}"
_TREND_CHART_LOOKBACK_DAYS: int = 30


def _invoke_report_writer(write_callable: Callable[[Path], object], report_path: Path) -> None:
    """Invoke a write callable on report_path, translating OS errors into typer.Exit."""
    try:
        write_callable(report_path)
    except OSError as write_error:
        typer.echo(_REPORT_PATH_WRITE_ERROR.format(path=report_path, error=write_error), err=True)
        raise typer.Exit(code=EXIT_CODE_ERROR) from write_error
    typer.echo(_REPORT_PATH_WRITTEN_MESSAGE.format(path=report_path), err=True)


def write_report_text_to_file(content: str, report_path: Path) -> None:
    """Write serialized report content to a file and confirm on stderr."""
    _invoke_report_writer(
        lambda destination_path: destination_path.write_text(
            content, encoding=DEFAULT_TEXT_ENCODING
        ),
        report_path,
    )


def _write_report_bytes_to_file(content: bytes, report_path: Path) -> None:
    """Write binary report content (PDF or HTML) to a file and confirm on stderr."""
    _invoke_report_writer(
        lambda destination_path: destination_path.write_bytes(content),
        report_path,
    )


def generate_report_bytes(
    scan_result: ScanResult,
    options: ScanOutputOptions,
    audit_rows: list[dict[str, object]],
) -> bytes:
    """Generate PDF or HTML report bytes from a scan result."""
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


def write_binary_report(scan_result: ScanResult, options: ScanOutputOptions) -> None:
    """Write the rendered binary report to the path specified in options."""
    if options.report_path is None:
        typer.echo(
            _REPORT_PATH_BINARY_FORMAT_REQUIRED_ERROR.format(format=options.output_format.value),
            err=True,
        )
        raise typer.Exit(code=EXIT_CODE_ERROR)
    audit_rows = _fetch_report_audit_rows()
    report_bytes = generate_report_bytes(scan_result, options, audit_rows)
    _write_report_bytes_to_file(report_bytes, options.report_path)
