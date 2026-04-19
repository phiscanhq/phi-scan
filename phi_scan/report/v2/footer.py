"""V2 renderer: scan-complete footer section."""

from __future__ import annotations

from pathlib import Path

from rich import box as rich_box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel

from phi_scan.constants import SeverityLevel
from phi_scan.models import ScanResult
from phi_scan.report.v2.glyphs import (
    ARROW,
    CLEAN_MARKER,
    EM_DASH,
    SECTION_BAR,
    SEPARATOR,
    VIOLATION_MARKER,
)

_SECTION_HEADER_STYLE: str = "bold green"
_SECTION_BAR_STYLE: str = "green"


def _build_violation_left(scan_result: ScanResult, unique_action_count: int) -> str:
    """Build the left column content for a violation scan-complete card."""
    risk_label = scan_result.risk_level.value
    total = len(scan_result.findings)
    high = scan_result.severity_counts.get(SeverityLevel.HIGH, 0)
    medium = scan_result.severity_counts.get(SeverityLevel.MEDIUM, 0)
    low = scan_result.severity_counts.get(SeverityLevel.LOW, 0)
    files_with = scan_result.files_with_findings
    files_total = scan_result.files_scanned

    return (
        f"[bold red]{VIOLATION_MARKER} VIOLATION[/bold red]\n\n"
        f"Risk level:  [bold red]{risk_label}[/bold red]\n\n"
        f"Findings:    [bold]{total}[/bold]  {SEPARATOR}  "
        f"high {high}   medium {medium}   low {low}\n"
        f"Files:       {files_with} of {files_total} contain PHI\n"
        f"Actions:     {unique_action_count} unique remediations required\n"
        f"Elapsed:     {scan_result.scan_duration:.2f} s"
    )


def _build_violation_right(report_path: Path | None) -> str:
    """Build the right column content with next steps and exit code explanation."""
    next_steps = "[bold]Next steps[/bold]\n\n"

    if report_path is not None:
        next_steps += f"  {ARROW}  open   {report_path}\n"

    next_steps += (
        f"  {ARROW}  run    phi-scan fix --interactive\n"
        f"  {ARROW}  rerun  phi-scan scan . --verbose\n"
    )

    exit_panel = (
        "\n[bold red]EXIT 1[/bold red]\n"
        "[dim]Pipeline blocked until findings are\n"
        "remediated or explicitly suppressed with\n"
        "[bold yellow]# phi-scan:ignore[/bold yellow] comments.[/dim]"
    )

    return next_steps + exit_panel


def _build_clean_left(scan_result: ScanResult) -> str:
    """Build the left column content for a clean scan-complete card."""
    return (
        f"[bold green]{CLEAN_MARKER} CLEAN[/bold green]\n\n"
        f"Files:       {scan_result.files_scanned} scanned\n"
        f"Findings:    0\n"
        f"Elapsed:     {scan_result.scan_duration:.2f} s"
    )


def _build_clean_right() -> str:
    """Build the right column content for a clean scan."""
    return (
        f"[bold]Next steps[/bold]\n\n"
        f"  {ARROW}  No action required.\n"
        f"  {ARROW}  Pipeline clear {EM_DASH} exit code 0."
    )


def render_scan_complete(
    console: Console,
    scan_result: ScanResult,
    unique_action_count: int,
    report_path: Path | None,
) -> None:
    """Render the SCAN COMPLETE footer section."""
    console.print()
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]{SECTION_BAR}[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]SCAN COMPLETE[/{_SECTION_HEADER_STYLE}]"
    )
    console.print()

    if scan_result.is_clean:
        left_content = _build_clean_left(scan_result)
        right_content = _build_clean_right()
        border_style = "bold green"
    else:
        left_content = _build_violation_left(scan_result, unique_action_count)
        right_content = _build_violation_right(report_path)
        border_style = "bold red"

    left_panel = Panel(left_content, box=rich_box.ROUNDED, expand=True, padding=(1, 2))
    right_panel = Panel(right_content, box=rich_box.ROUNDED, expand=True, padding=(1, 2))

    console.print(
        Panel(
            Columns([left_panel, right_panel], equal=True, expand=True),
            box=rich_box.ROUNDED,
            border_style=border_style,
            padding=(0, 0),
        )
    )
