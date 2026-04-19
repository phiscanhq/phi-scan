"""V2 renderer: scan-complete footer section."""

from __future__ import annotations

from pathlib import Path

from rich import box as rich_box
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel
from rich.table import Table

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
_FOOTER_COLUMN_GAP: int = 2
_SUMMARY_RATIO: int = 3
_NEXT_STEPS_RATIO: int = 2
_NARROW_TERMINAL_THRESHOLD: int = 100
_PANEL_PADDING: tuple[int, int] = (1, 2)


def _build_violation_summary(scan_result: ScanResult, unique_action_count: int) -> str:
    """Build the summary column content for a violation scan-complete card."""
    risk_label = scan_result.risk_level.value
    total = len(scan_result.findings)
    high = scan_result.severity_counts.get(SeverityLevel.HIGH, 0)
    medium = scan_result.severity_counts.get(SeverityLevel.MEDIUM, 0)
    low = scan_result.severity_counts.get(SeverityLevel.LOW, 0)
    files_with = scan_result.files_with_findings
    files_total = scan_result.files_scanned

    severity_mix = (
        f"[red]high {high}[/red]   [yellow]medium {medium}[/yellow]   [green]low {low}[/green]"
    )

    return (
        f"[bold red]{VIOLATION_MARKER} VIOLATION[/bold red]\n\n"
        f"Risk level:  [bold red]{risk_label}[/bold red]\n\n"
        f"Findings:    [bold]{total}[/bold]  {SEPARATOR}  {severity_mix}\n"
        f"Files:       {files_with} of {files_total} contain PHI\n"
        f"Actions:     {unique_action_count} unique remediations required\n"
        f"Elapsed:     {scan_result.scan_duration:.2f} s"
    )


def _build_violation_next_steps(report_path: Path | None) -> str:
    """Build the next-steps column (plus embedded report-path hint)."""
    lines: list[str] = ["[bold]Next steps[/bold]", ""]

    if report_path is not None:
        lines.append(f"  {ARROW} open {escape_markup(str(report_path))}")
    else:
        lines.append(f"  {ARROW} full report: run with --output html")

    lines.append(f"  {ARROW} phi-scan fix --interactive")
    lines.append(f"  {ARROW} phi-scan scan . --verbose")
    lines.append("")
    lines.append("[bold red]EXIT 1[/bold red]")
    lines.append("[dim]Blocked until findings are remediated")
    lines.append("or suppressed with [bold yellow]# phi-scan:ignore[/bold yellow].[/dim]")

    return "\n".join(lines)


def _build_clean_summary(scan_result: ScanResult) -> str:
    """Build the summary column content for a clean scan-complete card."""
    return (
        f"[bold green]{CLEAN_MARKER} CLEAN[/bold green]\n\n"
        f"Files:       {scan_result.files_scanned} scanned\n"
        f"Findings:    0\n"
        f"Elapsed:     {scan_result.scan_duration:.2f} s"
    )


def _build_clean_next_steps() -> str:
    """Build the next-steps column for a clean scan."""
    return (
        f"[bold]Next steps[/bold]\n\n"
        f"  {ARROW} No action required.\n"
        f"  {ARROW} Pipeline clear {EM_DASH} exit code 0."
    )


def _build_two_column_layout(summary: str, next_steps: str) -> Table:
    """Wide-terminal layout: summary and next-steps side-by-side."""
    layout = Table.grid(expand=True, padding=(0, _FOOTER_COLUMN_GAP))
    layout.add_column(ratio=_SUMMARY_RATIO)
    layout.add_column(ratio=_NEXT_STEPS_RATIO)
    layout.add_row(summary, next_steps)
    return layout


def _build_single_column_layout(summary: str, next_steps: str) -> Table:
    """Narrow-terminal layout: stack summary over next-steps."""
    layout = Table.grid(expand=True)
    layout.add_column()
    layout.add_row(summary)
    layout.add_row("")
    layout.add_row(next_steps)
    return layout


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
        summary = _build_clean_summary(scan_result)
        next_steps = _build_clean_next_steps()
        border_style = "bold green"
    else:
        summary = _build_violation_summary(scan_result, unique_action_count)
        next_steps = _build_violation_next_steps(report_path)
        border_style = "bold red"

    is_narrow_terminal = console.width < _NARROW_TERMINAL_THRESHOLD
    if is_narrow_terminal:
        layout = _build_single_column_layout(summary, next_steps)
    else:
        layout = _build_two_column_layout(summary, next_steps)

    console.print(
        Panel(
            layout,
            box=rich_box.ROUNDED,
            border_style=border_style,
            padding=_PANEL_PADDING,
        )
    )
