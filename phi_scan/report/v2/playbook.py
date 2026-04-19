"""V2 renderer: deduplicated remediation playbook section."""

from __future__ import annotations

from pathlib import Path

from rich import box as rich_box
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel

from phi_scan.constants import SeverityLevel
from phi_scan.report.v2.models import RemediationAction

_SECTION_HEADER_STYLE: str = "bold green"
_SECTION_BAR_STYLE: str = "green"

_SEVERITY_PILL_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "reverse red",
    SeverityLevel.MEDIUM: "reverse yellow",
    SeverityLevel.LOW: "reverse green",
    SeverityLevel.INFO: "reverse dim",
}

_SEVERITY_BORDER_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "green",
    SeverityLevel.INFO: "dim",
}

_CONFIDENCE_DOT_FILLED: str = "●"
_CONFIDENCE_DOT_EMPTY: str = "○"
_CONFIDENCE_DOT_COUNT: int = 5

_MAX_DISPLAYED_LINES: int = 12
_MAX_HINT_DISPLAY_LENGTH: int = 100


def _render_confidence_dots(mean_confidence: float) -> str:
    """Render mean confidence as a 5-dot scale."""
    filled_count = round(mean_confidence * _CONFIDENCE_DOT_COUNT)
    filled_count = max(0, min(_CONFIDENCE_DOT_COUNT, filled_count))
    empty_count = _CONFIDENCE_DOT_COUNT - filled_count
    return _CONFIDENCE_DOT_FILLED * filled_count + _CONFIDENCE_DOT_EMPTY * empty_count


def _format_lines_compact(affected_lines: tuple[tuple[Path, int], ...]) -> str:
    """Format affected lines with range compression for consecutive lines."""
    if not affected_lines:
        return ""

    line_numbers = sorted(pair[1] for pair in affected_lines)

    if len(line_numbers) <= _MAX_DISPLAYED_LINES:
        ranges = _compress_line_ranges(line_numbers)
        parts: list[str] = []
        for start, end in ranges:
            if start == end:
                parts.append(f"line {start}")
            else:
                parts.append(f"lines {start}–{end}")
        return "  ·  ".join(parts)

    shown = line_numbers[:_MAX_DISPLAYED_LINES]
    ranges = _compress_line_ranges(shown)
    parts = []
    for start, end in ranges:
        if start == end:
            parts.append(str(start))
        else:
            parts.append(f"{start}–{end}")
    remaining = len(line_numbers) - _MAX_DISPLAYED_LINES
    return "lines " + ", ".join(parts) + f" (+{remaining} more)"


def _compress_line_ranges(line_numbers: list[int]) -> list[tuple[int, int]]:
    """Compress consecutive line numbers into (start, end) ranges."""
    if not line_numbers:
        return []

    ranges: list[tuple[int, int]] = []
    start = line_numbers[0]
    end = start

    for line_number in line_numbers[1:]:
        if line_number == end + 1:
            end = line_number
        else:
            ranges.append((start, end))
            start = line_number
            end = line_number

    ranges.append((start, end))
    return ranges


def _render_action_card(
    console: Console,
    action: RemediationAction,
    index: int,
) -> None:
    """Render a single remediation action card."""
    border_style = _SEVERITY_BORDER_STYLE[action.highest_severity]
    pill_style = _SEVERITY_PILL_STYLE[action.highest_severity]
    pill = f"[{pill_style}] {action.highest_severity.value.upper()} [/{pill_style}]"
    dots = _render_confidence_dots(action.mean_confidence)

    lines_str = _format_lines_compact(action.affected_lines)

    finding_word = "findings" if action.finding_count != 1 else "finding"
    count_label = f"[bold]{action.finding_count}[/bold] {finding_word}"

    body = (
        f" ({index})  [bold]{escape_markup(action.title)}[/bold]"
        f"     {count_label}  {pill}\n"
        f"      [dim]{escape_markup(action.remediation_hint[:_MAX_HINT_DISPLAY_LENGTH])}[/dim]\n"
        f"      [dim]{lines_str}[/dim]\n"
        f"      {dots}"
    )

    console.print(Panel(body, box=rich_box.ROUNDED, border_style=border_style, padding=(0, 1)))


def render_remediation_playbook(
    console: Console,
    actions: list[RemediationAction],
    total_finding_count: int,
    report_path: Path | None,
) -> None:
    """Render the REMEDIATION PLAYBOOK section."""
    console.print()
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]▎[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]REMEDIATION PLAYBOOK[/{_SECTION_HEADER_STYLE}]"
    )
    action_word = "action" if len(actions) == 1 else "actions"
    console.print(
        f"[dim]{len(actions)} unique {action_word} resolve all "
        f"{total_finding_count} findings. Each action shown once.[/dim]"
    )
    console.print()

    for index, action in enumerate(actions, start=1):
        _render_action_card(console, action, index)

    _render_full_report_footer(console, report_path)


def _render_full_report_footer(console: Console, report_path: Path | None) -> None:
    """Render the FULL REPORT footer with actual or suggested report paths."""
    console.print()

    if report_path is not None:
        body = f"[bold]FULL REPORT[/bold]\n  {escape_markup(str(report_path))}"
    else:
        body = (
            "[bold]FULL REPORT[/bold]\n"
            "  [dim]Generate full reports with:[/dim]\n"
            "  [dim]  phi-scan scan . --output json --report-path report.json[/dim]\n"
            "  [dim]  phi-scan scan . --output html --report-path report.html[/dim]\n"
            "  [dim]  phi-scan scan . --output sarif --report-path report.sarif[/dim]"
        )

    console.print(
        Panel(
            body,
            box=rich_box.ROUNDED,
            border_style="dim",
            padding=(0, 1),
        )
    )
