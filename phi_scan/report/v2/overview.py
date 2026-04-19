"""V2 renderer: executive summary section (title strip, status banner, stats, top actions, bars)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from rich import box as rich_box
from rich.columns import Columns
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel

from phi_scan import __version__
from phi_scan.constants import SeverityLevel
from phi_scan.models import ScanResult
from phi_scan.report.v2.aggregation import (
    compute_category_severity_distribution,
    compute_hotspot_count,
    group_by_line,
    rank_top_actions,
)
from phi_scan.report.v2.glyphs import (
    BAR_FILLED,
    CLEAN_MARKER,
    EM_DASH,
    SECTION_BAR,
    SEPARATOR,
    VIOLATION_MARKER,
)
from phi_scan.report.v2.models import LineAggregate, RemediationAction

_TITLE_TEMPLATE: str = (
    "[bold]phi-scan[/bold] v{version}   PHI / PII Scanner"
    f"  {SEPARATOR}  HIPAA Safe-Harbor aligned"
)
_TIMESTAMP_FORMAT: str = "%Y-%m-%d  %H:%M:%S"

_STATUS_VIOLATION: str = "VIOLATION"
_STATUS_CLEAN: str = "CLEAN"
_VIOLATION_SUBTITLE_TEMPLATE: str = f"Pipeline blocked {EM_DASH} {{risk}} risk level, exit code 1"
_CLEAN_SUBTITLE: str = "No PHI/PII detected. Pipeline clear."

_STAT_FINDINGS: str = "FINDINGS"
_STAT_HIGH: str = "HIGH"
_STAT_MEDIUM: str = "MEDIUM"
_STAT_LOW: str = "LOW"
_STAT_HOTSPOTS: str = "HOTSPOTS"

_BAR_MAX_WIDTH: int = 40
_BAR_DENOMINATOR_FLOOR: int = 1
_MAX_DISPLAYED_AFFECTED_LINES: int = 8
_NAME_COLUMN_WIDTH: int = 16
_COUNT_COLUMN_WIDTH: int = 5

_SEVERITY_BAR_COLORS: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "green",
    SeverityLevel.INFO: "dim",
}

_SEVERITY_PILL_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "reverse red",
    SeverityLevel.MEDIUM: "reverse yellow",
    SeverityLevel.LOW: "reverse green",
    SeverityLevel.INFO: "reverse dim",
}

_SECTION_HEADER_STYLE: str = "bold green"
_SECTION_BAR_STYLE: str = "green"


def render_title_strip(console: Console, scan_target: str) -> None:
    """Print the compact one-line title strip with version and timestamp."""
    timestamp = datetime.now(tz=UTC).strftime(_TIMESTAMP_FORMAT)
    title = _TITLE_TEMPLATE.format(version=__version__)
    console.print(f"{title}   [dim]{timestamp}[/dim]")
    console.print()


def render_status_banner(
    console: Console,
    scan_result: ScanResult,
    scan_target: str,
) -> None:
    """Print the full-width status banner (violation or clean)."""
    if scan_result.is_clean:
        right_meta = (
            f"Target: [bold]{escape_markup(scan_target)}[/bold]\n"
            f"Elapsed: [bold]{scan_result.scan_duration:.2f} s[/bold]"
            f"  {SEPARATOR}  {scan_result.files_scanned} file(s)"
        )
        clean_body = (
            f"  [bold green]{CLEAN_MARKER} {_STATUS_CLEAN}[/bold green]\n"
            f"  [green]{_CLEAN_SUBTITLE}[/green]\n\n  {right_meta}"
        )
        console.print(
            Panel(
                clean_body,
                box=rich_box.ROUNDED,
                border_style="bold green",
                expand=True,
            )
        )
        return

    risk_label = scan_result.risk_level.value
    subtitle = _VIOLATION_SUBTITLE_TEMPLATE.format(risk=risk_label)
    right_meta = (
        f"Target: [bold]{escape_markup(scan_target)}[/bold]\n"
        f"Elapsed: [bold]{scan_result.scan_duration:.2f} s[/bold]  {SEPARATOR}  "
        f"{scan_result.files_scanned} file(s)"
    )

    left_text = (
        f"  [bold red]{VIOLATION_MARKER} {_STATUS_VIOLATION}[/bold red]\n  [dim]{subtitle}[/dim]"
    )
    content = f"{left_text}\n\n  {right_meta}"

    console.print(
        Panel(
            content,
            box=rich_box.ROUNDED,
            border_style="bold red",
            expand=True,
        )
    )


def _render_stat_tile(label: str, value: int, color: str, subtitle: str = "") -> Panel:
    """Build a single stat tile panel."""
    value_text = f"[{color}]{value}[/{color}]"
    body = f"[dim]{label}[/dim]\n[bold]{value_text}[/bold]"
    if subtitle:
        body += f"\n[dim]{subtitle}[/dim]"
    return Panel(body, box=rich_box.ROUNDED, expand=True, padding=(0, 1))


def render_stat_tiles(
    console: Console,
    scan_result: ScanResult,
    line_aggregates: list[LineAggregate],
) -> None:
    """Print the five stat tiles (findings, high, medium, low, hotspots)."""
    total = len(scan_result.findings)
    high = scan_result.severity_counts.get(SeverityLevel.HIGH, 0)
    medium = scan_result.severity_counts.get(SeverityLevel.MEDIUM, 0)
    low = scan_result.severity_counts.get(SeverityLevel.LOW, 0)
    hotspots = compute_hotspot_count(line_aggregates)

    file_count = scan_result.files_with_findings
    file_label = "file" if file_count == 1 else "files"

    tiles = [
        _render_stat_tile(_STAT_FINDINGS, total, "white", f"across {file_count} {file_label}"),
        _render_stat_tile(_STAT_HIGH, high, "red"),
        _render_stat_tile(_STAT_MEDIUM, medium, "yellow"),
        _render_stat_tile(_STAT_LOW, low, "green"),
        _render_stat_tile(
            _STAT_HOTSPOTS, hotspots, "magenta", f"{EM_DASH} unique PHI hotspot lines {EM_DASH}"
        ),
    ]
    console.print(Columns(tiles, equal=True, expand=True))


def render_top_actions(
    console: Console,
    top_actions: list[RemediationAction],
) -> None:
    """Print the TOP ACTIONS section — numbered remediation priorities."""
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]{SECTION_BAR}[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]TOP ACTIONS[/{_SECTION_HEADER_STYLE}]"
        "    [dim]ranked by residual risk if ignored[/dim]"
    )
    console.print()

    for index, action in enumerate(top_actions, start=1):
        pill_style = _SEVERITY_PILL_STYLE[action.highest_severity]
        pill = f"[{pill_style}] {action.highest_severity.value.upper()} [/{pill_style}]"

        lines_str = _format_affected_lines_compact(action.affected_lines)
        title_with_count = action.title
        if action.finding_count > 1:
            title_with_count = f"{action.title}"

        body = (
            f" [{index}]  [bold]{escape_markup(title_with_count)}[/bold]"
            f"     {pill}\n      [dim]{lines_str}[/dim]"
        )
        console.print(Panel(body, box=rich_box.ROUNDED, padding=(0, 1)))


def _format_affected_lines_compact(
    affected_lines: tuple[tuple[Path, int], ...],
) -> str:
    """Format affected lines as a compact string like 'lines 7, 24, 40, 54'."""
    line_numbers = [pair[1] for pair in affected_lines]
    if len(line_numbers) <= _MAX_DISPLAYED_AFFECTED_LINES:
        return "lines " + ", ".join(str(ln) for ln in line_numbers)
    shown = ", ".join(str(ln) for ln in line_numbers[:_MAX_DISPLAYED_AFFECTED_LINES])
    remaining = len(line_numbers) - _MAX_DISPLAYED_AFFECTED_LINES
    return f"lines {shown} (+{remaining} more)"


def render_category_breakdown(
    console: Console,
    scan_result: ScanResult,
) -> None:
    """Print the CATEGORY BREAKDOWN section with severity-segmented bars."""
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]{SECTION_BAR}[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]CATEGORY BREAKDOWN[/{_SECTION_HEADER_STYLE}]"
    )
    console.print()

    distribution = compute_category_severity_distribution(scan_result.findings)
    category_totals: list[tuple[str, int, dict[SeverityLevel, int]]] = []
    for category_name, sev_dist in distribution.items():
        total = sum(sev_dist.values())
        category_totals.append((category_name, total, sev_dist))

    category_totals.sort(key=lambda ct: -ct[1])

    max_count = max((ct[1] for ct in category_totals), default=_BAR_DENOMINATOR_FLOOR)
    max_count = max(max_count, _BAR_DENOMINATOR_FLOOR)

    for category_name, total, sev_dist in category_totals:
        bar_width = round(total / max_count * _BAR_MAX_WIDTH)
        bar_width = max(bar_width, 1)

        bar_parts: list[str] = []
        severity_order = (
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        )
        for severity in severity_order:
            sev_count = sev_dist.get(severity, 0)
            if sev_count > 0:
                segment_width = max(round(sev_count / total * bar_width), 1)
                color = _SEVERITY_BAR_COLORS[severity]
                bar_parts.append(f"[{color}]{BAR_FILLED * segment_width}[/{color}]")

        bar_str = "".join(bar_parts)
        name_padded = category_name.ljust(_NAME_COLUMN_WIDTH)
        count_padded = str(total).rjust(_COUNT_COLUMN_WIDTH)

        console.print(f"  {name_padded}{count_padded}  {bar_str}")


def render_overview(
    console: Console,
    scan_result: ScanResult,
    scan_target: str,
    all_actions: list[RemediationAction],
) -> None:
    """Compose and render the full overview section."""
    line_aggregates = group_by_line(scan_result.findings)

    render_title_strip(console, scan_target)
    render_status_banner(console, scan_result, scan_target)
    console.print()

    if not scan_result.is_clean:
        render_stat_tiles(console, scan_result, line_aggregates)
        top_actions = rank_top_actions(all_actions)
        if top_actions:
            render_top_actions(console, top_actions)
        render_category_breakdown(console, scan_result)
