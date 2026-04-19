"""V2 renderer: executive summary section (title strip, status banner, stats, top actions, bars)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from rich import box as rich_box
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel
from rich.table import Table

from phi_scan import __version__
from phi_scan.constants import PhiCategory, SeverityLevel
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
_BAR_MIN_FILLED: int = 0
_MAX_DISPLAYED_AFFECTED_LINES: int = 8
_NAME_COLUMN_WIDTH: int = 16
_COUNT_COLUMN_WIDTH: int = 5
_STAT_TILE_COUNT: int = 5
_STAT_TILE_BAR_WIDTH: int = 12

_KNOWN_PHI_CATEGORY_VALUES: frozenset[str] = frozenset(member.value for member in PhiCategory)

_SEVERITY_BAR_COLORS: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "green",
    SeverityLevel.INFO: "dim",
}

_CATEGORY_BAR_COLORS: dict[PhiCategory, str] = {
    PhiCategory.UNIQUE_ID: "magenta",
    PhiCategory.HEALTH_PLAN: "bright_blue",
    PhiCategory.DATE: "yellow",
    PhiCategory.ACCOUNT: "yellow",
    PhiCategory.MRN: "yellow",
    PhiCategory.GEOGRAPHIC: "green",
    PhiCategory.SSN: "red",
    PhiCategory.PHONE: "red",
    PhiCategory.EMAIL: "red",
    PhiCategory.FAX: "red",
    PhiCategory.IP: "red",
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: "red",
    PhiCategory.NAME: "red",
    PhiCategory.CERTIFICATE: "yellow",
    PhiCategory.URL: "cyan",
    PhiCategory.VEHICLE: "cyan",
    PhiCategory.DEVICE: "cyan",
    PhiCategory.BIOMETRIC: "red",
    PhiCategory.PHOTO: "red",
    PhiCategory.SUBSTANCE_USE_DISORDER: "red",
}
_CATEGORY_BAR_DEFAULT: str = "cyan"

_CATEGORY_DISPLAY_NAMES: dict[PhiCategory, str] = {
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: "quasi_combo",
    PhiCategory.SUBSTANCE_USE_DISORDER: "sud",
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


def _render_proportional_bar(value: int, max_value: int, color: str) -> str:
    """Render a proportional single-line bar shown under severity tile counts."""
    denominator = max(max_value, _BAR_DENOMINATOR_FLOOR)
    ratio = value / denominator
    filled = round(ratio * _STAT_TILE_BAR_WIDTH)
    filled = max(_BAR_MIN_FILLED, min(_STAT_TILE_BAR_WIDTH, filled))
    empty = _STAT_TILE_BAR_WIDTH - filled
    filled_segment = f"[{color}]{BAR_FILLED * filled}[/{color}]"
    empty_segment = f"[dim]{BAR_FILLED * empty}[/dim]"
    return filled_segment + empty_segment


def _render_stat_tile(
    label: str,
    value: int,
    color: str,
    subtitle: str = "",
    bar_markup: str = "",
) -> Panel:
    """Build a single stat tile panel."""
    value_text = f"[{color}]{value}[/{color}]"
    body = f"[dim]{label}[/dim]\n[bold]{value_text}[/bold]"
    if bar_markup:
        body += f"\n{bar_markup}"
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

    severity_max = max(high, medium, low, _BAR_DENOMINATOR_FLOOR)
    high_bar = _render_proportional_bar(high, severity_max, "red")
    medium_bar = _render_proportional_bar(medium, severity_max, "yellow")
    low_bar = _render_proportional_bar(low, severity_max, "green")

    findings_subtitle = f"across {file_count} {file_label}"
    tiles = [
        _render_stat_tile(_STAT_FINDINGS, total, "white", subtitle=findings_subtitle),
        _render_stat_tile(_STAT_HIGH, high, "red", bar_markup=high_bar),
        _render_stat_tile(_STAT_MEDIUM, medium, "yellow", bar_markup=medium_bar),
        _render_stat_tile(_STAT_LOW, low, "green", bar_markup=low_bar),
        _render_stat_tile(
            _STAT_HOTSPOTS,
            hotspots,
            "magenta",
            subtitle="unique PHI hotspot lines",
        ),
    ]

    grid = Table.grid(expand=True, padding=(0, 1))
    for _ in range(_STAT_TILE_COUNT):
        grid.add_column(ratio=1)
    grid.add_row(*tiles)
    console.print(grid)


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
    line_numbers = [path_line_pair[1] for path_line_pair in affected_lines]
    if len(line_numbers) <= _MAX_DISPLAYED_AFFECTED_LINES:
        return "lines " + ", ".join(str(ln) for ln in line_numbers)
    shown = ", ".join(str(ln) for ln in line_numbers[:_MAX_DISPLAYED_AFFECTED_LINES])
    remaining = len(line_numbers) - _MAX_DISPLAYED_AFFECTED_LINES
    return f"lines {shown} (+{remaining} more)"


def _resolve_category_color(category_name: str) -> str:
    """Map a category name (enum value) to its display color."""
    if category_name not in _KNOWN_PHI_CATEGORY_VALUES:
        return _CATEGORY_BAR_DEFAULT
    return _CATEGORY_BAR_COLORS[PhiCategory(category_name)]


def _resolve_category_display(category_name: str) -> str:
    """Abbreviate long category names for the breakdown label column."""
    if category_name not in _KNOWN_PHI_CATEGORY_VALUES:
        return category_name
    return _CATEGORY_DISPLAY_NAMES.get(PhiCategory(category_name), category_name)


def render_category_breakdown(
    console: Console,
    scan_result: ScanResult,
) -> None:
    """Print the CATEGORY BREAKDOWN section with per-category colored bars."""
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]{SECTION_BAR}[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]CATEGORY BREAKDOWN[/{_SECTION_HEADER_STYLE}]"
    )
    console.print()

    distribution = compute_category_severity_distribution(scan_result.findings)
    category_totals: list[tuple[str, int]] = [
        (category_name, sum(sev_dist.values())) for category_name, sev_dist in distribution.items()
    ]
    category_totals.sort(key=lambda ct: -ct[1])

    max_count = max((ct[1] for ct in category_totals), default=_BAR_DENOMINATOR_FLOOR)
    max_count = max(max_count, _BAR_DENOMINATOR_FLOOR)

    for category_name, total in category_totals:
        filled_width = round(total / max_count * _BAR_MAX_WIDTH)
        filled_width = max(1, min(_BAR_MAX_WIDTH, filled_width))
        empty_width = _BAR_MAX_WIDTH - filled_width

        color = _resolve_category_color(category_name)
        bar_str = (
            f"[{color}]{BAR_FILLED * filled_width}[/{color}][dim]{BAR_FILLED * empty_width}[/dim]"
        )

        display_name = _resolve_category_display(category_name)
        name_markup = f"[dim]{display_name.ljust(_NAME_COLUMN_WIDTH)}[/dim]"
        count_markup = f"[bold {color}]{str(total).rjust(_COUNT_COLUMN_WIDTH)}[/bold {color}]"

        console.print(f"  {name_markup}{count_markup}  {bar_str}")


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
