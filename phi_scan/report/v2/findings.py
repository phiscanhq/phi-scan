"""V2 renderer: findings-by-line section with line cards grouped by file."""

from __future__ import annotations

from rich import box as rich_box
from rich.console import Console
from rich.markup import escape as escape_markup
from rich.panel import Panel

from phi_scan.constants import SEVERITY_RANK, SeverityLevel
from phi_scan.report.v2.aggregation import build_line_title
from phi_scan.report.v2.glyphs import MULTIPLIER, PREVIEW_MARKER, SECTION_BAR, SEPARATOR
from phi_scan.report.v2.models import FileAggregate, LineAggregate

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

_LINE_BADGE_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: "bold red",
    SeverityLevel.MEDIUM: "bold yellow",
    SeverityLevel.LOW: "bold green",
    SeverityLevel.INFO: "dim",
}

_TYPE_CHIP_STYLE: str = "cyan"
_EXPAND_CUTOFF_DEFAULT: SeverityLevel = SeverityLevel.MEDIUM
_MAX_FIX_DISPLAY_LENGTH: int = 120


def _should_expand_line(
    line_aggregate: LineAggregate,
    expand_cutoff: SeverityLevel,
    is_verbose: bool,
) -> bool:
    """Determine if a line card should be expanded or collapsed."""
    if is_verbose:
        return True
    return SEVERITY_RANK[line_aggregate.highest_severity] >= SEVERITY_RANK[expand_cutoff]


def _build_type_chips(category_counts: dict[str, int]) -> str:
    """Build type chips like 'SSN · AGE_OVER_THRESHOLD ×2 · ZIP_CODE'."""
    chips: list[str] = []
    for entity_type, count in sorted(category_counts.items()):
        if count > 1:
            chip = f"[{_TYPE_CHIP_STYLE}]{entity_type} {MULTIPLIER}{count}[/{_TYPE_CHIP_STYLE}]"
            chips.append(chip)
        else:
            chips.append(f"[{_TYPE_CHIP_STYLE}]{entity_type}[/{_TYPE_CHIP_STYLE}]")
    return f"  {SEPARATOR}  ".join(chips)


def _render_line_card(console: Console, line_aggregate: LineAggregate) -> None:
    """Render a single line card panel."""
    severity = line_aggregate.highest_severity
    badge_style = _LINE_BADGE_STYLE[severity]
    border_style = _SEVERITY_BORDER_STYLE[severity]
    pill_style = _SEVERITY_PILL_STYLE[severity]

    title = build_line_title(line_aggregate)
    finding_word = "finding" if line_aggregate.finding_count == 1 else "findings"
    pill = f"[{pill_style}] {severity.value.upper()} [/{pill_style}]"
    header = (
        f"[{badge_style}] line {line_aggregate.line_number} [/{badge_style}]  "
        f"[bold]{escape_markup(title)}[/bold]"
        f"     [dim]{line_aggregate.finding_count} {finding_word}[/dim]  {pill}"
    )

    preview = f"  {PREVIEW_MARKER}  {escape_markup(line_aggregate.display_context)}"
    type_chips = f"  types: {_build_type_chips(line_aggregate.category_counts)}"

    fix_text = line_aggregate.combined_fix
    if len(fix_text) > _MAX_FIX_DISPLAY_LENGTH:
        fix_text = fix_text[:_MAX_FIX_DISPLAY_LENGTH] + "..."
    fix_line = f"  fix:   {escape_markup(fix_text)}"

    body = f"{header}\n\n{preview}\n{type_chips}\n{fix_line}"

    console.print(Panel(body, box=rich_box.ROUNDED, border_style=border_style, padding=(0, 1)))


def render_findings_by_line(
    console: Console,
    file_aggregates: list[FileAggregate],
    total_finding_count: int,
    total_line_count: int,
    severity_threshold: SeverityLevel,
    is_verbose: bool,
) -> None:
    """Render the FINDINGS BY LINE section with file grouping."""
    console.print()
    console.print()
    console.print(
        f"[{_SECTION_BAR_STYLE}]{SECTION_BAR}[/{_SECTION_BAR_STYLE}] "
        f"[{_SECTION_HEADER_STYLE}]FINDINGS BY LINE[/{_SECTION_HEADER_STYLE}]"
    )
    console.print(
        f"[dim]{total_finding_count} findings collapsed into {total_line_count} unique lines[/dim]"
    )
    console.print()

    collapsed_line_count = 0
    collapsed_finding_count = 0
    expanded_any = False

    for file_agg in file_aggregates:
        has_expanded_lines = False
        for line_agg in file_agg.line_aggregates:
            if _should_expand_line(line_agg, severity_threshold, is_verbose):
                has_expanded_lines = True
                break

        if has_expanded_lines:
            console.print(
                f"[bold]{escape_markup(str(file_agg.file_path))}[/bold]  "
                f"[dim]({file_agg.total_finding_count} findings)[/dim]"
            )
            console.print()

        for line_agg in file_agg.line_aggregates:
            if _should_expand_line(line_agg, severity_threshold, is_verbose):
                _render_line_card(console, line_agg)
                expanded_any = True
            else:
                collapsed_line_count += 1
                collapsed_finding_count += line_agg.finding_count

    if collapsed_line_count > 0 and not is_verbose:
        console.print()
        console.print(
            Panel(
                f"[bold]+ {collapsed_line_count} more lines[/bold]  {SEPARATOR}  "
                f"[dim]{collapsed_finding_count} low-severity findings collapsed.[/dim]\n"
                "[dim]Re-run with [bold]--verbose[/bold] or "
                "[bold]--severity-threshold low[/bold] to expand them.[/dim]",
                box=rich_box.ROUNDED,
                border_style="dim",
                padding=(0, 1),
            )
        )

    if not expanded_any and collapsed_line_count == 0:
        console.print("[dim]No findings to display.[/dim]")
