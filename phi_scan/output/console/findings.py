"""Findings display: findings table, file tree, code context, and category breakdown."""

from __future__ import annotations

from pathlib import Path

from rich.markup import escape as escape_markup
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from phi_scan.constants import PhiCategory
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output.console import (
    _CATEGORY_BAR_DENOMINATOR_FLOOR,
    _CATEGORY_BAR_EMPTY_CHAR,
    _CATEGORY_BAR_FILLED_CHAR,
    _CATEGORY_BAR_MAX_WIDTH,
    _CATEGORY_TABLE_TITLE,
    _CODE_CONTEXT_ARROW,
    _CODE_CONTEXT_PANEL_FORMAT,
    _CODE_CONTEXT_REMEDIATION_PREFIX,
    _COL_CATEGORY,
    _COL_CATEGORY_NAME,
    _COL_CONFIDENCE,
    _COL_COUNT,
    _COL_DISTRIBUTION,
    _COL_ENTITY_TYPE,
    _COL_FILE,
    _COL_LINE,
    _COL_SEVERITY,
    _CONFIDENCE_DOT_COUNT,
    _CONFIDENCE_DOT_EMPTY,
    _CONFIDENCE_DOT_FILLED,
    _EM_DASH_SEPARATOR,
    _FILE_TREE_TITLE,
    _FINDING_WORD,
    _FINDING_WORD_PLURAL,
    _FINDINGS_TABLE_TITLE,
    _ICON_FOLDER,
    _JUSTIFY_RIGHT,
    _LINE_LABEL,
    _MIN_VALID_MAX_COUNT,
    _PANEL_LABEL_STYLE,
    _SEVERITY_DESCENDING_ORDER,
    _SEVERITY_ICON,
    _SEVERITY_STYLE,
    _SINGULAR_COUNT,
    _ZERO_FINDINGS,
    _ZERO_MAX_COUNT_ERROR,
)
from phi_scan.output.console.core import get_console


def _build_confidence_dots(confidence: float) -> str:
    """Render a confidence score as a row of filled and empty dot characters.

    Maps 0.0–1.0 to a sequence of _CONFIDENCE_DOT_COUNT symbols, e.g. "●●●○○"
    for 0.6 with a count of 5. Filled/empty glyphs are resolved via _resolve_symbol
    so ASCII terminals receive "#" and "." instead of Unicode dots.

    Args:
        confidence: A float in [0.0, 1.0].

    Returns:
        A string of dot characters representing the confidence level.
    """
    filled_count = round(confidence * _CONFIDENCE_DOT_COUNT)
    empty_count = _CONFIDENCE_DOT_COUNT - filled_count
    return _CONFIDENCE_DOT_FILLED * filled_count + _CONFIDENCE_DOT_EMPTY * empty_count


def _build_count_bar(count: int, max_count: int) -> str:
    """Build a fixed-width block bar for a category count.

    Precondition: max_count must be > 0. Callers are responsible for ensuring
    this via max(..., default=_CATEGORY_BAR_DENOMINATOR_FLOOR).

    Args:
        count: The category's finding count.
        max_count: The highest count across all categories (sets bar scale).

    Returns:
        A string of filled and empty block characters totalling
        _CATEGORY_BAR_MAX_WIDTH characters.

    Raises:
        ValueError: If max_count is zero or less.
    """
    if max_count < _MIN_VALID_MAX_COUNT:
        raise ValueError(_ZERO_MAX_COUNT_ERROR)
    filled_block_count = round(count / max_count * _CATEGORY_BAR_MAX_WIDTH)
    empty_block_count = _CATEGORY_BAR_MAX_WIDTH - filled_block_count
    return (
        _CATEGORY_BAR_FILLED_CHAR * filled_block_count
        + _CATEGORY_BAR_EMPTY_CHAR * empty_block_count
    )


def _group_findings_by_file(
    findings: tuple[ScanFinding, ...],
) -> dict[Path, list[ScanFinding]]:
    """Group findings by file path, preserving the order findings were seen.

    Args:
        findings: All findings from a scan result.

    Returns:
        Dict mapping each affected file path to its list of findings.
    """
    findings_by_file: dict[Path, list[ScanFinding]] = {}
    for finding in findings:
        if finding.file_path not in findings_by_file:
            findings_by_file[finding.file_path] = []
        findings_by_file[finding.file_path].append(finding)
    return findings_by_file


def _highest_severity_icon(file_findings: list[ScanFinding]) -> str:
    """Return the emoji icon for the highest severity level in a set of findings.

    Args:
        file_findings: All findings for a single file.

    Returns:
        Emoji string corresponding to the highest severity level found.
    """
    file_severities = {f.severity for f in file_findings}
    for level in _SEVERITY_DESCENDING_ORDER:
        if level in file_severities:
            return _SEVERITY_ICON.get(level, "")
    return ""


def _build_findings_table(findings: tuple[ScanFinding, ...], title: str) -> Table:
    """Build a color-coded Rich Table from a sequence of findings.

    Args:
        findings: Findings to render, ordered by file path then line number.
        title: Title shown above the table.

    Returns:
        A configured Rich Table ready to print.
    """
    # code_context is omitted from table columns: terminal output is captured
    # by CI log systems, and rendering the raw source line would expose PHI in
    # those logs. File path and line number are sufficient for the developer to
    # locate and fix the finding.
    table = Table(title=title, show_header=True, header_style=_PANEL_LABEL_STYLE)
    table.add_column(_COL_FILE, no_wrap=True)
    table.add_column(_COL_LINE, justify=_JUSTIFY_RIGHT)
    table.add_column(_COL_ENTITY_TYPE)
    table.add_column(_COL_CATEGORY)
    table.add_column(_COL_SEVERITY)
    table.add_column(_COL_CONFIDENCE, justify=_JUSTIFY_RIGHT)
    for finding in findings:
        style = _SEVERITY_STYLE[finding.severity]
        confidence_str = _build_confidence_dots(finding.confidence)
        table.add_row(
            escape_markup(str(finding.file_path)),
            str(finding.line_number),
            finding.entity_type,
            finding.hipaa_category.value,
            f"[{style}]{finding.severity.value}[/{style}]",
            confidence_str,
        )
    return table


def format_table(scan_result: ScanResult) -> Table:
    """Build a Rich Table from a ScanResult for --output table mode.

    Args:
        scan_result: The completed scan result.

    Returns:
        A Rich Table with one row per finding, color-coded by severity.
    """
    return _build_findings_table(scan_result.findings, _FINDINGS_TABLE_TITLE)


def display_findings_table(findings: tuple[ScanFinding, ...]) -> None:
    """Render findings as a color-coded Rich table to the console.

    Args:
        findings: Findings to display, ordered by file path then line number.
    """
    get_console().print(_build_findings_table(findings, _FINDINGS_TABLE_TITLE))


def display_file_tree(findings: tuple[ScanFinding, ...]) -> None:
    """Render a Rich Tree of affected files with severity icons and per-file finding counts.

    Args:
        findings: All findings from a scan result.
    """
    tree = Tree(f"{_ICON_FOLDER} {_FILE_TREE_TITLE}", style=_PANEL_LABEL_STYLE)
    findings_by_file = _group_findings_by_file(findings)
    # Path objects sort lexicographically — produces alphabetical file order intentionally.
    for file_path, file_findings in sorted(findings_by_file.items()):
        count = len(file_findings)
        finding_word = _FINDING_WORD if count == _SINGULAR_COUNT else _FINDING_WORD_PLURAL
        icon = _highest_severity_icon(file_findings)
        branch = tree.add(f"{icon} {escape_markup(str(file_path))} ({count} {finding_word})")
        for finding in file_findings:
            style = _SEVERITY_STYLE[finding.severity]
            # line_number is an int; entity_type is a hardcoded pattern constant
            # (e.g. "SSN", "EMAIL") — neither comes from scanned file content,
            # so escape_markup is not required here.
            branch.add(
                f"[{style}]{_LINE_LABEL} {finding.line_number}[/{style}]"
                f"{_EM_DASH_SEPARATOR}{finding.entity_type}"
            )
    get_console().print(tree)


def display_code_context_panel(finding: ScanFinding) -> None:
    """Render a bordered panel showing the code context and remediation hint for a finding.

    finding.code_context has the matched PHI value already replaced by [REDACTED]
    by the detection layer. escape_markup is still applied because the surrounding
    source code may contain bracket sequences that Rich would misinterpret as tags.

    Args:
        finding: A single scan finding with code_context and remediation_hint populated.
    """
    severity_style = _SEVERITY_STYLE[finding.severity]
    title = _CODE_CONTEXT_PANEL_FORMAT.format(
        file=escape_markup(str(finding.file_path)),
        line=finding.line_number,
        entity=finding.entity_type,
        severity=finding.severity.value,
    )
    content = "\n".join(
        [
            f"{_CODE_CONTEXT_ARROW} {escape_markup(finding.code_context)}",
            "",
            f"[{severity_style}]{_CODE_CONTEXT_REMEDIATION_PREFIX}"
            f"{finding.remediation_hint}[/{severity_style}]",
        ]
    )
    get_console().print(Panel(content, title=title, border_style=severity_style))


def display_category_breakdown(scan_result: ScanResult) -> None:
    """Render a table of PHI category counts with a bar-chart distribution column.

    Only categories with at least one finding are shown. Categories with zero
    findings are omitted to keep the output concise.

    Args:
        scan_result: The completed scan result.
    """
    table = Table(title=_CATEGORY_TABLE_TITLE, show_header=True, header_style=_PANEL_LABEL_STYLE)
    table.add_column(_COL_CATEGORY_NAME, style=_PANEL_LABEL_STYLE)
    table.add_column(_COL_COUNT, justify=_JUSTIFY_RIGHT)
    table.add_column(_COL_DISTRIBUTION)
    max_count = max(scan_result.category_counts.values(), default=_CATEGORY_BAR_DENOMINATOR_FLOOR)
    for category in PhiCategory:
        count = scan_result.category_counts.get(category, _ZERO_FINDINGS)
        if count > _ZERO_FINDINGS:
            table.add_row(category.value, str(count), _build_count_bar(count, max_count))
    get_console().print(table)
