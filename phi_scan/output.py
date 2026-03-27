"""Output formatters (table, json, csv, sarif) and Rich UI components."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.tree import Tree

from phi_scan import __version__
from phi_scan.constants import PhiCategory, RiskLevel, SeverityLevel
from phi_scan.models import ScanConfig, ScanFinding, ScanResult

__all__ = [
    "display_banner",
    "display_category_breakdown",
    "display_clean_result",
    "display_file_tree",
    "display_findings_table",
    "display_scan_header",
    "create_scan_progress",
    "display_summary_panel",
    "display_violation_alert",
    "format_csv",
    "format_json",
    "format_sarif",
    "format_table",
]

# ---------------------------------------------------------------------------
# Module-level Rich console — all display functions write to this instance.
# Rich automatically respects the NO_COLOR environment variable (no-color.org).
# ---------------------------------------------------------------------------

_console: Console = Console()

# ---------------------------------------------------------------------------
# Rich style strings
# ---------------------------------------------------------------------------

_STYLE_BOLD_RED: str = "bold red"
_STYLE_RED: str = "red"
_STYLE_YELLOW: str = "yellow"
_STYLE_GREEN: str = "green"
_STYLE_BOLD_GREEN: str = "bold green"
_STYLE_DIM: str = "dim"
_STYLE_BOLD: str = "bold"
_STYLE_BOLD_CYAN: str = "bold cyan"

# ---------------------------------------------------------------------------
# Severity and risk level → Rich style mappings
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _STYLE_BOLD_RED,
    SeverityLevel.MEDIUM: _STYLE_YELLOW,
    SeverityLevel.LOW: _STYLE_GREEN,
    SeverityLevel.INFO: _STYLE_DIM,
}

_RISK_LEVEL_STYLE: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: _STYLE_BOLD_RED,
    RiskLevel.HIGH: _STYLE_RED,
    RiskLevel.MODERATE: _STYLE_YELLOW,
    RiskLevel.LOW: _STYLE_GREEN,
    RiskLevel.CLEAN: _STYLE_BOLD_GREEN,
}

# ---------------------------------------------------------------------------
# SARIF 2.1.0 protocol constants
# ---------------------------------------------------------------------------

_SARIF_VERSION: str = "2.1.0"
_SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_SCHEMA_KEY: str = "$schema"
_SARIF_URI_BASE_ID: str = "%SRCROOT%"
_SARIF_TOOL_NAME: str = "PhiScan"
_SARIF_LEVEL_ERROR: str = "error"
_SARIF_LEVEL_WARNING: str = "warning"
_SARIF_LEVEL_NOTE: str = "note"
_SARIF_LEVEL_NONE: str = "none"

_SEVERITY_TO_SARIF_LEVEL: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _SARIF_LEVEL_ERROR,
    SeverityLevel.MEDIUM: _SARIF_LEVEL_WARNING,
    SeverityLevel.LOW: _SARIF_LEVEL_NOTE,
    SeverityLevel.INFO: _SARIF_LEVEL_NONE,
}

# ---------------------------------------------------------------------------
# Panel and rule styles
# ---------------------------------------------------------------------------

_PANEL_LABEL_STYLE: str = _STYLE_BOLD_CYAN
_PANEL_BORDER_STYLE: str = "cyan"
_RULE_STYLE: str = _STYLE_DIM
_VIOLATION_BORDER_STYLE: str = _STYLE_BOLD_RED

# ---------------------------------------------------------------------------
# Banner constants
# ---------------------------------------------------------------------------

_BANNER_FONT: str = "slant"
_BANNER_TEXT: str = "PhiScan"
_BANNER_TAGLINE_TEMPLATE: str = "v{version}  —  HIPAA-Compliant PHI/PII Scanner"
_BANNER_STYLE: str = _STYLE_BOLD_CYAN
_BANNER_TAGLINE_STYLE: str = _STYLE_DIM

# ---------------------------------------------------------------------------
# Panel and table titles
# ---------------------------------------------------------------------------

_SCAN_HEADER_TITLE: str = "Scan Target"
_SUMMARY_PANEL_TITLE: str = "Scan Summary"
_CATEGORY_TABLE_TITLE: str = "PHI Category Breakdown"
_FINDINGS_TABLE_TITLE: str = "Findings"
_FILE_TREE_TITLE: str = "Affected Files"
_VIOLATION_ALERT_TITLE: str = "PHI/PII Violation Detected"
_VIOLATION_RISK_LEVEL_LABEL: str = "Risk Level: "

# ---------------------------------------------------------------------------
# Findings table column headers
# ---------------------------------------------------------------------------

_COL_FILE: str = "File"
_COL_LINE: str = "Line"
_COL_ENTITY_TYPE: str = "Entity Type"
_COL_CATEGORY: str = "Category"
_COL_SEVERITY: str = "Severity"
_COL_CONFIDENCE: str = "Confidence"

# ---------------------------------------------------------------------------
# Category breakdown table column headers and bar chart constants
# ---------------------------------------------------------------------------

_COL_CATEGORY_NAME: str = "Category"
_COL_COUNT: str = "Count"
_COL_DISTRIBUTION: str = "Distribution"
_CATEGORY_BAR_MAX_WIDTH: int = 20
_CATEGORY_BAR_FILLED_CHAR: str = "█"
_CATEGORY_BAR_EMPTY_CHAR: str = "░"
# Prevents division by zero when all category counts are zero — a clean scan
# still calls display_category_breakdown with an all-zero MappingProxyType.
_CATEGORY_BAR_DENOMINATOR_FLOOR: int = 1

# ---------------------------------------------------------------------------
# Clean result display
# ---------------------------------------------------------------------------

_CLEAN_RESULT_TEXT: str = "✓  No PHI/PII detected"
_CLEAN_RESULT_STYLE: str = _STYLE_BOLD_GREEN
_JUSTIFY_CENTER: Literal["center"] = "center"
_JUSTIFY_RIGHT: Literal["right"] = "right"

# ---------------------------------------------------------------------------
# CSV field names (in output column order)
# ---------------------------------------------------------------------------

_CSV_FIELD_NAMES: list[str] = [
    "file_path",
    "line_number",
    "entity_type",
    "hipaa_category",
    "confidence",
    "severity",
    "detection_layer",
    "remediation_hint",
]

# ---------------------------------------------------------------------------
# Numeric and format constants
# ---------------------------------------------------------------------------

_JSON_INDENT: int = 2
_CONFIDENCE_FORMAT: str = "{:.2f}"
_DURATION_FORMAT: str = "{:.2f}s"
_TIMESTAMP_TIMESPEC: str = "seconds"
_PROGRESS_DESCRIPTION: str = "Scanning"

# ---------------------------------------------------------------------------
# Pluralization constants
# ---------------------------------------------------------------------------

_FINDING_WORD: str = "finding"
_FINDING_WORD_PLURAL: str = "findings"
_SINGULAR_COUNT: int = 1
_ZERO_FINDINGS: int = 0
_MIN_VALID_MAX_COUNT: int = 1
_LINE_LABEL: str = "line"
_MARKUP_BLANK_LINE: str = ""
_EM_DASH_SEPARATOR: str = " — "
# Error raised when _build_count_bar receives max_count=0 — callers must guard
# via max(..., default=_CATEGORY_BAR_DENOMINATOR_FLOOR) before calling.
_ZERO_MAX_COUNT_ERROR: str = (
    "max_count must be greater than zero — "
    "callers must pass default=_CATEGORY_BAR_DENOMINATOR_FLOOR to max()"
)
_VIOLATION_DETECTED_SUFFIX: str = "detected"

# ---------------------------------------------------------------------------
# Private helper functions
# ---------------------------------------------------------------------------


def _serialize_finding_to_dict(finding: ScanFinding) -> dict[str, object]:
    """Serialize a ScanFinding to a JSON-serializable dict.

    code_context is intentionally omitted: it contains the raw source line
    that triggered the finding, which may hold the PHI value itself. JSON
    output is consumed by CI systems and log aggregators where raw PHI must
    never appear. File path and line number are sufficient for remediation.
    The value_hash field is a SHA-256 digest — it never contains raw PHI.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict with string keys and JSON-serializable values.
    """
    return {
        "file_path": str(finding.file_path),
        "line_number": finding.line_number,
        "entity_type": finding.entity_type,
        "hipaa_category": finding.hipaa_category.value,
        "confidence": finding.confidence,
        "detection_layer": finding.detection_layer.value,
        "severity": finding.severity.value,
        "value_hash": finding.value_hash,
        # remediation_hint must never contain raw PHI — the ScanFinding contract
        # requires it to hold only generic guidance (e.g. "Replace SSN with
        # synthetic value"), never the matched value itself.
        "remediation_hint": finding.remediation_hint,
    }


def _serialize_finding_to_csv_row(finding: ScanFinding) -> dict[str, object]:
    """Build a CSV row dict from a ScanFinding.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict whose keys match _CSV_FIELD_NAMES.
    """
    return {
        "file_path": str(finding.file_path),
        "line_number": finding.line_number,
        "entity_type": finding.entity_type,
        "hipaa_category": finding.hipaa_category.value,
        "confidence": finding.confidence,
        "severity": finding.severity.value,
        "detection_layer": finding.detection_layer.value,
        # remediation_hint must never contain raw PHI — see _serialize_finding_to_dict.
        "remediation_hint": finding.remediation_hint,
    }


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
        confidence_str = _CONFIDENCE_FORMAT.format(finding.confidence)
        table.add_row(
            str(finding.file_path),
            str(finding.line_number),
            finding.entity_type,
            finding.hipaa_category.value,
            f"[{style}]{finding.severity.value}[/{style}]",
            confidence_str,
        )
    return table


def _build_sarif_rule(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF rule entry from the first finding for an entity type.

    Args:
        finding: A representative finding for the rule.

    Returns:
        A SARIF rule dict with id, name, shortDescription, and help.
    """
    return {
        "id": finding.entity_type,
        "name": finding.entity_type,
        "shortDescription": {"text": finding.hipaa_category.value},
        "help": {
            "text": finding.remediation_hint,
            "markdown": finding.remediation_hint,
        },
    }


def _build_sarif_rules(scan_result: ScanResult) -> list[dict[str, object]]:
    """Deduplicate findings into one SARIF rule per unique entity type.

    Args:
        scan_result: The completed scan result.

    Returns:
        List of SARIF rule dicts, one per distinct entity_type.
    """
    seen_entity_types: set[str] = set()
    rules: list[dict[str, object]] = []
    for finding in scan_result.findings:
        if finding.entity_type not in seen_entity_types:
            seen_entity_types.add(finding.entity_type)
            rules.append(_build_sarif_rule(finding))
    return rules


def _build_sarif_finding_message(finding: ScanFinding) -> str:
    """Build the human-readable SARIF result message for a finding.

    Args:
        finding: The finding to describe.

    Returns:
        A sentence describing the category, layer, confidence, and remediation.
    """
    confidence_str = _CONFIDENCE_FORMAT.format(finding.confidence)
    # remediation_hint must never contain raw PHI — see _serialize_finding_to_dict.
    # SARIF output is consumed by GitHub Advanced Security and other CI platforms.
    return (
        f"{finding.hipaa_category.value} identifier detected by the "
        f"{finding.detection_layer.value} layer "
        f"(confidence: {confidence_str}). {finding.remediation_hint}"
    )


def _build_sarif_location(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF physicalLocation entry for a finding.

    Args:
        finding: The finding whose file path and line number to encode.

    Returns:
        A SARIF location dict with artifactLocation and region.
    """
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": str(finding.file_path),
                "uriBaseId": _SARIF_URI_BASE_ID,
            },
            "region": {"startLine": finding.line_number},
        }
    }


def _build_sarif_result(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF result dict for a single finding.

    Args:
        finding: The finding to encode as a SARIF result.

    Returns:
        A SARIF result dict with ruleId, level, message, and locations.
    """
    return {
        "ruleId": finding.entity_type,
        "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
        "message": {"text": _build_sarif_finding_message(finding)},
        "locations": [_build_sarif_location(finding)],
    }


def _build_sarif_run(scan_result: ScanResult) -> dict[str, object]:
    """Build the single SARIF run object for a completed scan.

    Args:
        scan_result: The completed scan result.

    Returns:
        A SARIF run dict with tool driver and results array.
    """
    return {
        "tool": {
            "driver": {
                "name": _SARIF_TOOL_NAME,
                "version": __version__,
                "rules": _build_sarif_rules(scan_result),
            }
        },
        "results": [_build_sarif_result(finding) for finding in scan_result.findings],
    }


def _build_severity_breakdown(severity_counts: MappingProxyType[SeverityLevel, int]) -> str:
    """Build a Rich markup string listing count per severity level.

    Args:
        severity_counts: Mapping from severity level to finding count.

    Returns:
        Newline-separated Rich markup lines, one per severity level.
    """
    severity_markup_lines = []
    for level in SeverityLevel:
        count = severity_counts.get(level, _ZERO_FINDINGS)
        style = _SEVERITY_STYLE[level]
        severity_markup_lines.append(
            f"[{_PANEL_LABEL_STYLE}]{level.value.title()}:[/{_PANEL_LABEL_STYLE}]"
            f" [{style}]{count}[/{style}]"
        )
    return "\n".join(severity_markup_lines)


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
    filled = round(count / max_count * _CATEGORY_BAR_MAX_WIDTH)
    empty = _CATEGORY_BAR_MAX_WIDTH - filled
    return _CATEGORY_BAR_FILLED_CHAR * filled + _CATEGORY_BAR_EMPTY_CHAR * empty


def _format_risk_level_display(risk_level: RiskLevel) -> str:
    """Format a risk level as uppercase text for panel display.

    Centralised so the display format (uppercase) is defined once. Both
    display_summary_panel and display_violation_alert use this helper to
    avoid duplicating the .upper() transformation.

    Args:
        risk_level: The risk level to format.

    Returns:
        Uppercase string representation (e.g., "CRITICAL", "HIGH").
    """
    return risk_level.value.upper()


def _group_findings_by_file(
    findings: tuple[ScanFinding, ...],
) -> dict[Path, list[ScanFinding]]:
    """Group findings by file path, preserving the order findings were seen.

    Args:
        findings: All findings from a scan result.

    Returns:
        Dict mapping each affected file path to its list of findings.
    """
    groups: dict[Path, list[ScanFinding]] = {}
    for finding in findings:
        if finding.file_path not in groups:
            groups[finding.file_path] = []
        groups[finding.file_path].append(finding)
    return groups


# ---------------------------------------------------------------------------
# Format functions — return serialized output strings (or Rich Table)
# ---------------------------------------------------------------------------


def format_table(scan_result: ScanResult) -> Table:
    """Build a Rich Table from a ScanResult for --output table mode.

    Args:
        scan_result: The completed scan result.

    Returns:
        A Rich Table with one row per finding, color-coded by severity.
    """
    return _build_findings_table(scan_result.findings, _FINDINGS_TABLE_TITLE)


def format_json(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a JSON string.

    The value_hash field in each finding is a SHA-256 digest — this function
    never serializes raw PHI values.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented JSON string with findings array and summary metadata.
    """
    payload: dict[str, object] = {
        "files_scanned": scan_result.files_scanned,
        "files_with_findings": scan_result.files_with_findings,
        "scan_duration": scan_result.scan_duration,
        "is_clean": scan_result.is_clean,
        "risk_level": scan_result.risk_level.value,
        "severity_counts": {k.value: v for k, v in scan_result.severity_counts.items()},
        "category_counts": {k.value: v for k, v in scan_result.category_counts.items()},
        "findings": [_serialize_finding_to_dict(finding) for finding in scan_result.findings],
    }
    return json.dumps(payload, indent=_JSON_INDENT)


def format_csv(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a CSV string with headers.

    Args:
        scan_result: The completed scan result.

    Returns:
        CSV-formatted string with a header row and one data row per finding.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELD_NAMES)
    writer.writeheader()
    for finding in scan_result.findings:
        writer.writerow(_serialize_finding_to_csv_row(finding))
    return buffer.getvalue()


def format_sarif(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a SARIF 2.1.0 JSON string.

    SARIF (Static Analysis Results Interchange Format) is consumed by GitHub
    Advanced Security, Azure DevOps, and other CI/CD platforms for inline
    code annotations and security dashboards.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented SARIF 2.1.0 JSON string.
    """
    sarif_doc: dict[str, object] = {
        _SARIF_SCHEMA_KEY: _SARIF_SCHEMA_URL,
        "version": _SARIF_VERSION,
        "runs": [_build_sarif_run(scan_result)],
    }
    return json.dumps(sarif_doc, indent=_JSON_INDENT)


# ---------------------------------------------------------------------------
# Display functions — render Rich components to the console
# ---------------------------------------------------------------------------


_BANNER_PYFIGLET_MISSING_NOTE: str = (
    "note: install pyfiglet for ASCII art banner (pip install pyfiglet)"
)


def _build_ascii_banner_text() -> str:
    """Return the PhiScan ASCII art string, falling back to plain text.

    pyfiglet is an optional dependency. When absent, emits a dim console note
    so operators know the tool is in fallback mode, then returns plain text.

    Returns:
        ASCII art string from pyfiglet, or the plain _BANNER_TEXT fallback.
    """
    try:
        import pyfiglet  # noqa: PLC0415 — optional dependency, import deferred

        return str(pyfiglet.figlet_format(_BANNER_TEXT, font=_BANNER_FONT))
    except ImportError:
        _console.print(_BANNER_PYFIGLET_MISSING_NOTE, style=_STYLE_DIM)
        return _BANNER_TEXT


def display_banner() -> None:
    """Render the PhiScan ASCII art banner, tagline, and separator rule."""
    _console.print(_build_ascii_banner_text(), style=_BANNER_STYLE)
    _console.print(
        _BANNER_TAGLINE_TEMPLATE.format(version=__version__),
        style=_BANNER_TAGLINE_STYLE,
    )
    _console.rule(style=_RULE_STYLE)


def _build_scan_header_markup(path: Path, config: ScanConfig, timestamp: str) -> str:
    """Build the Rich markup string for the scan header panel.

    Pure function — timestamp is passed in so the caller (display_scan_header)
    owns the datetime.now() side effect and this builder remains testable.

    Args:
        path: The directory or file being scanned.
        config: Active scan configuration.
        timestamp: ISO-format timestamp string to display in the header.

    Returns:
        Newline-separated Rich markup string with target, thresholds, and timestamp.
    """
    label_style = _PANEL_LABEL_STYLE
    return "\n".join(
        [
            f"[{label_style}]Target:[/{label_style}] {path}",
            f"[{label_style}]Severity threshold:[/{label_style}] {config.severity_threshold.value}",
            f"[{label_style}]Confidence threshold:[/{label_style}]"
            f" {_CONFIDENCE_FORMAT.format(config.confidence_threshold)}",
            f"[{label_style}]Timestamp:[/{label_style}] {timestamp}",
        ]
    )


def display_scan_header(path: Path, config: ScanConfig) -> None:
    """Render a styled panel showing the scan target and active configuration.

    Args:
        path: The directory or file being scanned.
        config: Active scan configuration (severity threshold, confidence, etc.).
    """
    timestamp = datetime.now().isoformat(timespec=_TIMESTAMP_TIMESPEC)
    scan_header_markup = _build_scan_header_markup(path, config, timestamp)
    _console.print(
        Panel(scan_header_markup, title=_SCAN_HEADER_TITLE, border_style=_PANEL_BORDER_STYLE)
    )


@contextmanager
def create_scan_progress(total_files: int) -> Generator[tuple[Progress, TaskID], None, None]:
    """Yield a configured Rich Progress bar for file-by-file scan updates.

    Usage::

        with create_scan_progress(total) as (progress, task_id):
            for path in files:
                progress.update(task_id, advance=1, description=str(path))

    Args:
        total_files: Total number of files to be scanned (sets the bar maximum).

    Yields:
        A tuple of (Progress instance, TaskID) so callers can update per file.
    """
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console,
    ) as progress:
        task_id = progress.add_task(_PROGRESS_DESCRIPTION, total=total_files)
        yield progress, task_id


def display_findings_table(findings: tuple[ScanFinding, ...]) -> None:
    """Render findings as a color-coded Rich table to the console.

    Args:
        findings: Findings to display, ordered by file path then line number.
    """
    _console.print(_build_findings_table(findings, _FINDINGS_TABLE_TITLE))


def display_file_tree(findings: tuple[ScanFinding, ...]) -> None:
    """Render a Rich Tree of affected files with per-file finding counts.

    Args:
        findings: All findings from a scan result.
    """
    tree = Tree(_FILE_TREE_TITLE, style=_PANEL_LABEL_STYLE)
    findings_by_file = _group_findings_by_file(findings)
    # Path objects sort lexicographically — produces alphabetical file order intentionally.
    for file_path, file_findings in sorted(findings_by_file.items()):
        count = len(file_findings)
        word = _FINDING_WORD if count == _SINGULAR_COUNT else _FINDING_WORD_PLURAL
        branch = tree.add(f"{file_path} ({count} {word})")
        for finding in file_findings:
            style = _SEVERITY_STYLE[finding.severity]
            branch.add(
                f"[{style}]{_LINE_LABEL} {finding.line_number}[/{style}]"
                f"{_EM_DASH_SEPARATOR}{finding.entity_type}"
            )
    _console.print(tree)


def _build_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the scan summary panel.

    Args:
        scan_result: The completed scan result.

    Returns:
        Newline-separated Rich markup string with risk level, file stats, and severity.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    label_style = _PANEL_LABEL_STYLE
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    return "\n".join(
        [
            f"[{label_style}]Risk Level:[/{label_style}] [{risk_style}]"
            f"{_format_risk_level_display(scan_result.risk_level)}[/{risk_style}]",
            f"[{label_style}]Files Scanned:[/{label_style}] {scan_result.files_scanned}",
            f"[{label_style}]Files with Findings:[/{label_style}]"
            f" {scan_result.files_with_findings}",
            f"[{label_style}]Scan Duration:[/{label_style}] {duration_str}",
            _MARKUP_BLANK_LINE,
            _build_severity_breakdown(scan_result.severity_counts),
        ]
    )


def display_summary_panel(scan_result: ScanResult) -> None:
    """Render a bordered summary panel with risk level, file stats, and severity breakdown.

    Args:
        scan_result: The completed scan result to summarise.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    _console.print(
        Panel(
            _build_summary_panel_markup(scan_result),
            title=_SUMMARY_PANEL_TITLE,
            border_style=risk_style,
        )
    )


def display_clean_result() -> None:
    """Render a prominent green checkmark indicating no PHI/PII was detected."""
    _console.print()
    _console.print(
        f"[{_CLEAN_RESULT_STYLE}]{_CLEAN_RESULT_TEXT}[/{_CLEAN_RESULT_STYLE}]",
        justify=_JUSTIFY_CENTER,
    )
    _console.print()


def _build_violation_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the violation alert panel.

    Args:
        scan_result: The completed scan result that contains violations.

    Returns:
        Newline-separated Rich markup string with finding count and risk level.
    """
    count = len(scan_result.findings)
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    word = _FINDING_WORD if count == _SINGULAR_COUNT else _FINDING_WORD_PLURAL
    return "\n".join(
        [
            f"[{_STYLE_BOLD}]{count} {word} {_VIOLATION_DETECTED_SUFFIX}[/{_STYLE_BOLD}]",
            f"{_VIOLATION_RISK_LEVEL_LABEL}"
            f"[{risk_style}]{_format_risk_level_display(scan_result.risk_level)}[/{risk_style}]",
        ]
    )


def display_violation_alert(scan_result: ScanResult) -> None:
    """Render a red alert panel summarising the violation count and risk level.

    Args:
        scan_result: The completed scan result that contains violations.
    """
    _console.print(
        Panel(
            _build_violation_panel_markup(scan_result),
            title=_VIOLATION_ALERT_TITLE,
            border_style=_VIOLATION_BORDER_STYLE,
        )
    )


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
    _console.print(table)
