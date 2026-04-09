"""Rich console display functions: banners, phase separators, findings UI, and baseline panels."""

# ruff: noqa: E402 — sub-module re-exports intentionally placed after constants to avoid
# circular imports; sub-modules import constants from this module at load time.

from __future__ import annotations

from typing import Literal

from phi_scan.constants import RiskLevel, SeverityLevel
from phi_scan.output.console.core import (
    _detect_unicode_support,
    _rich_console as _rich_console,
    create_scan_progress as create_scan_progress,
    display_status_spinner as display_status_spinner,
    get_console as get_console,
)

# ---------------------------------------------------------------------------
# Unicode support detection
# _UNICODE_SUPPORTED and _resolve_symbol are defined here (not in core.py) so
# that monkeypatch.setattr("phi_scan.output.console._UNICODE_SUPPORTED", ...)
# in tests correctly affects the _resolve_symbol function's behaviour.
# _detect_unicode_support is imported from core.py; the result is bound here.
# ---------------------------------------------------------------------------


_UNICODE_SUPPORTED: bool = _detect_unicode_support()


def _resolve_symbol(unicode_char: str, ascii_char: str) -> str:
    """Return unicode_char when the terminal supports Unicode, else ascii_char.

    Args:
        unicode_char: The preferred Unicode glyph (emoji, box-drawing, etc.).
        ascii_char: The ASCII-safe fallback for non-UTF-8 terminals.

    Returns:
        unicode_char if _UNICODE_SUPPORTED, ascii_char otherwise.
    """
    return unicode_char if _UNICODE_SUPPORTED else ascii_char


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
_STYLE_CYAN: str = "cyan"
_STYLE_DIM_YELLOW: str = "dim yellow"
_STYLE_BOLD_WHITE_ON_RED: str = "bold white on red"

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
# Unicode symbols — raw pairs and resolved constants
# Each symbol has a Unicode form (UTF-8 terminals) and an ASCII fallback
# (legacy terminals, ASCII-only pipes). _resolve_symbol selects at import time.
# IMPORTANT: The resolved _ICON_* / _CODE_CONTEXT_ARROW / _CONFIDENCE_DOT_* constants
# below are frozen at module import and are NOT affected by later monkeypatching of
# _UNICODE_SUPPORTED. Tests must call _resolve_symbol directly (not read the resolved
# constants) to exercise the Unicode vs ASCII selection paths.
# ---------------------------------------------------------------------------

_UNICODE_ICON_CLEAN: str = "✅"
_ASCII_ICON_CLEAN: str = "[OK]"
_UNICODE_ICON_VIOLATION: str = "⚠"
_ASCII_ICON_VIOLATION: str = "[!]"
_UNICODE_ICON_FILE: str = "📄"
_ASCII_ICON_FILE: str = "[f]"
_UNICODE_ICON_FOLDER: str = "📁"
_ASCII_ICON_FOLDER: str = "[d]"
_UNICODE_CODE_CONTEXT_ARROW: str = "►"
_ASCII_CODE_CONTEXT_ARROW: str = ">"
_UNICODE_CONFIDENCE_DOT_FILLED: str = "●"
_ASCII_CONFIDENCE_DOT_FILLED: str = "#"
_UNICODE_CONFIDENCE_DOT_EMPTY: str = "○"
_ASCII_CONFIDENCE_DOT_EMPTY: str = "."
_UNICODE_SEVERITY_HIGH: str = "🔴"
_ASCII_SEVERITY_HIGH: str = "[H]"
_UNICODE_SEVERITY_MEDIUM: str = "🟡"
_ASCII_SEVERITY_MEDIUM: str = "[M]"
_UNICODE_SEVERITY_LOW: str = "🟢"
_ASCII_SEVERITY_LOW: str = "[L]"
_UNICODE_SEVERITY_INFO: str = "⚪"
_ASCII_SEVERITY_INFO: str = "[I]"

_ICON_CLEAN: str = _resolve_symbol(_UNICODE_ICON_CLEAN, _ASCII_ICON_CLEAN)
_ICON_VIOLATION: str = _resolve_symbol(_UNICODE_ICON_VIOLATION, _ASCII_ICON_VIOLATION)
_ICON_FILE: str = _resolve_symbol(_UNICODE_ICON_FILE, _ASCII_ICON_FILE)
_ICON_FOLDER: str = _resolve_symbol(_UNICODE_ICON_FOLDER, _ASCII_ICON_FOLDER)
_CODE_CONTEXT_ARROW: str = _resolve_symbol(_UNICODE_CODE_CONTEXT_ARROW, _ASCII_CODE_CONTEXT_ARROW)
_CONFIDENCE_DOT_FILLED: str = _resolve_symbol(
    _UNICODE_CONFIDENCE_DOT_FILLED, _ASCII_CONFIDENCE_DOT_FILLED
)
_CONFIDENCE_DOT_EMPTY: str = _resolve_symbol(
    _UNICODE_CONFIDENCE_DOT_EMPTY, _ASCII_CONFIDENCE_DOT_EMPTY
)
_SEVERITY_ICON_HIGH: str = _resolve_symbol(_UNICODE_SEVERITY_HIGH, _ASCII_SEVERITY_HIGH)
_SEVERITY_ICON_MEDIUM: str = _resolve_symbol(_UNICODE_SEVERITY_MEDIUM, _ASCII_SEVERITY_MEDIUM)
_SEVERITY_ICON_LOW: str = _resolve_symbol(_UNICODE_SEVERITY_LOW, _ASCII_SEVERITY_LOW)
_SEVERITY_ICON_INFO: str = _resolve_symbol(_UNICODE_SEVERITY_INFO, _ASCII_SEVERITY_INFO)

# Confidence visualization — dots rendered in the findings table confidence column.
_CONFIDENCE_DOT_COUNT: int = 5

# Banner gradient colors — applied line-by-line across the pyfiglet ASCII art.
_BANNER_GRADIENT_COLORS: tuple[str, ...] = ("cyan", "blue", "magenta")
# Offset to convert a 1-based color count to a 0-based maximum valid index.
_COLOR_INDEX_OFFSET: int = 1

# ---------------------------------------------------------------------------
# Panel and rule styles
# ---------------------------------------------------------------------------

_PANEL_LABEL_STYLE: str = _STYLE_BOLD_CYAN
_PANEL_BORDER_STYLE: str = _STYLE_CYAN
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
_BANNER_PYFIGLET_MISSING_NOTE: str = (
    "note: install pyfiglet for ASCII art banner (pip install pyfiglet)"
)
_BANNER_MIN_LINE_COUNT: int = 1  # floor for gradient line-count division safety

# ---------------------------------------------------------------------------
# Panel and table titles
# ---------------------------------------------------------------------------

_PHASE_SEPARATOR_COLLECTING: str = "Collecting Files"
_PHASE_SEPARATOR_SCANNING: str = "Scanning for PHI/PII"
_PHASE_SEPARATOR_AUDIT: str = "Writing Audit Log"
_PHASE_SEPARATOR_REPORT: str = "Generating Report"
_PHASE_SEPARATOR_STYLE: str = _STYLE_BOLD_CYAN

# Maximum number of named extensions shown in the file type summary line.
# Extensions beyond this count are folded into the "other" bucket.
_FILE_TYPE_SUMMARY_MAX_EXTENSIONS: int = 5
_FILE_TYPE_SUMMARY_OTHER_LABEL: str = "other"
_FILE_TYPE_SUMMARY_SEPARATOR: str = " | "
_FILE_TYPE_SUMMARY_ENTRY_FORMAT: str = "{ext}: {count}"
_FILE_TYPE_SUMMARY_STYLE: str = _STYLE_DIM
_FILE_TYPE_SUMMARY_ZERO_FILES_MESSAGE: str = "No files collected."

_SCAN_HEADER_TITLE: str = "Scan Target"
_SUMMARY_PANEL_TITLE: str = "Scan Summary"
_CATEGORY_TABLE_TITLE: str = "PHI Category Breakdown"
_FINDINGS_TABLE_TITLE: str = "Findings"
_FILE_TREE_TITLE: str = "Affected Files"
_VIOLATION_ALERT_TITLE: str = "PHI/PII Violation Detected"
_VIOLATION_RISK_LEVEL_LABEL: str = "Risk Level: "

# Severity levels ordered from highest to lowest — used when selecting the
# most severe icon to represent a group of findings.
_SEVERITY_DESCENDING_ORDER: tuple[SeverityLevel, ...] = (
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
)

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

_CLEAN_RESULT_ICON: str = _ICON_CLEAN
_CLEAN_RESULT_TEXT: str = "CLEAN — No PHI or PII Detected"
_CLEAN_RESULT_STYLE: str = _STYLE_BOLD_GREEN
_CLEAN_SUMMARY_PANEL_TITLE: str = "Scan Complete"
_CLEAN_SUMMARY_BORDER_STYLE: str = _STYLE_BOLD_GREEN
_CLEAN_SUMMARY_STATUS_VALUE: str = f"{_ICON_CLEAN}  CLEAN"
_CLEAN_SUMMARY_STATUS_LABEL: str = "Status"
_CLEAN_SUMMARY_FILES_LABEL: str = "Files Scanned"
_CLEAN_SUMMARY_TIME_LABEL: str = "Scan Time"
_CLEAN_SUMMARY_RISK_LABEL: str = "Risk Level"
_EXIT_CODE_CLEAN_MESSAGE: str = "Exit code: 0 (clean)"
_EXIT_CODE_CLEAN_STYLE: str = _STYLE_BOLD_GREEN
_EXIT_CODE_VIOLATION_MESSAGE: str = "Exit code: 1 (violations found — pipeline blocked)"
_EXIT_CODE_VIOLATION_STYLE: str = _STYLE_BOLD_RED

# ---------------------------------------------------------------------------
# Violation display
# ---------------------------------------------------------------------------

_VIOLATION_ALERT_ICON: str = _ICON_VIOLATION
_VIOLATION_ALERT_MESSAGE_FORMAT: str = (
    "{icon}  PHI/PII DETECTED — {count} {finding_word} in {files} {file_word}"
)
_VIOLATION_ALERT_BOX_STYLE: str = _STYLE_BOLD_RED
_RISK_LEVEL_BADGE_STYLE: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: _STYLE_BOLD_WHITE_ON_RED,
    RiskLevel.HIGH: _STYLE_BOLD_RED,
    RiskLevel.MODERATE: _STYLE_YELLOW,
    RiskLevel.LOW: _STYLE_DIM_YELLOW,
    RiskLevel.CLEAN: _STYLE_BOLD_GREEN,
}
_SEVERITY_ICON: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _SEVERITY_ICON_HIGH,
    SeverityLevel.MEDIUM: _SEVERITY_ICON_MEDIUM,
    SeverityLevel.LOW: _SEVERITY_ICON_LOW,
    SeverityLevel.INFO: _SEVERITY_ICON_INFO,
}
_SEVERITY_INLINE_SEPARATOR: str = "    "
_SEVERITY_INLINE_FORMAT: str = "{icon} {level}: {count}"
_VIOLATION_SUMMARY_STATUS_VALUE: str = f"{_ICON_VIOLATION}  VIOLATION"
_VIOLATION_SUMMARY_STATUS_LABEL: str = "Status"
_VIOLATION_SUMMARY_RISK_LABEL: str = "Risk Level"
_VIOLATION_SUMMARY_FINDINGS_LABEL: str = "Findings"
_VIOLATION_SUMMARY_FILES_LABEL: str = "Files"
_VIOLATION_SUMMARY_FILES_FORMAT: str = "{with_findings} of {total:,} contain PHI"
_VIOLATION_SUMMARY_TIME_LABEL: str = "Scan Time"
_VIOLATION_SUMMARY_AUDIT_LABEL: str = "Audit Log"
_VIOLATION_SUMMARY_ACTION_LABEL: str = "Action"
_VIOLATION_SUMMARY_ACTION_VALUE: str = "Pipeline BLOCKED — exit code 1"
_VIOLATION_SUMMARY_PANEL_TITLE: str = "Scan Complete"
_CODE_CONTEXT_PANEL_FORMAT: str = "{file}:{line}  —  {entity} ({severity})"
_CODE_CONTEXT_REMEDIATION_PREFIX: str = "💡 Remediation: "
_FILE_WORD: str = "file"
_FILE_WORD_PLURAL: str = "files"

_JUSTIFY_CENTER: Literal["center"] = "center"
_JUSTIFY_RIGHT: Literal["right"] = "right"

# ---------------------------------------------------------------------------
# Numeric and format constants
# ---------------------------------------------------------------------------

_CONFIDENCE_FORMAT: str = "{:.2f}"
_DURATION_FORMAT: str = "{:.2f}s"
_TIMESTAMP_TIMESPEC: str = "seconds"

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
# Baseline display constants (Phase 3B)
# ---------------------------------------------------------------------------

_BASELINE_SUMMARY_TITLE: str = "Baseline Summary"
_BASELINE_DIFF_TITLE: str = "Baseline Diff"
_BASELINE_DRIFT_TITLE: str = "Baseline Drift Warning"
_BASELINE_NOTICE_TITLE: str = "Baseline Mode"

_BASELINE_SUMMARY_BORDER_STYLE: str = "bold cyan"
_BASELINE_DRIFT_BORDER_STYLE: str = "bold yellow"
_BASELINE_NOTICE_BORDER_STYLE: str = "bold blue"

_BASELINE_ENTRY_LABEL: str = "entry"
_BASELINE_ENTRIES_LABEL: str = "entries"

_BASELINE_ACTIVE_STYLE: str = "green"
_BASELINE_EXPIRED_STYLE: str = "dim"
_BASELINE_NEW_STYLE: str = "bold red"
_BASELINE_RESOLVED_STYLE: str = "green"
_BASELINE_PERSISTING_STYLE: str = "dim"

_BASELINE_NEW_SECTION_HEADER_FORMAT: str = (
    f"[{_BASELINE_NEW_STYLE}]NEW — not in baseline ({{count}})[/{_BASELINE_NEW_STYLE}]"
)
_BASELINE_RESOLVED_SECTION_HEADER_FORMAT: str = (
    f"[{_BASELINE_RESOLVED_STYLE}]RESOLVED — no longer detected ({{count}})"
    f"[/{_BASELINE_RESOLVED_STYLE}]"
)
_BASELINE_PERSISTING_SECTION_HEADER_FORMAT: str = (
    f"[{_BASELINE_PERSISTING_STYLE}]PERSISTING — still present, still baselined ({{count}})"
    f"[/{_BASELINE_PERSISTING_STYLE}]"
)
_BASELINE_DIFF_FINDING_ROW: str = "  {file_path}:{line}  {entity_type}  {severity}"
_BASELINE_DIFF_ENTRY_ROW: str = _BASELINE_DIFF_FINDING_ROW  # same format; alias avoids duplication
_BASELINE_DRIFT_MESSAGE: str = (
    "Baseline entry count increased by [bold yellow]{percent}%[/bold yellow] "
    "({old} → {new} entries).\n"
    "This may indicate PHI accumulation. Consider remediating findings\n"
    "rather than accepting them into the baseline."
)
_BASELINE_SCAN_NOTICE_MESSAGE: str = (
    "[bold]{new_count} new finding(s)[/bold]  ·  "
    "[dim]{baselined_count} suppressed by baseline[/dim]"
)
_BASELINE_SCAN_CLEAN_MESSAGE: str = (
    "[bold green]No new findings[/bold green]  ·  "
    "[dim]{baselined_count} suppressed by baseline[/dim]"
)

_ENTRY_PLURAL_THRESHOLD: int = 1

# ---------------------------------------------------------------------------
# Re-exports from sub-modules — import last so all constants are defined first,
# allowing sub-modules to import from phi_scan.output.console without circular issues.
# ---------------------------------------------------------------------------

from phi_scan.output.console.baseline import (
    _format_entry_label as _format_entry_label,
    display_baseline_diff as display_baseline_diff,
    display_baseline_drift_warning as display_baseline_drift_warning,
    display_baseline_scan_notice as display_baseline_scan_notice,
    display_baseline_summary as display_baseline_summary,
)
from phi_scan.output.console.findings import (
    _build_confidence_dots as _build_confidence_dots,
    _build_count_bar as _build_count_bar,
    _build_findings_table as _build_findings_table,
    _group_findings_by_file as _group_findings_by_file,
    _highest_severity_icon as _highest_severity_icon,
    display_category_breakdown as display_category_breakdown,
    display_code_context_panel as display_code_context_panel,
    display_file_tree as display_file_tree,
    display_findings_table as display_findings_table,
    format_table as format_table,
)
from phi_scan.output.console.summary import (
    _build_ascii_banner_text as _build_ascii_banner_text,
    _build_banner_gradient_text as _build_banner_gradient_text,
    _build_clean_summary_panel_markup as _build_clean_summary_panel_markup,
    _build_scan_header_markup as _build_scan_header_markup,
    _build_severity_breakdown as _build_severity_breakdown,
    _build_severity_inline_text as _build_severity_inline_text,
    _build_summary_panel_markup as _build_summary_panel_markup,
    _build_violation_alert_text as _build_violation_alert_text,
    _build_violation_summary_panel_markup as _build_violation_summary_panel_markup,
    _count_files_by_extension as _count_files_by_extension,
    _format_risk_level_display as _format_risk_level_display,
    _select_banner_gradient_color as _select_banner_gradient_color,
    display_banner as display_banner,
    display_clean_result as display_clean_result,
    display_clean_summary_panel as display_clean_summary_panel,
    display_exit_code_message as display_exit_code_message,
    display_file_type_summary as display_file_type_summary,
    display_phase_audit as display_phase_audit,
    display_phase_collecting as display_phase_collecting,
    display_phase_report as display_phase_report,
    display_phase_scanning as display_phase_scanning,
    display_phase_separator as display_phase_separator,
    display_risk_level_badge as display_risk_level_badge,
    display_scan_header as display_scan_header,
    display_severity_inline as display_severity_inline,
    display_summary_panel as display_summary_panel,
    display_violation_alert as display_violation_alert,
    display_violation_summary_panel as display_violation_summary_panel,
)
