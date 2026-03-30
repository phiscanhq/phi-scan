"""Output formatters (table, json, csv, sarif, junit, codequality, gitlab-sast) and Rich UI."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import operator
import sys
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal
from xml.etree import ElementTree

from rich import box as rich_box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Column, Table
from rich.text import Text
from rich.tree import Tree

from phi_scan import __version__
from phi_scan.constants import PhiCategory, RiskLevel, SeverityLevel
from phi_scan.models import ScanConfig, ScanFinding, ScanResult

__all__ = [
    "build_dashboard_layout",
    "build_watch_layout",
    "get_console",
    "WatchEvent",
    "display_banner",
    "display_category_breakdown",
    "display_clean_result",
    "display_clean_summary_panel",
    "display_exit_code_message",
    "display_file_tree",
    "display_findings_table",
    "display_file_type_summary",
    "display_phase_audit",
    "display_status_spinner",
    "display_phase_collecting",
    "display_phase_report",
    "display_phase_scanning",
    "display_phase_separator",
    "display_scan_header",
    "create_scan_progress",
    "display_code_context_panel",
    "display_risk_level_badge",
    "display_severity_inline",
    "display_violation_alert",
    "display_violation_summary_panel",
    "display_baseline_diff",
    "display_baseline_drift_warning",
    "display_baseline_scan_notice",
    "display_baseline_summary",
    "format_codequality",
    "format_csv",
    "format_gitlab_sast",
    "format_json",
    "format_junit",
    "format_sarif",
    "format_table",
]

# ---------------------------------------------------------------------------
# Module-level Rich console — all display functions write to this instance.
# Rich automatically respects the NO_COLOR environment variable (no-color.org).
# Note: NO_COLOR suppresses ANSI color codes only — Unicode glyphs are unaffected,
# which is correct per the no-color.org specification.
# ---------------------------------------------------------------------------

_console: Console = Console()


def get_console() -> Console:
    """Return the shared module-level Rich console.

    Callers that need to print Rich markup should use this rather than
    constructing their own Console instance — a single instance ensures
    consistent output buffering and colour detection across the CLI.
    """
    return _console


# ---------------------------------------------------------------------------
# Unicode support detection
# Defined before symbol constants so _resolve_symbol is available at constant
# initialization time. Detection is done once at import and stored as a module
# constant to avoid repeated encoding lookups on every render call.
# ---------------------------------------------------------------------------

_UNICODE_ENCODING_PREFIX: str = "UTF"


def _detect_unicode_support() -> bool:
    """Return True when the terminal encoding can represent Unicode characters.

    Checks sys.stdout.encoding. Falls back to False when encoding is absent or
    non-UTF — covers ASCII-only terminals, legacy Windows cmd.exe, and pipes
    redirected to ASCII sinks.

    Returns:
        True if the stdout encoding starts with "UTF" (e.g. UTF-8, UTF-16).
    """
    encoding: str = getattr(sys.stdout, "encoding", None) or ""
    return encoding.upper().startswith(_UNICODE_ENCODING_PREFIX)


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
# JUnit XML protocol constants
# ---------------------------------------------------------------------------

_JUNIT_TESTSUITE_NAME: str = "phi-scan"
_JUNIT_TESTSUITE_TAG: str = "testsuite"
_JUNIT_TESTCASE_TAG: str = "testcase"
_JUNIT_FAILURE_TAG: str = "failure"
_JUNIT_FAILURE_TYPE: str = "PHIViolation"
_JUNIT_ERROR_COUNT: str = "0"
_JUNIT_INDENT: str = "  "
_JUNIT_ENCODING: str = "utf-8"
_JUNIT_DURATION_FORMAT: str = "{:.2f}"
_JUNIT_CONFIDENCE_FORMAT: str = "{:.2f}"
_JUNIT_TESTCASE_NAME_FORMAT: str = "{file_path}:{line_number} [{entity_type}]"
_JUNIT_FAILURE_MESSAGE_FORMAT: str = "[{severity}] PHI detected: {entity_type}"
_JUNIT_FAILURE_TEXT_FORMAT: str = (
    "file: {file_path}\nline: {line_number}\ncategory: {hipaa_category}\n"
    "confidence: {confidence}\nremediation: {remediation_hint}"
)

# ---------------------------------------------------------------------------
# GitLab Code Quality protocol constants
# ---------------------------------------------------------------------------

_CODEQUALITY_SEVERITY_CRITICAL: str = "critical"
_CODEQUALITY_SEVERITY_MAJOR: str = "major"
_CODEQUALITY_SEVERITY_MINOR: str = "minor"
_CODEQUALITY_SEVERITY_INFO: str = "info"
_SEVERITY_TO_CODEQUALITY: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _CODEQUALITY_SEVERITY_CRITICAL,
    SeverityLevel.MEDIUM: _CODEQUALITY_SEVERITY_MAJOR,
    SeverityLevel.LOW: _CODEQUALITY_SEVERITY_MINOR,
    SeverityLevel.INFO: _CODEQUALITY_SEVERITY_INFO,
}
_CODEQUALITY_DESCRIPTION_FORMAT: str = "PHI detected: {entity_type} ({category})"

# ---------------------------------------------------------------------------
# GitLab SAST protocol constants
# ---------------------------------------------------------------------------

_GITLAB_SAST_VERSION: str = "15.0.4"
_GITLAB_SAST_CATEGORY: str = "sast"
_GITLAB_SAST_SCANNER_ID: str = "phi-scan"
_GITLAB_SAST_SCANNER_NAME: str = "PhiScan"
_GITLAB_SAST_VENDOR_NAME: str = "PhiScan"
_GITLAB_SAST_SCAN_TYPE: str = "sast"
_GITLAB_SAST_SCAN_STATUS: str = "success"
_GITLAB_SAST_IDENTIFIER_TYPE: str = "phi_scan_rule"
_GITLAB_SAST_VULNERABILITY_NAME_FORMAT: str = "PHI detected: {entity_type}"
_GITLAB_SAST_DESCRIPTION_FORMAT: str = "{category} identifier found by the {layer} detection layer"
_GITLAB_SAST_TIMESTAMP_FORMAT: str = "%Y-%m-%dT%H:%M:%SZ"
_GITLAB_SAST_SEVERITY_CRITICAL: str = "Critical"
_GITLAB_SAST_SEVERITY_HIGH: str = "High"
_GITLAB_SAST_SEVERITY_MEDIUM: str = "Medium"
_GITLAB_SAST_SEVERITY_LOW: str = "Low"
_SEVERITY_TO_GITLAB_SAST: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _GITLAB_SAST_SEVERITY_CRITICAL,
    SeverityLevel.MEDIUM: _GITLAB_SAST_SEVERITY_HIGH,
    SeverityLevel.LOW: _GITLAB_SAST_SEVERITY_MEDIUM,
    SeverityLevel.INFO: _GITLAB_SAST_SEVERITY_LOW,
}
_GITLAB_SAST_CONFIDENCE_HIGH: str = "High"
_GITLAB_SAST_CONFIDENCE_MEDIUM: str = "Medium"
_GITLAB_SAST_CONFIDENCE_LOW: str = "Low"
_SEVERITY_TO_GITLAB_SAST_CONFIDENCE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _GITLAB_SAST_CONFIDENCE_HIGH,
    SeverityLevel.MEDIUM: _GITLAB_SAST_CONFIDENCE_HIGH,
    SeverityLevel.LOW: _GITLAB_SAST_CONFIDENCE_MEDIUM,
    SeverityLevel.INFO: _GITLAB_SAST_CONFIDENCE_LOW,
}

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

# ---------------------------------------------------------------------------
# Panel and table titles
# ---------------------------------------------------------------------------

_PHASE_SEPARATOR_COLLECTING: str = "Collecting Files"
_PHASE_SEPARATOR_SCANNING: str = "Scanning for PHI/PII"
_PHASE_SEPARATOR_AUDIT: str = "Writing Audit Log"
_PHASE_SEPARATOR_REPORT: str = "Generating Report"
_PHASE_SEPARATOR_STYLE: str = _STYLE_BOLD_CYAN

_SPINNER_STYLE: str = "dots"

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
# Dashboard display
# ---------------------------------------------------------------------------

_DASHBOARD_TOP_PANEL_HEIGHT: int = 5
_DASHBOARD_BOTTOM_PANEL_HEIGHT: int = 3
_DASHBOARD_TOP_SECTION: str = "top"
_DASHBOARD_MAIN_SECTION: str = "main"
_DASHBOARD_LEFT_SECTION: str = "left"
_DASHBOARD_RIGHT_SECTION: str = "right"
_DASHBOARD_BOTTOM_SECTION: str = "bottom"
_DASHBOARD_STATUS_PANEL_TITLE: str = "PhiScan — Live Dashboard"
_DASHBOARD_HISTORY_PANEL_TITLE: str = "Recent Scans"
_DASHBOARD_CATEGORY_PANEL_TITLE: str = "PHI Categories"
_DASHBOARD_WATCHER_PANEL_TITLE: str = "Watch Status"
_DASHBOARD_COMPACT_BANNER: str = "⬛ PhiScan"
_DASHBOARD_VERSION_FORMAT: str = "v{version}  —  HIPAA-Compliant PHI/PII Scanner"
_DASHBOARD_LAST_SCAN_LABEL: str = "Last scan: "
_DASHBOARD_NO_HISTORY_TEXT: str = "No scan history found."
_DASHBOARD_NO_CATEGORIES_TEXT: str = "No findings recorded yet."
_DASHBOARD_WATCHER_INACTIVE_TEXT: str = "File watcher: Not active  (run phi-scan watch <path>)"
_DASHBOARD_HISTORY_CLEAN_STATUS: str = f"{_ICON_CLEAN} CLEAN"
_DASHBOARD_HISTORY_VIOLATION_STATUS: str = f"{_ICON_VIOLATION}  VIOLATION"
_DASHBOARD_HISTORY_CLEAN_STYLE: str = _STYLE_BOLD_GREEN
_DASHBOARD_HISTORY_VIOLATION_STYLE: str = _STYLE_BOLD_RED
_DASHBOARD_BOOLEAN_CLEAN: int = 1
_DASHBOARD_COL_TIME: str = "Time"
_DASHBOARD_COL_STATUS: str = "Status"
_DASHBOARD_COL_FILES: str = "Files"
_DASHBOARD_COL_FINDINGS: str = "Findings"
_DASHBOARD_COL_DURATION: str = "Duration"
_DASHBOARD_COL_CATEGORY: str = "HIPAA Category"
_DASHBOARD_COL_TOTAL: str = "Total"
# 19 = len("YYYY-MM-DD HH:MM:SS") — ISO-8601 local datetime without microseconds.
_DASHBOARD_TIMESTAMP_DISPLAY_LENGTH: int = 19

# ---------------------------------------------------------------------------
# Watch mode display
# ---------------------------------------------------------------------------

_WATCH_HEADER_PANEL_TITLE: str = "PhiScan — Watch Mode"
_WATCH_HEADER_FORMAT: str = "Watching: {path}  —  Press [bold]Ctrl+C[/bold] to stop"
# Shown in the panel subtitle so it appears inside the Rich alternate-screen buffer,
# not on stdout before Live() takes over (which would immediately scroll out of view).
_WATCH_PHASE_ONE_NOTE: str = (
    "Detection engine not loaded — run `phi-scan setup` to enable full scanning."
)
_WATCH_HEADER_HEIGHT: int = 4
_WATCH_HEADER_SECTION: str = "watch_header"
_WATCH_BODY_SECTION: str = "watch_body"
_WATCH_LOG_PANEL_TITLE: str = "Recent Events"
_WATCH_NO_EVENTS_TEXT: str = "Waiting for file changes…"
_WATCH_COL_TIME: str = "Time"
_WATCH_COL_FILE: str = "Changed File"
_WATCH_COL_RESULT: str = "Result"
# Timestamp format applied in _build_watch_event_table — kept in output.py so the
# display concern (how to render a datetime) stays in the same module that renders it.
_WATCH_TIMESTAMP_FORMAT: str = "%H:%M:%S"
# Style strings derived from WatchEvent.is_clean in _build_watch_event_table.
# Kept here (display layer) so WatchEvent only carries the typed is_clean bool.
_WATCH_RESULT_CLEAN_STYLE: str = _STYLE_BOLD_GREEN
_WATCH_RESULT_VIOLATION_STYLE: str = _STYLE_BOLD_RED
# Result text constants are public (no underscore) because cli.py imports them to
# build _WatchScanOutcome. Keeping them here rather than in constants.py preserves
# the display-layer boundary — they format terminal strings, not domain values.
WATCH_RESULT_CLEAN_TEXT: str = f"{_ICON_CLEAN} Clean"
WATCH_RESULT_VIOLATION_FORMAT: str = _ICON_VIOLATION + "  {count} findings detected"
# Rich inline markup template: "[{style}]text[/{style}]". Extracted so the
# literal tag syntax does not appear as a magic string in rendering logic.
_RICH_STYLED_TEXT_FORMAT: str = "[{style}]{text}[/{style}]"
# Filler for the two unused columns in the empty-state placeholder row.
_WATCH_EMPTY_CELL: str = ""


@dataclass(frozen=True)
class WatchEvent:
    """A single watch-mode event record rendered in the rolling event table.

    Created by cli.py when watchdog fires and scan_file completes; consumed
    by output.py to render the rolling log table. Frozen to prevent mutation
    across the shared deque boundary between the watchdog thread and main thread.
    event_time is stored as datetime so formatting stays in output.py and events
    remain sortable/comparable without reparsing a formatted string.
    """

    event_time: datetime
    file_path: str
    result_text: str
    # Typed boolean rather than a raw Rich style string — keeps the data model free of
    # display concerns. The rendering layer (_build_watch_event_table) derives the style.
    is_clean: bool


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
_PROGRESS_CURRENT_FILE_WIDTH: int = 40

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


def _select_banner_gradient_color(line_index: int, total_lines: int) -> str:
    """Pick a gradient color for a banner line by evenly distributing across the palette.

    Args:
        line_index: Zero-based position of the line within the banner.
        total_lines: Total number of lines in the banner.

    Returns:
        A Rich color name from _BANNER_GRADIENT_COLORS.
    """
    color_count = len(_BANNER_GRADIENT_COLORS)
    max_color_index = color_count - _COLOR_INDEX_OFFSET
    color_index = min(int(line_index * color_count / total_lines), max_color_index)
    return _BANNER_GRADIENT_COLORS[color_index]


def _build_banner_gradient_text(banner_str: str) -> Text:
    """Wrap the banner string in a Rich Text object with a cyan→blue→magenta gradient.

    Each line of the banner receives a color from _BANNER_GRADIENT_COLORS, distributed
    evenly from top to bottom. Under NO_COLOR, Rich strips ANSI codes automatically —
    the Text object renders as plain text with no color escapes.

    Args:
        banner_str: The pyfiglet ASCII art string (or plain text fallback).

    Returns:
        A Rich Text object with per-line color spans applied.
    """
    gradient_text = Text()
    lines = banner_str.splitlines()
    total_lines = max(len(lines), 1)
    for index, line in enumerate(lines):
        color = _select_banner_gradient_color(index, total_lines)
        gradient_text.append(line + "\n", style=color)
    return gradient_text


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
        confidence_str = _build_confidence_dots(finding.confidence)
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
    # remediation_hint must never contain raw PHI — SARIF is consumed by GitHub
    # Advanced Security and other external CI platforms. Enforcement of this
    # constraint belongs in ScanFinding.__post_init__, not here; output.py trusts
    # the model-layer contract. See _serialize_finding_to_dict for the full note.
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


def _build_severity_inline_text(severity_counts: MappingProxyType[SeverityLevel, int]) -> str:
    """Build a single-line severity breakdown with colored emoji icons.

    Only includes levels with at least one finding, so a scan with only HIGH
    findings shows just '🔴 HIGH: 4' without trailing zero entries.

    Args:
        severity_counts: Mapping from severity level to finding count.

    Returns:
        Inline Rich markup string: '🔴 HIGH: 4    🟡 MEDIUM: 5    🟢 LOW: 3'
    """
    severity_entries = []
    for level in SeverityLevel:
        count = severity_counts.get(level, _ZERO_FINDINGS)
        if count == _ZERO_FINDINGS:
            continue
        icon = _SEVERITY_ICON.get(level, "")
        style = _SEVERITY_STYLE[level]
        count_markup = f"[{style}]{count}[/{style}]"
        severity_entries.append(
            _SEVERITY_INLINE_FORMAT.format(icon=icon, level=level.value.upper(), count=count_markup)
        )
    return _SEVERITY_INLINE_SEPARATOR.join(severity_entries)


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
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=_CSV_FIELD_NAMES)
    writer.writeheader()
    for finding in scan_result.findings:
        writer.writerow(_serialize_finding_to_csv_row(finding))
    return csv_buffer.getvalue()


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
# JUnit XML formatter helpers
# ---------------------------------------------------------------------------


def _build_junit_failure_element(finding: ScanFinding) -> ElementTree.Element:
    """Build a JUnit <failure> element for one PHI finding.

    PHI-safety: embeds file_path, line_number, entity_type, and
    remediation_hint — all non-PHI metadata fields. The raw PHI value is never
    included; entity_type (e.g. "us_ssn") is a detection-rule identifier.

    Args:
        finding: The PHI finding to represent as a failure.

    Returns:
        A configured failure Element with message, type, and text body.
    """
    failure = ElementTree.Element(
        _JUNIT_FAILURE_TAG,
        {
            "message": _JUNIT_FAILURE_MESSAGE_FORMAT.format(
                severity=finding.severity.value.upper(),
                entity_type=finding.entity_type,
            ),
            "type": _JUNIT_FAILURE_TYPE,
        },
    )
    failure.text = _JUNIT_FAILURE_TEXT_FORMAT.format(
        file_path=finding.file_path,
        line_number=finding.line_number,
        hipaa_category=finding.hipaa_category.value,
        confidence=_JUNIT_CONFIDENCE_FORMAT.format(finding.confidence),
        remediation_hint=finding.remediation_hint,
    )
    return failure


def _build_junit_testcase(finding: ScanFinding) -> ElementTree.Element:
    """Build a JUnit <testcase> element with a <failure> child for one finding.

    Args:
        finding: The PHI finding to represent as a test failure.

    Returns:
        A configured testcase Element with a failure child.
    """
    testcase = ElementTree.Element(
        _JUNIT_TESTCASE_TAG,
        {
            "name": _JUNIT_TESTCASE_NAME_FORMAT.format(
                file_path=finding.file_path,
                line_number=finding.line_number,
                entity_type=finding.entity_type,
            ),
            "classname": finding.hipaa_category.value,
        },
    )
    testcase.append(_build_junit_failure_element(finding))
    return testcase


def format_junit(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to JUnit XML.

    Each PHI finding becomes a <testcase> with a <failure> child. Consumed
    by CircleCI Test Summary, Jenkins, Azure DevOps, and GitHub Actions test
    reporting panels.

    Args:
        scan_result: The completed scan result.

    Returns:
        JUnit XML string with an XML declaration, UTF-8 encoded.
    """
    suite_attrs = {
        "name": _JUNIT_TESTSUITE_NAME,
        "tests": str(len(scan_result.findings)),
        "failures": str(len(scan_result.findings)),
        "errors": _JUNIT_ERROR_COUNT,
        "time": _JUNIT_DURATION_FORMAT.format(scan_result.scan_duration),
    }
    suite = ElementTree.Element(_JUNIT_TESTSUITE_TAG, suite_attrs)
    for finding in scan_result.findings:
        suite.append(_build_junit_testcase(finding))
    ElementTree.indent(suite, space=_JUNIT_INDENT)
    serialized_xml_buffer = io.BytesIO()
    ElementTree.ElementTree(suite).write(
        serialized_xml_buffer, encoding=_JUNIT_ENCODING, xml_declaration=True
    )
    return serialized_xml_buffer.getvalue().decode(_JUNIT_ENCODING)


# ---------------------------------------------------------------------------
# Fingerprint primitive — shared by Code Quality and GitLab SAST formatters
# ---------------------------------------------------------------------------

# Both Code Quality and GitLab SAST fingerprints are keyed on the same
# three non-PHI metadata fields. One constant prevents the two formatters
# from drifting silently if the fingerprint scheme is ever updated.
_FINDING_FINGERPRINT_INPUT_FORMAT: str = "{file_path}:{line_number}:{entity_type}"


def _compute_sha256_hexadecimal(raw: str) -> str:
    """Return the lowercase SHA-256 hex digest of raw encoded as UTF-8.

    Args:
        raw: The pre-formatted string to hash.

    Returns:
        64-character lowercase hexadecimal digest.
    """
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# GitLab Code Quality formatter helpers
# ---------------------------------------------------------------------------


def _compute_finding_fingerprint(finding: ScanFinding) -> str:
    """Compute a stable SHA-256 fingerprint for a finding's location metadata.

    PHI-safety: only non-PHI metadata fields (file path, line number, entity
    type) are included in the fingerprint input. The raw PHI value is never
    hashed here — that is stored separately as finding.value_hash. Entity type
    (e.g. "us_ssn") is a detection-rule identifier, not the PHI value itself.

    Args:
        finding: The PHI finding to fingerprint.

    Returns:
        64-character lowercase hex digest, stable across runs for the same
        file/line/entity-type combination.
    """
    fingerprint_input = _FINDING_FINGERPRINT_INPUT_FORMAT.format(
        file_path=finding.file_path,
        line_number=finding.line_number,
        entity_type=finding.entity_type,
    )
    return _compute_sha256_hexadecimal(fingerprint_input)


def _build_codequality_entry(finding: ScanFinding) -> dict[str, object]:
    """Serialize one ScanFinding to a GitLab Code Quality issue dict.

    PHI-safety: description, location, and fingerprint contain only non-PHI
    metadata (entity_type rule name, file path, line number). The raw PHI
    value is never serialized into output. See _compute_finding_fingerprint
    for the PHI-safety rationale for entity_type.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict conforming to the gl-code-quality-report.json schema.
    """
    return {
        "description": _CODEQUALITY_DESCRIPTION_FORMAT.format(
            entity_type=finding.entity_type,
            category=finding.hipaa_category.value,
        ),
        "fingerprint": _compute_finding_fingerprint(finding),
        "severity": _SEVERITY_TO_CODEQUALITY[finding.severity],
        "location": {
            "path": str(finding.file_path),
            "lines": {"begin": finding.line_number},
        },
    }


def format_codequality(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to the GitLab Code Quality JSON format.

    Produces the gl-code-quality-report.json schema. Findings appear as
    inline MR annotations in GitLab's merge request view.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented JSON array — one entry per finding; empty array when clean.
    """
    entries = [_build_codequality_entry(finding) for finding in scan_result.findings]
    return json.dumps(entries, indent=_JSON_INDENT)


# ---------------------------------------------------------------------------
# GitLab SAST formatter helpers
# ---------------------------------------------------------------------------


def _build_gitlab_sast_location(finding: ScanFinding) -> dict[str, object]:
    """Build the location dict for a GitLab SAST vulnerability entry.

    PHI-safety: file_path is always relative — ScanFinding.__post_init__ rejects
    absolute paths, so str(finding.file_path) is safe to serialize directly.

    Args:
        finding: The finding to extract location metadata from.

    Returns:
        A location dict with file path and start/end line numbers.
    """
    return {
        "file": str(finding.file_path),
        "start_line": finding.line_number,
        "end_line": finding.line_number,
    }


def _build_gitlab_sast_vulnerability(finding: ScanFinding) -> dict[str, object]:
    """Serialize one ScanFinding to a GitLab SAST vulnerability dict.

    PHI-safety: name, description, location, and identifiers contain only
    non-PHI metadata (entity_type rule name, HIPAA category, file path, line
    number). The raw PHI value is never serialized into output. See
    _compute_finding_fingerprint for the PHI-safety rationale for entity_type.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict conforming to the gl-sast-report.json v15.0.4 schema.
    """
    return {
        "id": _compute_finding_fingerprint(finding),
        "category": _GITLAB_SAST_CATEGORY,
        "name": _GITLAB_SAST_VULNERABILITY_NAME_FORMAT.format(entity_type=finding.entity_type),
        "description": _GITLAB_SAST_DESCRIPTION_FORMAT.format(
            category=finding.hipaa_category.value,
            layer=finding.detection_layer.value,
        ),
        "severity": _SEVERITY_TO_GITLAB_SAST[finding.severity],
        "confidence": _SEVERITY_TO_GITLAB_SAST_CONFIDENCE[finding.severity],
        "scanner": {"id": _GITLAB_SAST_SCANNER_ID, "name": _GITLAB_SAST_SCANNER_NAME},
        "location": _build_gitlab_sast_location(finding),
        "identifiers": [
            {
                "type": _GITLAB_SAST_IDENTIFIER_TYPE,
                "name": finding.entity_type,
                "value": finding.entity_type,
            }
        ],
    }


def _build_gitlab_sast_scan_section(scan_result: ScanResult) -> dict[str, object]:
    """Build the scan metadata section of a GitLab SAST report.

    Args:
        scan_result: The completed scan result (used for timing).

    Returns:
        A scan dict with analyzer, scanner, type, timestamps, and status.
    """
    end_time = datetime.now(tz=UTC)
    start_time = end_time - timedelta(seconds=scan_result.scan_duration)
    start_time_iso = start_time.strftime(_GITLAB_SAST_TIMESTAMP_FORMAT)
    end_time_iso = end_time.strftime(_GITLAB_SAST_TIMESTAMP_FORMAT)
    analyzer_block = {
        "id": _GITLAB_SAST_SCANNER_ID,
        "name": _GITLAB_SAST_SCANNER_NAME,
        "vendor": {"name": _GITLAB_SAST_VENDOR_NAME},
        "version": __version__,
    }
    scanner_block = {
        "id": _GITLAB_SAST_SCANNER_ID,
        "name": _GITLAB_SAST_SCANNER_NAME,
        "vendor": {"name": _GITLAB_SAST_VENDOR_NAME},
        "version": __version__,
    }
    return {
        "analyzer": analyzer_block,
        "scanner": scanner_block,
        "type": _GITLAB_SAST_SCAN_TYPE,
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "status": _GITLAB_SAST_SCAN_STATUS,
    }


def format_gitlab_sast(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to the GitLab SAST JSON format (v15.0.4).

    Produces the gl-sast-report.json schema. Findings appear in GitLab's
    Security Dashboard and as MR security annotations.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented SAST JSON string — empty vulnerabilities array when clean.
    """
    sast_doc: dict[str, object] = {
        "version": _GITLAB_SAST_VERSION,
        "vulnerabilities": [
            _build_gitlab_sast_vulnerability(finding) for finding in scan_result.findings
        ],
        "scan": _build_gitlab_sast_scan_section(scan_result),
    }
    return json.dumps(sast_doc, indent=_JSON_INDENT)


# ---------------------------------------------------------------------------
# Display functions — render Rich components to the console
# ---------------------------------------------------------------------------


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
    """Render the PhiScan ASCII art banner with a cyan→blue→magenta gradient, tagline, and rule."""
    _console.print(_build_banner_gradient_text(_build_ascii_banner_text()))
    _console.print(
        _BANNER_TAGLINE_TEMPLATE.format(version=__version__),
        style=_BANNER_TAGLINE_STYLE,
    )
    _console.rule(style=_RULE_STYLE)


def display_phase_separator(title: str) -> None:
    """Render a styled console rule marking the start of a named scan phase.

    Used between the four scan stages (Collecting Files, Scanning for PHI/PII,
    Writing Audit Log, Generating Report) to give the user a clear visual cue
    that the terminal is progressing through distinct work phases.

    Args:
        title: Short human-readable phase name to embed in the rule line.
    """
    _console.rule(title, style=_PHASE_SEPARATOR_STYLE)


def display_phase_collecting() -> None:
    """Render the 'Collecting Files' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_COLLECTING)


def display_phase_scanning() -> None:
    """Render the 'Scanning for PHI/PII' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_SCANNING)


def display_phase_audit() -> None:
    """Render the 'Writing Audit Log' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_AUDIT)


def display_phase_report() -> None:
    """Render the 'Generating Report' phase separator rule."""
    display_phase_separator(_PHASE_SEPARATOR_REPORT)


@contextmanager
def display_status_spinner(message: str, is_active: bool) -> Generator[None, None, None]:
    """Show a spinner with status text for the duration of the wrapped block.

    When is_active is False the context manager is a no-op, allowing call
    sites to pass is_rich_mode directly without a conditional at every usage.

    Args:
        message: Status text shown beside the spinner.
        is_active: Show the spinner only when True.

    Yields:
        None — caller wraps the work block.
    """
    if is_active:
        with _console.status(message, spinner=_SPINNER_STYLE):
            yield
    else:
        yield


def _count_files_by_extension(scan_targets: list[Path]) -> dict[str, int]:
    """Count scan targets grouped by lowercased file extension.

    Files with no extension are tallied under the 'other' bucket key so they
    surface in the summary without a misleading blank label.

    Args:
        scan_targets: Paths returned by _resolve_scan_targets.

    Returns:
        Mapping of extension string (e.g. '.py') to file count.
        The 'other' key is only present when at least one file has no extension.
    """
    counts: dict[str, int] = {}
    for file_path in scan_targets:
        extension = file_path.suffix.lower() if file_path.suffix else _FILE_TYPE_SUMMARY_OTHER_LABEL
        counts[extension] = counts.get(extension, 0) + 1
    return counts


def display_file_type_summary(scan_targets: list[Path]) -> None:
    """Print a one-line file type breakdown after the collection phase.

    Shows up to _FILE_TYPE_SUMMARY_MAX_EXTENSIONS named extensions sorted by
    count descending. Remaining files are folded into an 'other' bucket.
    Outputs nothing if scan_targets is empty — the zero-files message is
    printed instead.

    Args:
        scan_targets: Collected file paths, as returned by _resolve_scan_targets.
    """
    if not scan_targets:
        _console.print(_FILE_TYPE_SUMMARY_ZERO_FILES_MESSAGE, style=_FILE_TYPE_SUMMARY_STYLE)
        return
    counts = _count_files_by_extension(scan_targets)
    sorted_extensions = sorted(
        counts.items(), key=lambda extension_count_pair: extension_count_pair[1], reverse=True
    )
    top_extensions = sorted_extensions[:_FILE_TYPE_SUMMARY_MAX_EXTENSIONS]
    overflow_extensions = sorted_extensions[_FILE_TYPE_SUMMARY_MAX_EXTENSIONS:]
    overflow_count = sum(count for _, count in overflow_extensions)
    extension_entries = [
        _FILE_TYPE_SUMMARY_ENTRY_FORMAT.format(ext=ext, count=count)
        for ext, count in top_extensions
    ]
    if overflow_count:
        extension_entries.append(
            _FILE_TYPE_SUMMARY_ENTRY_FORMAT.format(
                ext=_FILE_TYPE_SUMMARY_OTHER_LABEL, count=overflow_count
            )
        )
    _console.print(
        _FILE_TYPE_SUMMARY_SEPARATOR.join(extension_entries), style=_FILE_TYPE_SUMMARY_STYLE
    )


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
        MofNCompleteColumn(),
        TextColumn(
            "[progress.description]{task.description}",
            table_column=Column(min_width=_PROGRESS_CURRENT_FILE_WIDTH, no_wrap=True),
        ),
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
        branch = tree.add(f"{icon} {file_path} ({count} {finding_word})")
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

    Deprecated: superseded by display_clean_summary_panel and
    display_violation_summary_panel which provide split clean/violation UI.
    Retained for test coverage only — not part of the public API.

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
    """Render a large green checkmark and CLEAN headline for zero-finding scans."""
    _console.print()
    _console.print(_CLEAN_RESULT_ICON, justify=_JUSTIFY_CENTER)
    _console.print(
        f"[{_CLEAN_RESULT_STYLE}]{_CLEAN_RESULT_TEXT}[/{_CLEAN_RESULT_STYLE}]",
        justify=_JUSTIFY_CENTER,
    )
    _console.print()


def _build_clean_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the clean scan summary panel.

    Args:
        scan_result: A completed scan result with zero findings.

    Returns:
        Newline-separated Rich markup string showing status, file count,
        scan time, and risk level.
    """
    label_style = _PANEL_LABEL_STYLE
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    return "\n".join(
        [
            f"[{label_style}]{_CLEAN_SUMMARY_STATUS_LABEL}:[/{label_style}]"
            f"  {_CLEAN_SUMMARY_STATUS_VALUE}",
            f"[{label_style}]{_CLEAN_SUMMARY_FILES_LABEL}:[/{label_style}]"
            f"  {scan_result.files_scanned:,}",
            f"[{label_style}]{_CLEAN_SUMMARY_TIME_LABEL}:[/{label_style}]  {duration_str}",
            f"[{label_style}]{_CLEAN_SUMMARY_RISK_LABEL}:[/{label_style}]"
            f"  [{_CLEAN_RESULT_STYLE}]{_format_risk_level_display(scan_result.risk_level)}"
            f"[/{_CLEAN_RESULT_STYLE}]",
        ]
    )


def display_clean_summary_panel(scan_result: ScanResult) -> None:
    """Render the green-bordered 'Scan Complete' summary panel for clean scans.

    Args:
        scan_result: A completed scan result with zero findings.
    """
    _console.print(
        Panel(
            _build_clean_summary_panel_markup(scan_result),
            title=_CLEAN_SUMMARY_PANEL_TITLE,
            border_style=_CLEAN_SUMMARY_BORDER_STYLE,
        )
    )


def display_exit_code_message(is_clean: bool) -> None:
    """Print a colored exit code line at the end of the scan output.

    Args:
        is_clean: True for a clean scan (exit 0), False for violations (exit 1).
    """
    if is_clean:
        _console.print(_EXIT_CODE_CLEAN_MESSAGE, style=_EXIT_CODE_CLEAN_STYLE)
    else:
        _console.print(_EXIT_CODE_VIOLATION_MESSAGE, style=_EXIT_CODE_VIOLATION_STYLE)


def _build_violation_alert_text(scan_result: ScanResult) -> str:
    """Build the full-width alert message for the heavy-box violation banner.

    Args:
        scan_result: The completed scan result that contains violations.

    Returns:
        Rich markup string: '⚠  PHI/PII DETECTED — N findings in M files'
    """
    count = len(scan_result.findings)
    finding_word = _FINDING_WORD if count == _SINGULAR_COUNT else _FINDING_WORD_PLURAL
    files = scan_result.files_with_findings
    file_word = _FILE_WORD if files == _SINGULAR_COUNT else _FILE_WORD_PLURAL
    return _VIOLATION_ALERT_MESSAGE_FORMAT.format(
        icon=_VIOLATION_ALERT_ICON,
        count=count,
        finding_word=finding_word,
        files=files,
        file_word=file_word,
    )


def display_violation_alert(scan_result: ScanResult) -> None:
    """Render a full-width heavy-box red alert banner for violation scans.

    Uses rich.box.HEAVY (┏━━━┓ borders) and embeds the ⚠ icon, finding
    count, and affected file count directly in the panel content.

    Args:
        scan_result: The completed scan result that contains violations.
    """
    _console.print(
        Panel(
            f"[{_VIOLATION_ALERT_BOX_STYLE}]{_build_violation_alert_text(scan_result)}"
            f"[/{_VIOLATION_ALERT_BOX_STYLE}]",
            box=rich_box.HEAVY,
            border_style=_VIOLATION_BORDER_STYLE,
            expand=True,
        )
    )


def display_risk_level_badge(scan_result: ScanResult) -> None:
    """Print a color-coded risk level badge on its own line.

    Badge styles per level:
      CRITICAL — bold white text on red background
      HIGH     — bold red text
      MODERATE — yellow text
      LOW      — dim yellow text

    Args:
        scan_result: The completed scan result whose risk level to badge.
    """
    level_name = scan_result.risk_level.value
    badge_style = _RISK_LEVEL_BADGE_STYLE.get(scan_result.risk_level, _STYLE_BOLD)
    _console.print(f"[{badge_style}] {level_name} [/{badge_style}]")


def display_severity_inline(scan_result: ScanResult) -> None:
    """Print a single-line severity breakdown with colored emoji icons.

    Args:
        scan_result: The completed scan result.
    """
    _console.print(_build_severity_inline_text(scan_result.severity_counts))


def _build_violation_summary_panel_markup(scan_result: ScanResult) -> str:
    """Build the Rich markup string for the violation scan summary panel.

    Args:
        scan_result: The completed scan result with findings.

    Returns:
        Newline-separated Rich markup showing status, risk, findings, files,
        time, audit log path, and action.
    """
    label_style = _PANEL_LABEL_STYLE
    risk_level_name = scan_result.risk_level.value
    badge_style = _RISK_LEVEL_BADGE_STYLE.get(scan_result.risk_level, _STYLE_BOLD)
    duration_str = _DURATION_FORMAT.format(scan_result.scan_duration)
    severity_inline = _build_severity_inline_text(scan_result.severity_counts)
    files_line = _VIOLATION_SUMMARY_FILES_FORMAT.format(
        with_findings=scan_result.files_with_findings,
        total=scan_result.files_scanned,
    )
    return "\n".join(
        [
            f"[{label_style}]{_VIOLATION_SUMMARY_STATUS_LABEL}:[/{label_style}]"
            f"  [{_VIOLATION_ALERT_BOX_STYLE}]{_VIOLATION_SUMMARY_STATUS_VALUE}"
            f"[/{_VIOLATION_ALERT_BOX_STYLE}]",
            f"[{label_style}]{_VIOLATION_SUMMARY_RISK_LABEL}:[/{label_style}]"
            f"  [{badge_style}]{risk_level_name}[/{badge_style}]",
            f"[{label_style}]{_VIOLATION_SUMMARY_FINDINGS_LABEL}:[/{label_style}]"
            f"  {len(scan_result.findings)}  ({severity_inline})",
            f"[{label_style}]{_VIOLATION_SUMMARY_FILES_LABEL}:[/{label_style}]  {files_line}",
            f"[{label_style}]{_VIOLATION_SUMMARY_TIME_LABEL}:[/{label_style}]  {duration_str}",
            f"[{label_style}]{_VIOLATION_SUMMARY_ACTION_LABEL}:[/{label_style}]"
            f"  [{_STYLE_BOLD_RED}]{_VIOLATION_SUMMARY_ACTION_VALUE}[/{_STYLE_BOLD_RED}]",
        ]
    )


def display_violation_summary_panel(scan_result: ScanResult) -> None:
    """Render the risk-level-colored summary panel for violation scans.

    Args:
        scan_result: The completed scan result with findings.
    """
    risk_style = _RISK_LEVEL_STYLE[scan_result.risk_level]
    _console.print(
        Panel(
            _build_violation_summary_panel_markup(scan_result),
            title=_VIOLATION_SUMMARY_PANEL_TITLE,
            border_style=risk_style,
        )
    )


def display_code_context_panel(finding: ScanFinding) -> None:
    """Render a bordered panel showing the code context and remediation hint for a finding.

    Args:
        finding: A single scan finding with code_context and remediation_hint populated.
    """
    severity_style = _SEVERITY_STYLE[finding.severity]
    title = _CODE_CONTEXT_PANEL_FORMAT.format(
        file=finding.file_path,
        line=finding.line_number,
        entity=finding.entity_type,
        severity=finding.severity.value,
    )
    content = "\n".join(
        [
            f"{_CODE_CONTEXT_ARROW} {finding.code_context}",
            "",
            f"[{severity_style}]{_CODE_CONTEXT_REMEDIATION_PREFIX}"
            f"{finding.remediation_hint}[/{severity_style}]",
        ]
    )
    _console.print(Panel(content, title=title, border_style=severity_style))


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


# ---------------------------------------------------------------------------
# Watch mode layout builders
# ---------------------------------------------------------------------------


def _build_watch_header_panel(watch_path: Path) -> Panel:
    """Build the persistent header panel shown at the top of the watch display.

    Args:
        watch_path: The directory currently being watched.

    Returns:
        Rich Panel with the watching path and Ctrl+C instruction.
    """
    watch_header_text = _WATCH_HEADER_FORMAT.format(path=str(watch_path))
    return Panel(
        watch_header_text,
        title=_WATCH_HEADER_PANEL_TITLE,
        subtitle=_WATCH_PHASE_ONE_NOTE,
        style=_STYLE_BOLD_CYAN,
    )


def _build_watch_event_table(events: Sequence[WatchEvent]) -> Table:
    """Build the rolling event log table from recent watch events.

    Args:
        events: Sequence of WatchEvent records (most recent last).

    Returns:
        Rich Table with time, changed file, and mini scan result columns.
    """
    table = Table(
        title=_WATCH_LOG_PANEL_TITLE,
        box=rich_box.SIMPLE,
        show_header=True,
        expand=True,
    )
    table.add_column(_WATCH_COL_TIME, style=_STYLE_DIM, no_wrap=True)
    table.add_column(_WATCH_COL_FILE)
    table.add_column(_WATCH_COL_RESULT, no_wrap=True)
    if not events:
        table.add_row(_WATCH_NO_EVENTS_TEXT, _WATCH_EMPTY_CELL, _WATCH_EMPTY_CELL)
        return table
    for event in events:
        result_cell_style = (
            _WATCH_RESULT_CLEAN_STYLE if event.is_clean else _WATCH_RESULT_VIOLATION_STYLE
        )
        result_markup = _RICH_STYLED_TEXT_FORMAT.format(
            style=result_cell_style, text=event.result_text
        )
        table.add_row(
            event.event_time.strftime(_WATCH_TIMESTAMP_FORMAT),
            event.file_path,
            result_markup,
        )
    return table


def build_watch_layout(watch_path: Path, events: Sequence[WatchEvent]) -> Layout:
    """Build the Rich Layout for the watch mode live display.

    Args:
        watch_path: The directory currently being watched.
        events: Recent watch events for the rolling event log.

    Returns:
        Layout with a persistent header panel and rolling event table.
    """
    layout = Layout()
    layout.split_column(
        Layout(name=_WATCH_HEADER_SECTION, size=_WATCH_HEADER_HEIGHT),
        Layout(name=_WATCH_BODY_SECTION),
    )
    layout[_WATCH_HEADER_SECTION].update(_build_watch_header_panel(watch_path))
    layout[_WATCH_BODY_SECTION].update(_build_watch_event_table(events))
    return layout


# ---------------------------------------------------------------------------
# Dashboard layout builders
# ---------------------------------------------------------------------------


def _build_dashboard_top_panel(last_scan: dict[str, Any] | None) -> Panel:
    """Build the top banner panel showing version and last scan status.

    Args:
        last_scan: Most recent scan row from the audit DB, or None if no scans.

    Returns:
        A Panel with compact banner and last-scan status line.
    """
    version_text = _DASHBOARD_VERSION_FORMAT.format(version=__version__)
    version_line = f"[{_BANNER_TAGLINE_STYLE}]{version_text}[/{_BANNER_TAGLINE_STYLE}]"
    if last_scan is None:
        status_line = f"[{_STYLE_DIM}]{_DASHBOARD_NO_HISTORY_TEXT}[/{_STYLE_DIM}]"
    elif last_scan.get("is_clean") == _DASHBOARD_BOOLEAN_CLEAN:
        label = f"[{_PANEL_LABEL_STYLE}]{_DASHBOARD_LAST_SCAN_LABEL}[/{_PANEL_LABEL_STYLE}]"
        value = f"[{_DASHBOARD_HISTORY_CLEAN_STYLE}]{_DASHBOARD_HISTORY_CLEAN_STATUS}"
        status_line = label + value + f"[/{_DASHBOARD_HISTORY_CLEAN_STYLE}]"
    else:
        label = f"[{_PANEL_LABEL_STYLE}]{_DASHBOARD_LAST_SCAN_LABEL}[/{_PANEL_LABEL_STYLE}]"
        value = f"[{_DASHBOARD_HISTORY_VIOLATION_STYLE}]{_DASHBOARD_HISTORY_VIOLATION_STATUS}"
        status_line = label + value + f"[/{_DASHBOARD_HISTORY_VIOLATION_STYLE}]"
    return Panel(
        f"{version_line}\n{status_line}",
        title=_DASHBOARD_STATUS_PANEL_TITLE,
        border_style=_PANEL_BORDER_STYLE,
    )


def _format_dashboard_history_row(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    is_clean = row.get("is_clean") == _DASHBOARD_BOOLEAN_CLEAN
    status_text = (
        _DASHBOARD_HISTORY_CLEAN_STATUS if is_clean else _DASHBOARD_HISTORY_VIOLATION_STATUS
    )
    row_style = _DASHBOARD_HISTORY_CLEAN_STYLE if is_clean else _DASHBOARD_HISTORY_VIOLATION_STYLE
    timestamp = str(row.get("timestamp", ""))[:_DASHBOARD_TIMESTAMP_DISPLAY_LENGTH]
    duration_str = _DURATION_FORMAT.format(float(row.get("scan_duration", 0.0)))
    return (
        timestamp,
        f"[{row_style}]{status_text}[/{row_style}]",
        str(row.get("files_scanned", 0)),
        str(row.get("findings_count", 0)),
        duration_str,
    )


def _build_dashboard_history_table(recent_scans: list[dict[str, Any]]) -> Table:
    """Build the recent scan history table for the dashboard left panel.

    Args:
        recent_scans: Scan rows from the audit DB, most recent first.

    Returns:
        A Rich Table with color-coded rows per scan outcome.
    """
    table = Table(
        title=_DASHBOARD_HISTORY_PANEL_TITLE,
        show_header=True,
        header_style=_PANEL_LABEL_STYLE,
        expand=True,
    )
    table.add_column(_DASHBOARD_COL_TIME, style=_STYLE_DIM)
    table.add_column(_DASHBOARD_COL_STATUS)
    table.add_column(_DASHBOARD_COL_FILES, justify=_JUSTIFY_RIGHT)
    table.add_column(_DASHBOARD_COL_FINDINGS, justify=_JUSTIFY_RIGHT)
    table.add_column(_DASHBOARD_COL_DURATION, justify=_JUSTIFY_RIGHT)
    if not recent_scans:
        table.add_row(_DASHBOARD_NO_HISTORY_TEXT, "", "", "", "")
        return table
    for row in recent_scans:
        table.add_row(*_format_dashboard_history_row(row))
    return table


def _build_dashboard_category_table(category_totals: dict[str, int]) -> Table:
    """Build the HIPAA category totals table for the dashboard right panel.

    Args:
        category_totals: Mapping of HIPAA category value to total finding count.

    Returns:
        A Rich Table listing categories sorted by count descending.
    """
    table = Table(
        title=_DASHBOARD_CATEGORY_PANEL_TITLE,
        show_header=True,
        header_style=_PANEL_LABEL_STYLE,
        expand=True,
    )
    table.add_column(_DASHBOARD_COL_CATEGORY, style=_PANEL_LABEL_STYLE)
    table.add_column(_DASHBOARD_COL_TOTAL, justify=_JUSTIFY_RIGHT)
    if not category_totals:
        table.add_row(_DASHBOARD_NO_CATEGORIES_TEXT, "")
        return table
    for category, count in sorted(
        category_totals.items(), key=operator.itemgetter(1), reverse=True
    ):
        table.add_row(category, str(count))
    return table


def _build_dashboard_watcher_panel() -> Panel:
    """Build the bottom watcher status panel.

    Returns:
        A Panel indicating the file watcher is not currently active.
    """
    return Panel(
        f"[{_STYLE_DIM}]{_DASHBOARD_WATCHER_INACTIVE_TEXT}[/{_STYLE_DIM}]",
        title=_DASHBOARD_WATCHER_PANEL_TITLE,
        border_style=_STYLE_DIM,
    )


def build_dashboard_layout(
    recent_scans: list[dict[str, Any]],
    category_totals: dict[str, int],
    last_scan: dict[str, Any] | None,
) -> Layout:
    """Assemble the full dashboard Layout from pre-fetched audit data.

    Layout structure:
      top    — compact banner + last scan status
      main
        left  — recent scan history table
        right — HIPAA category totals table
      bottom — file watcher status

    Args:
        recent_scans: Rows from query_recent_scans, most recent first.
        category_totals: Pre-aggregated HIPAA category counts across all scans.
        last_scan: Row from get_last_scan, or None if no scans recorded.

    Returns:
        A fully populated Rich Layout renderable.
    """
    layout = Layout()
    layout.split_column(
        Layout(name=_DASHBOARD_TOP_SECTION, size=_DASHBOARD_TOP_PANEL_HEIGHT),
        Layout(name=_DASHBOARD_MAIN_SECTION),
        Layout(name=_DASHBOARD_BOTTOM_SECTION, size=_DASHBOARD_BOTTOM_PANEL_HEIGHT),
    )
    layout[_DASHBOARD_MAIN_SECTION].split_row(
        Layout(name=_DASHBOARD_LEFT_SECTION),
        Layout(name=_DASHBOARD_RIGHT_SECTION),
    )
    layout[_DASHBOARD_TOP_SECTION].update(_build_dashboard_top_panel(last_scan))
    layout[_DASHBOARD_LEFT_SECTION].update(_build_dashboard_history_table(recent_scans))
    layout[_DASHBOARD_RIGHT_SECTION].update(_build_dashboard_category_table(category_totals))
    layout[_DASHBOARD_BOTTOM_SECTION].update(_build_dashboard_watcher_panel())
    return layout


# ---------------------------------------------------------------------------
# Baseline display functions (Phase 3B)
# ---------------------------------------------------------------------------

# Import here (not at top) to avoid a circular import: output.py is imported by
# cli.py before baseline.py exists during the Phase 1 bootstrap.  baseline.py
# imports from models.py and constants.py only — no cycle in the dependency graph.
# TYPE_CHECKING guard is not used because the functions below need the types at
# runtime, not just for annotations.
from phi_scan.baseline import BaselineDiff, BaselineSummary  # noqa: E402

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

_BASELINE_NEW_SECTION_HEADER: str = "[bold red]NEW — not in baseline ({count})[/bold red]"
_BASELINE_RESOLVED_SECTION_HEADER: str = "[green]RESOLVED — no longer detected ({count})[/green]"
_BASELINE_PERSISTING_SECTION_HEADER: str = (
    "[dim]PERSISTING — still present, still baselined ({count})[/dim]"
)
_BASELINE_DIFF_FINDING_ROW: str = "  {file_path}:{line}  {entity_type}  {severity}"
_BASELINE_DIFF_ENTRY_ROW: str = "  {file_path}:{line}  {entity_type}  {severity}"
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


def _entry_label(count: int) -> str:
    """Return 'entry' for exactly 1, 'entries' otherwise."""
    return _BASELINE_ENTRY_LABEL if count == _ENTRY_PLURAL_THRESHOLD else _BASELINE_ENTRIES_LABEL


def display_baseline_summary(summary: BaselineSummary) -> None:
    """Render a Rich summary panel for a baseline snapshot.

    Displays total/active/expired entry counts, oldest entry age, and
    per-severity breakdown. Called by ``phi-scan baseline show``.

    Args:
        summary: Computed statistics for the current baseline snapshot.
    """
    lines: list[str] = [
        f"  File:            {summary.baseline_path}",
        f"  Created:         {summary.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Scanner version: {summary.scanner_version}",
        "",
        f"  Total entries:   {summary.total_entries}",
        f"  Active:          [green]{summary.active_entries}[/green]",
        f"  Expired:         [dim]{summary.expired_entries}[/dim]",
        f"  Oldest entry:    {summary.oldest_entry_age_days} day(s) ago",
    ]
    if summary.severity_counts:
        lines.append("")
        lines.append("  Severity breakdown:")
        for severity, count in sorted(
            summary.severity_counts.items(), key=lambda item: item[0].value
        ):
            lines.append(f"    {severity.value.upper():<8} {count}")
    _console.print(
        Panel(
            "\n".join(lines),
            title=_BASELINE_SUMMARY_TITLE,
            border_style=_BASELINE_SUMMARY_BORDER_STYLE,
        )
    )


def display_baseline_diff(diff: BaselineDiff) -> None:
    """Render a Rich diff panel comparing baseline against the current scan.

    Shows new, resolved, and persisting finding counts with per-finding details
    for new and resolved sets. Called by ``phi-scan baseline diff``.

    Args:
        diff: Computed diff between the baseline and the current scan.
    """
    lines: list[str] = [
        _BASELINE_NEW_SECTION_HEADER.format(count=len(diff.new_findings)),
    ]
    for finding in diff.new_findings:
        lines.append(
            _BASELINE_DIFF_FINDING_ROW.format(
                file_path=finding.file_path,
                line=finding.line_number,
                entity_type=finding.entity_type,
                severity=finding.severity.value,
            )
        )
    lines += [
        "",
        _BASELINE_RESOLVED_SECTION_HEADER.format(count=len(diff.resolved_entries)),
    ]
    for entry in diff.resolved_entries:
        lines.append(
            _BASELINE_DIFF_ENTRY_ROW.format(
                file_path=entry.file_path,
                line=entry.line_number,
                entity_type=entry.entity_type,
                severity=entry.severity.value,
            )
        )
    lines += [
        "",
        _BASELINE_PERSISTING_SECTION_HEADER.format(count=len(diff.persisting_findings)),
    ]
    _console.print(Panel("\n".join(lines), title=_BASELINE_DIFF_TITLE))


def display_baseline_drift_warning(old_count: int, new_count: int, drift_percent: int) -> None:
    """Render a warning panel when a baseline update significantly increases entry count.

    Called by ``phi-scan baseline update`` when drift exceeds
    BASELINE_DRIFT_WARNING_PERCENT.

    Args:
        old_count: Entry count in the previous baseline.
        new_count: Entry count in the updated baseline.
        drift_percent: Percent increase, as returned by detect_baseline_drift.
    """
    _console.print(
        Panel(
            _BASELINE_DRIFT_MESSAGE.format(percent=drift_percent, old=old_count, new=new_count),
            title=_BASELINE_DRIFT_TITLE,
            border_style=_BASELINE_DRIFT_BORDER_STYLE,
        )
    )


def display_baseline_scan_notice(new_count: int, baselined_count: int) -> None:
    """Render a one-line panel summarising baseline-filtered scan results.

    Shows how many findings are new vs. suppressed by the baseline. Called
    after ``scan --baseline`` completes to clarify the exit-code decision.

    Args:
        new_count: Findings not covered by any active baseline entry.
        baselined_count: Findings suppressed by an active baseline entry.
    """
    if new_count == 0:
        message = _BASELINE_SCAN_CLEAN_MESSAGE.format(baselined_count=baselined_count)
    else:
        message = _BASELINE_SCAN_NOTICE_MESSAGE.format(
            new_count=new_count, baselined_count=baselined_count
        )
    _console.print(
        Panel(message, title=_BASELINE_NOTICE_TITLE, border_style=_BASELINE_NOTICE_BORDER_STYLE)
    )
