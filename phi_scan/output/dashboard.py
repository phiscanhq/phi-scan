"""Dashboard layout builders for the phi-scan live dashboard view."""

from __future__ import annotations

import operator
import sys
from typing import Any, Literal

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

from phi_scan import __version__

# ---------------------------------------------------------------------------
# Style constants (local to this module — no shared import needed)
# ---------------------------------------------------------------------------

_STYLE_BOLD_GREEN: str = "bold green"
_STYLE_BOLD_RED: str = "bold red"
_STYLE_DIM: str = "dim"
_STYLE_BOLD: str = "bold"
_STYLE_CYAN: str = "cyan"
_PANEL_LABEL_STYLE: str = "bold cyan"
_PANEL_BORDER_STYLE: str = "cyan"
_BANNER_TAGLINE_STYLE: str = "dim"

# ---------------------------------------------------------------------------
# Layout direction
# ---------------------------------------------------------------------------

_JUSTIFY_RIGHT: Literal["right"] = "right"

# ---------------------------------------------------------------------------
# Duration formatting
# ---------------------------------------------------------------------------

_DURATION_FORMAT: str = "{:.2f}s"

# ---------------------------------------------------------------------------
# Dashboard display constants
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
_DASHBOARD_VERSION_FORMAT: str = "v{version}  —  PHI/PII Scanner for HIPAA-Aligned Environments"
_DASHBOARD_LAST_SCAN_LABEL: str = "Last scan: "
_DASHBOARD_NO_HISTORY_TEXT: str = "No scan history found."
_DASHBOARD_NO_CATEGORIES_TEXT: str = "No findings recorded yet."
_DASHBOARD_WATCHER_INACTIVE_TEXT: str = "File watcher: Not active  (run phi-scan watch <path>)"
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

# Unicode detection for icon fallback — same logic as console.py.
_DASHBOARD_UNICODE_SUPPORTED: bool = (
    (getattr(sys.stdout, "encoding", None) or "").upper().startswith("UTF")
)
_DASHBOARD_ICON_CLEAN: str = "✅" if _DASHBOARD_UNICODE_SUPPORTED else "[OK]"
_DASHBOARD_ICON_VIOLATION: str = "⚠" if _DASHBOARD_UNICODE_SUPPORTED else "[!]"

# Status label strings used in both the panel and as test-accessible constants.
_DASHBOARD_HISTORY_CLEAN_STATUS: str = f"{_DASHBOARD_ICON_CLEAN} CLEAN"
_DASHBOARD_HISTORY_VIOLATION_STATUS: str = f"{_DASHBOARD_ICON_VIOLATION}  VIOLATION"


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
