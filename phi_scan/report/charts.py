"""Chart builders — matplotlib figures consumed by HTML and PDF report layers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from operator import itemgetter
from typing import TYPE_CHECKING

from phi_scan.constants import SEVERITY_RANK, SeverityLevel
from phi_scan.report._shared import (
    _CHART_HEIGHT_CATEGORY_INCHES,
    _CHART_HEIGHT_FILES_INCHES,
    _CHART_HEIGHT_PIE_INCHES,
    _CHART_HEIGHT_TREND_INCHES,
    _CHART_WIDTH_INCHES,
    _HEX_CRITICAL_RED,
    _HEX_HIGH_ORANGE,
    _HEX_LOW_GREEN,
    _MatplotlibFigure,
)

if TYPE_CHECKING:
    from phi_scan.models import ScanResult

# Top-N files shown in the files-with-most-findings chart
_TOP_FILES_COUNT: int = 10

# Chart file-label truncation threshold (chars before "..." prefix is added)
_MAX_LABEL_CHARS: int = 40

# Chart colours (matplotlib format: "#RRGGBB"). Shared colours are derived from
# the canonical hex constants in _shared so PDF and chart renderers stay in sync.
_CHART_COLOUR_ACTIVE: str = f"#{_HEX_CRITICAL_RED}"  # category bar with findings present
_CHART_COLOUR_ZERO_FINDINGS_BAR: str = "#BDC3C7"  # category bar with zero findings
_CHART_COLOUR_UNKNOWN_SEVERITY: str = "#95A5A6"  # severity donut fallback for unrecognised levels
_CHART_COLOUR_BLUE: str = "#2980B9"  # trend line and top-files bars
_CHART_COLOUR_SEVERITY_HIGH: str = f"#{_HEX_CRITICAL_RED}"
_CHART_COLOUR_SEVERITY_MEDIUM: str = f"#{_HEX_HIGH_ORANGE}"
_CHART_COLOUR_SEVERITY_LOW: str = f"#{_HEX_LOW_GREEN}"
_CHART_COLOUR_SEVERITY_INFO: str = "#3498DB"

# Trend-line chart style constants
_CHART_LINE_WIDTH: int = 2
_CHART_FILL_ALPHA: float = 0.15
_CHART_MARKER_STYLE: str = "o"

# Chart annotation and label style
_CHART_BAR_LABEL_PADDING: int = 3
_CHART_BAR_LABEL_FONT_SIZE: int = 8
_CHART_NO_DATA_FONT_SIZE: int = 14
_CHART_NO_HISTORY_FONT_SIZE: int = 12
_CHART_PIE_START_ANGLE: int = 90
_CHART_GRID_ALPHA: float = 0.5
_CHART_DONUT_WIDTH: float = 0.5

# Chart placeholder text for empty-data states
_CHART_NO_FINDINGS_LABEL: str = "(no findings)"
_CHART_NO_FINDINGS_TEXT: str = "No findings"
_CHART_NO_HISTORY_TEXT: str = "No audit history available"

# Audit row column keys consumed by the trend chart sanitization boundary.
# Only these two columns are ever read from audit rows.
# The audit schema stores SHA-256 digests for all path-based identifiers
# and never persists raw PHI values, so both columns are guaranteed PHI-free:
#   timestamp      — ISO 8601 datetime string; no PHI
#   findings_count — INTEGER aggregate count; no PHI
_AUDIT_ROW_KEY_TIMESTAMP: str = "timestamp"
_AUDIT_ROW_KEY_FINDINGS_COUNT: str = "findings_count"
# Frozenset of the only audit row keys permitted to enter the trend chart
# sanitization boundary. Used at runtime to restrict each row dict to exactly
# these two keys before any value is extracted — no other column can reach
# chart rendering regardless of schema changes or unexpected extra fields.
_AUDIT_ROW_ALLOWED_KEYS: frozenset[str] = frozenset(
    {_AUDIT_ROW_KEY_TIMESTAMP, _AUDIT_ROW_KEY_FINDINGS_COUNT}
)


@dataclass(frozen=True)
class _TrendDataPoint:
    """One sanitized (scan_date, findings_count) pair extracted from a single audit row."""

    scan_date: datetime
    findings_count: int


def _truncate_chart_label(label: str) -> str:
    """Shorten a file path label to _MAX_LABEL_CHARS for chart readability."""
    if len(label) <= _MAX_LABEL_CHARS:
        return label
    return "..." + label[-(_MAX_LABEL_CHARS - 1) :]


@dataclass(frozen=True)
class _HorizontalBarChartSpec:
    """Specification for rendering a horizontal bar chart figure."""

    labels: tuple[str, ...]
    values: tuple[int, ...]
    colours: tuple[str, ...]
    title: str
    xlabel: str
    chart_height_inches: float


def _render_horizontal_bar_figure(spec: _HorizontalBarChartSpec) -> _MatplotlibFigure:
    """Build and return a horizontal bar chart Figure from a spec."""
    import matplotlib.pyplot as plt

    figure, chart_axes = plt.subplots(figsize=(_CHART_WIDTH_INCHES, spec.chart_height_inches))
    bars = chart_axes.barh(spec.labels, spec.values, color=spec.colours)
    chart_axes.bar_label(
        bars, padding=_CHART_BAR_LABEL_PADDING, fontsize=_CHART_BAR_LABEL_FONT_SIZE
    )
    chart_axes.set_xlabel(spec.xlabel)
    chart_axes.set_title(spec.title)
    chart_axes.invert_yaxis()
    figure.tight_layout()
    plt.close(figure)
    return figure  # type: ignore[return-value]


def _prepare_category_chart_data(
    scan_result: ScanResult,
) -> tuple[list[str], list[int], list[str]]:
    """Return (labels, values, colours) for the HIPAA category bar chart."""
    category_counts = {
        cat.value.replace("_", " ").title(): count
        for cat, count in scan_result.category_counts.items()
        if count > 0
    }
    if not category_counts:
        return [_CHART_NO_FINDINGS_LABEL], [0], [_CHART_COLOUR_ZERO_FINDINGS_BAR]
    sorted_items = sorted(category_counts.items(), key=itemgetter(1), reverse=True)
    labels = [label for label, _ in sorted_items]
    finding_counts = [finding_count for _, finding_count in sorted_items]
    colours = [
        _CHART_COLOUR_ACTIVE if finding_count > 0 else _CHART_COLOUR_ZERO_FINDINGS_BAR
        for finding_count in finding_counts
    ]
    return labels, finding_counts, colours


def _build_category_chart(scan_result: ScanResult) -> _MatplotlibFigure:
    """Horizontal bar chart — findings count by HIPAA category, sorted descending."""
    labels, finding_counts, colours = _prepare_category_chart_data(scan_result)
    return _render_horizontal_bar_figure(
        _HorizontalBarChartSpec(
            labels=tuple(labels),
            values=tuple(finding_counts),
            colours=tuple(colours),
            title="Findings by HIPAA Category",
            xlabel="Findings Count",
            chart_height_inches=_CHART_HEIGHT_CATEGORY_INCHES,
        )
    )


def _prepare_severity_chart_data(
    scan_result: ScanResult,
) -> tuple[list[str], list[int], list[str]] | None:
    """Return (labels, values, colours) for the severity donut, or None if no findings."""
    severity_data = {
        level: count for level, count in scan_result.severity_counts.items() if count > 0
    }
    if not severity_data:
        return None
    ordered_levels = sorted(
        severity_data.keys(), key=lambda severity_level: SEVERITY_RANK[severity_level], reverse=True
    )
    level_colours: dict[SeverityLevel, str] = {
        SeverityLevel.HIGH: _CHART_COLOUR_SEVERITY_HIGH,
        SeverityLevel.MEDIUM: _CHART_COLOUR_SEVERITY_MEDIUM,
        SeverityLevel.LOW: _CHART_COLOUR_SEVERITY_LOW,
        SeverityLevel.INFO: _CHART_COLOUR_SEVERITY_INFO,
    }
    labels = [f"{level.value.title()} ({severity_data[level]})" for level in ordered_levels]
    severity_finding_counts = [severity_data[level] for level in ordered_levels]
    colours = [level_colours.get(level, _CHART_COLOUR_UNKNOWN_SEVERITY) for level in ordered_levels]
    return labels, severity_finding_counts, colours


def _build_severity_chart(scan_result: ScanResult) -> _MatplotlibFigure:
    """Donut chart — severity distribution."""
    import matplotlib.pyplot as plt

    figure, chart_axes = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_PIE_INCHES))
    chart_data = _prepare_severity_chart_data(scan_result)
    if chart_data is None:
        chart_axes.text(
            0.5,
            0.5,
            _CHART_NO_FINDINGS_TEXT,
            ha="center",
            va="center",
            fontsize=_CHART_NO_DATA_FONT_SIZE,
        )
        chart_axes.axis("off")
        figure.tight_layout()
        plt.close(figure)
        return figure  # type: ignore[return-value]
    labels, severity_finding_counts, colours = chart_data
    chart_axes.pie(
        severity_finding_counts,
        labels=labels,
        colors=colours,
        wedgeprops={"width": _CHART_DONUT_WIDTH},
        startangle=_CHART_PIE_START_ANGLE,
        autopct="%1.0f%%",
    )
    chart_axes.set_title("Severity Distribution")
    figure.tight_layout()
    plt.close(figure)
    return figure  # type: ignore[return-value]


def _prepare_top_files_chart_data(scan_result: ScanResult) -> tuple[list[str], list[int]]:
    """Return (display_labels, counts) for the top-N files bar chart."""
    file_counts: Counter[str] = Counter(str(finding.file_path) for finding in scan_result.findings)
    top_files = file_counts.most_common(_TOP_FILES_COUNT)
    labels = [_truncate_chart_label(file_path) for file_path, _ in top_files]
    counts = [count for _, count in top_files]
    return labels, counts


def _build_top_files_chart(scan_result: ScanResult) -> _MatplotlibFigure:
    """Horizontal bar chart — top N files with most findings."""
    import matplotlib.pyplot as plt

    labels, counts = _prepare_top_files_chart_data(scan_result)
    figure, chart_axes = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_FILES_INCHES))
    if not labels:
        chart_axes.text(
            0.5,
            0.5,
            _CHART_NO_FINDINGS_TEXT,
            ha="center",
            va="center",
            fontsize=_CHART_NO_DATA_FONT_SIZE,
        )
        chart_axes.axis("off")
        figure.tight_layout()
        plt.close(figure)
        return figure  # type: ignore[return-value]
    bars = chart_axes.barh(labels, counts, color=_CHART_COLOUR_BLUE)
    chart_axes.bar_label(
        bars, padding=_CHART_BAR_LABEL_PADDING, fontsize=_CHART_BAR_LABEL_FONT_SIZE
    )
    chart_axes.set_xlabel("Findings Count")
    chart_axes.set_title(f"Top {len(labels)} Files by Finding Count")
    chart_axes.invert_yaxis()
    figure.tight_layout()
    plt.close(figure)
    return figure  # type: ignore[return-value]


def _extract_trend_data_points(
    audit_rows: list[dict[str, object]],
) -> tuple[_TrendDataPoint, ...]:
    """Sanitization boundary: extract trend chart data from audit rows.

    Each raw audit row is first restricted to _AUDIT_ROW_ALLOWED_KEYS via a
    dict comprehension — this is the runtime enforcement that no other audit
    column (repository_hash, branch_hash, findings_json, etc.) can reach
    downstream chart rendering regardless of schema changes or unexpected fields.
    Only the two PHI-free columns are then extracted from the restricted dict:
    timestamp (ISO 8601 datetime string) and findings_count (integer aggregate).

    Rows with an unparseable timestamp are skipped so one malformed row does not
    suppress the entire trend chart.
    """
    sorted_rows = sorted(
        audit_rows,
        key=lambda row: str(row.get(_AUDIT_ROW_KEY_TIMESTAMP, "")),
    )
    points: list[_TrendDataPoint] = []
    for row in sorted_rows:
        safe_row: dict[str, object] = {
            key: row[key] for key in _AUDIT_ROW_ALLOWED_KEYS if key in row
        }
        raw_timestamp = safe_row.get(_AUDIT_ROW_KEY_TIMESTAMP, "")
        try:
            scan_date = datetime.fromisoformat(str(raw_timestamp))
        except (ValueError, TypeError):
            continue
        raw_count = safe_row.get(_AUDIT_ROW_KEY_FINDINGS_COUNT, 0)
        findings_count = int(raw_count) if isinstance(raw_count, (int, float, str)) else 0
        points.append(_TrendDataPoint(scan_date=scan_date, findings_count=findings_count))
    return tuple(points)


def _build_trend_chart(trend_points: tuple[_TrendDataPoint, ...]) -> _MatplotlibFigure:
    """Line chart — findings over time from audit log history.

    Accepts only pre-sanitized _TrendDataPoint values so raw audit row dicts
    never enter chart rendering. Callers must pass the output of
    _extract_trend_data_points rather than raw audit_rows.
    """
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    figure, chart_axes = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_TREND_INCHES))

    if not trend_points:
        chart_axes.text(
            0.5,
            0.5,
            _CHART_NO_HISTORY_TEXT,
            ha="center",
            va="center",
            fontsize=_CHART_NO_HISTORY_FONT_SIZE,
        )
        chart_axes.axis("off")
        figure.tight_layout()
        plt.close(figure)
        return figure  # type: ignore[return-value]

    date_nums = mdates.date2num([p.scan_date for p in trend_points])  # type: ignore[no-untyped-call]
    counts = [p.findings_count for p in trend_points]
    chart_axes.plot(
        date_nums,
        counts,
        marker=_CHART_MARKER_STYLE,
        linewidth=_CHART_LINE_WIDTH,
        color=_CHART_COLOUR_BLUE,
    )
    chart_axes.fill_between(date_nums, counts, alpha=_CHART_FILL_ALPHA, color=_CHART_COLOUR_BLUE)
    chart_axes.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))  # type: ignore[no-untyped-call]
    chart_axes.xaxis.set_major_locator(mdates.AutoDateLocator())  # type: ignore[no-untyped-call]
    figure.autofmt_xdate()
    chart_axes.set_ylabel("Findings")
    chart_axes.set_title("Findings Trend (Audit Log History)")
    chart_axes.grid(axis="y", linestyle="--", alpha=_CHART_GRID_ALPHA)
    figure.tight_layout()
    plt.close(figure)
    return figure  # type: ignore[return-value]
