"""Enterprise PDF and HTML report generation for PhiScan (Phase 4A).

Produces two report formats from a ScanResult:

  - HTML: self-contained single file with embedded base64 charts, responsive
    layout, colour-coded severity badges, and collapsible code context.
  - PDF: professional, printable, letterhead-style document with cover page,
    executive summary, visual charts, paginated findings table, and remediation
    guidance section.

Both formats are generated without any network calls.  All chart images are
rendered by matplotlib into in-memory PNG buffers and embedded directly in the
output — no temporary files are written to disk.

Usage::

    from phi_scan.report import generate_html_report, generate_pdf_report

    html_bytes = generate_html_report(scan_result, scan_target=Path("./src"))
    pdf_bytes  = generate_pdf_report(scan_result, scan_target=Path("./src"))
"""

from __future__ import annotations

import base64
import io
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from phi_scan import __version__
from phi_scan.constants import (
    HIPAA_REMEDIATION_GUIDANCE,
    SEVERITY_RANK,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.logging_config import get_logger

if TYPE_CHECKING:
    from phi_scan.models import ScanResult

__all__ = [
    "generate_html_report",
    "generate_pdf_report",
]

_logger = get_logger("report")

# ---------------------------------------------------------------------------
# Layout and colour constants
# ---------------------------------------------------------------------------

# Risk-level colours (hex, no leading #)
_COLOUR_CRITICAL: str = "C0392B"
_COLOUR_HIGH: str = "E67E22"
_COLOUR_MODERATE: str = "F1C40F"
_COLOUR_LOW: str = "27AE60"
_COLOUR_CLEAN: str = "2ECC71"

# Severity row colours for PDF table fill (light tint variants)
_COLOUR_HIGH_TINT: str = "FADBD8"
_COLOUR_MEDIUM_TINT: str = "FDEBD0"
_COLOUR_LOW_TINT: str = "D5F5E3"
_COLOUR_INFO_TINT: str = "EBF5FB"
_COLOUR_WHITE: str = "FFFFFF"

# PDF page dimensions (A4 portrait, mm)
_PAGE_WIDTH_MM: float = 210.0
_PAGE_HEIGHT_MM: float = 297.0
_MARGIN_MM: float = 15.0
_CONTENT_WIDTH_MM: float = _PAGE_WIDTH_MM - 2 * _MARGIN_MM

# PDF font sizes
_FONT_TITLE: int = 22
_FONT_HEADING: int = 14
_FONT_SUBHEADING: int = 11
_FONT_BODY: int = 9
_FONT_SMALL: int = 8
_FONT_TABLE_HEADER: int = 8
_FONT_TABLE_BODY: int = 7

# Chart dimensions
_CHART_WIDTH_INCHES: float = 7.0
_CHART_HEIGHT_CATEGORY_INCHES: float = 4.0
_CHART_HEIGHT_PIE_INCHES: float = 3.5
_CHART_HEIGHT_FILES_INCHES: float = 3.5
_CHART_HEIGHT_TREND_INCHES: float = 3.0
_CHART_DPI: int = 120

# Remediation checklist items at end of every report
_GENERAL_REMEDIATION_CHECKLIST: tuple[str, ...] = (
    "Run `phi-scan fix --dry-run <path>` to preview synthetic replacements for all findings.",
    "Add `phi-scan scan --diff HEAD` as a required pre-commit hook via `phi-scan install-hook`.",
    "Run `phi-scan baseline create` after resolving all findings to establish a clean baseline.",
    "Enable `phi-scan scan --baseline` in CI to block only new regressions going forward.",
    "Rotate any credentials or tokens that were exposed — treat them as compromised.",
    "Review the HIPAA Safe Harbor checklist in `phi-scan explain hipaa` for each category found.",
    "Document remediation actions taken in your organisation's HIPAA risk management plan.",
)

# Maximum code-context characters shown per finding in reports
_MAX_CONTEXT_CHARS: int = 200

# Top-N files shown in the files-with-most-findings chart
_TOP_FILES_COUNT: int = 10

# Chart file-label truncation threshold (chars before "..." prefix is added)
_MAX_LABEL_CHARS: int = 40

# Chart colours — matplotlib requires the leading "#"; fpdf2 constants above do not
_CHART_COLOUR_ACTIVE: str = "#C0392B"  # bar/value with findings
_CHART_COLOUR_INACTIVE: str = "#BDC3C7"  # bar with zero findings
_CHART_COLOUR_NEUTRAL: str = "#95A5A6"  # severity fallback / unknown
_CHART_COLOUR_BLUE: str = "#2980B9"  # trend line and top-files bars
_CHART_COLOUR_SEVERITY_HIGH: str = "#C0392B"
_CHART_COLOUR_SEVERITY_MEDIUM: str = "#E67E22"
_CHART_COLOUR_SEVERITY_LOW: str = "#27AE60"
_CHART_COLOUR_SEVERITY_INFO: str = "#3498DB"

# Trend-line chart style constants
_CHART_LINE_WIDTH: int = 2
_CHART_FILL_ALPHA: float = 0.15
_CHART_MARKER_STYLE: str = "o"

# PDF findings table column widths and headers
_PDF_COL_WIDTHS: tuple[float, ...] = (8.0, 52.0, 10.0, 28.0, 26.0, 16.0, 14.0, 16.0)
_PDF_COL_HEADERS: tuple[str, ...] = (
    "#",
    "File Path",
    "Line",
    "Entity Type",
    "HIPAA Category",
    "Severity",
    "Conf.",
    "Layer",
)
_PDF_ROW_HEIGHT: float = 5.5
_PDF_HEADER_HEIGHT: float = 7.0

# Page-break threshold for findings table (stop before footer area)
_PDF_PAGE_BREAK_Y_MM: float = _PAGE_HEIGHT_MM - 25.0


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------


def _hex_to_rgb(hex_colour: str) -> tuple[int, int, int]:
    """Convert a 6-char hex colour string to an (R, G, B) int tuple."""
    return int(hex_colour[0:2], 16), int(hex_colour[2:4], 16), int(hex_colour[4:6], 16)


# Map of Unicode characters that Helvetica (latin-1) cannot encode → ASCII fallbacks.
# fpdf2 raises FPDFUnicodeEncodingException for any character outside latin-1 when
# using the built-in core fonts.  We replace the most common typographic characters
# before passing text to any fpdf cell/multi_cell call.
_PDF_CHAR_REPLACEMENTS: dict[str, str] = {
    "\u2014": "-",  # em dash
    "\u2013": "-",  # en dash
    "\u2026": "...",  # ellipsis
    "\u2022": "-",  # bullet
    "\u00a7": "SS",  # section sign (§)
    "\u00a9": "(c)",  # copyright
    "\u00ae": "(R)",  # registered
    "\u2019": "'",  # right single quote
    "\u2018": "'",  # left single quote
    "\u201c": '"',  # left double quote
    "\u201d": '"',  # right double quote
}


def _pdf_safe(text: str) -> str:
    """Replace non-latin-1 characters with ASCII fallbacks for fpdf2 core fonts."""
    for char, replacement in _PDF_CHAR_REPLACEMENTS.items():
        text = text.replace(char, replacement)
    # Final fallback: drop any remaining non-latin-1 characters
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _risk_colour(risk_level: RiskLevel) -> str:
    """Return the hex colour string for a given RiskLevel."""
    colour_map: dict[RiskLevel, str] = {
        RiskLevel.CRITICAL: _COLOUR_CRITICAL,
        RiskLevel.HIGH: _COLOUR_HIGH,
        RiskLevel.MODERATE: _COLOUR_MODERATE,
        RiskLevel.LOW: _COLOUR_LOW,
        RiskLevel.CLEAN: _COLOUR_CLEAN,
    }
    return colour_map.get(risk_level, _COLOUR_LOW)


def _severity_row_colour(severity: SeverityLevel) -> str:
    """Return the light-tint hex colour for a severity-level table row."""
    tint_map: dict[SeverityLevel, str] = {
        SeverityLevel.HIGH: _COLOUR_HIGH_TINT,
        SeverityLevel.MEDIUM: _COLOUR_MEDIUM_TINT,
        SeverityLevel.LOW: _COLOUR_LOW_TINT,
        SeverityLevel.INFO: _COLOUR_INFO_TINT,
    }
    return tint_map.get(severity, _COLOUR_WHITE)


# ---------------------------------------------------------------------------
# Chart generation — all charts return a matplotlib Figure
# ---------------------------------------------------------------------------


def _truncate_file_label(label: str) -> str:
    """Shorten a file path label to _MAX_LABEL_CHARS for chart readability.

    Args:
        label: Raw file path string.

    Returns:
        Original label when short enough; otherwise a "..."-prefixed tail.
    """
    if len(label) <= _MAX_LABEL_CHARS:
        return label
    return "..." + label[-(_MAX_LABEL_CHARS - 1) :]


def _render_chart_to_base64(figure: object) -> str:
    """Render a matplotlib Figure to a base64-encoded PNG string."""
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", bbox_inches="tight", dpi=_CHART_DPI)  # type: ignore[attr-defined]
    buffer.seek(0)
    encoded = base64.b64encode(buffer.read()).decode("ascii")
    buffer.close()
    return encoded


def _render_chart_to_bytes(figure: object) -> bytes:
    """Render a matplotlib Figure to raw PNG bytes."""
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", bbox_inches="tight", dpi=_CHART_DPI)  # type: ignore[attr-defined]
    buffer.seek(0)
    png_bytes = buffer.read()
    buffer.close()
    return png_bytes


def _build_category_chart(scan_result: ScanResult) -> object:
    """Horizontal bar chart — findings count by HIPAA category, sorted descending."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    category_counts = {
        cat.value.replace("_", " ").title(): count
        for cat, count in scan_result.category_counts.items()
        if count > 0
    }
    if not category_counts:
        category_counts = {"(no findings)": 0}

    sorted_items = sorted(category_counts.items(), key=lambda pair: pair[1], reverse=True)
    labels = [category_label for category_label, _ in sorted_items]
    values = [category_value for _, category_value in sorted_items]

    fig, axis = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_CATEGORY_INCHES))
    colours = [_CHART_COLOUR_ACTIVE if v > 0 else _CHART_COLOUR_INACTIVE for v in values]
    bars = axis.barh(labels, values, color=colours)
    axis.bar_label(bars, padding=3, fontsize=8)
    axis.set_xlabel("Findings Count")
    axis.set_title("Findings by HIPAA Category")
    axis.invert_yaxis()
    fig.tight_layout()
    plt.close(fig)
    return fig


def _build_severity_chart(scan_result: ScanResult) -> object:
    """Donut chart — severity distribution."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    severity_data = {
        level: count for level, count in scan_result.severity_counts.items() if count > 0
    }

    fig, axis = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_PIE_INCHES))

    if not severity_data:
        axis.text(0.5, 0.5, "No findings", ha="center", va="center", fontsize=14)
        axis.axis("off")
        fig.tight_layout()
        plt.close(fig)
        return fig

    ordered_levels = sorted(severity_data.keys(), key=lambda lvl: SEVERITY_RANK[lvl], reverse=True)
    pie_labels = [f"{lvl.value.title()} ({severity_data[lvl]})" for lvl in ordered_levels]
    pie_values = [severity_data[lvl] for lvl in ordered_levels]
    level_colours: dict[SeverityLevel, str] = {
        SeverityLevel.HIGH: _CHART_COLOUR_SEVERITY_HIGH,
        SeverityLevel.MEDIUM: _CHART_COLOUR_SEVERITY_MEDIUM,
        SeverityLevel.LOW: _CHART_COLOUR_SEVERITY_LOW,
        SeverityLevel.INFO: _CHART_COLOUR_SEVERITY_INFO,
    }
    colours = [level_colours.get(lvl, _CHART_COLOUR_NEUTRAL) for lvl in ordered_levels]

    axis.pie(
        pie_values,
        labels=pie_labels,
        colors=colours,
        wedgeprops={"width": 0.5},
        startangle=90,
        autopct="%1.0f%%",
    )
    axis.set_title("Severity Distribution")
    fig.tight_layout()
    plt.close(fig)
    return fig


def _build_top_files_chart(scan_result: ScanResult) -> object:
    """Horizontal bar chart — top N files with most findings."""
    import matplotlib

    matplotlib.use("Agg")
    from collections import Counter

    import matplotlib.pyplot as plt

    fig, axis = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_FILES_INCHES))

    file_counts: Counter[str] = Counter(str(finding.file_path) for finding in scan_result.findings)
    top_files = file_counts.most_common(_TOP_FILES_COUNT)

    if not top_files:
        axis.text(0.5, 0.5, "No findings", ha="center", va="center", fontsize=14)
        axis.axis("off")
        fig.tight_layout()
        plt.close(fig)
        return fig

    display_labels = [_truncate_file_label(fp) for fp, _ in top_files]
    counts = [count for _, count in top_files]

    bars = axis.barh(display_labels, counts, color=_CHART_COLOUR_BLUE)
    axis.bar_label(bars, padding=3, fontsize=8)
    axis.set_xlabel("Findings Count")
    axis.set_title(f"Top {len(top_files)} Files by Finding Count")
    axis.invert_yaxis()
    fig.tight_layout()
    plt.close(fig)
    return fig


def _parse_audit_dates_and_counts(
    audit_rows: list[dict[str, object]],
) -> tuple[list[datetime], list[int]]:
    """Extract (date, findings_count) pairs from audit rows, skipping unparseable rows.

    Args:
        audit_rows: Raw rows from query_recent_scans.

    Returns:
        Tuple of (dates list, counts list), both in chronological order.
    """
    dates: list[datetime] = []
    counts: list[int] = []
    for row in sorted(audit_rows, key=lambda r: str(r.get("scanned_at", ""))):
        raw_timestamp = row.get("scanned_at", "")
        try:
            parsed_date = datetime.fromisoformat(str(raw_timestamp))
        except (ValueError, TypeError):
            continue
        dates.append(parsed_date)
        raw_count = row.get("findings_count", 0)
        counts.append(int(raw_count) if isinstance(raw_count, (int, float, str)) else 0)
    return dates, counts


def _build_trend_chart(audit_rows: list[dict[str, object]]) -> object:
    """Line chart — findings over time from audit log history."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    fig, axis = plt.subplots(figsize=(_CHART_WIDTH_INCHES, _CHART_HEIGHT_TREND_INCHES))
    dates, counts = _parse_audit_dates_and_counts(audit_rows) if audit_rows else ([], [])

    if not dates:
        axis.text(0.5, 0.5, "No audit history available", ha="center", va="center", fontsize=12)
        axis.axis("off")
        fig.tight_layout()
        plt.close(fig)
        return fig

    date_nums = mdates.date2num(dates)  # type: ignore[no-untyped-call]
    axis.plot(
        date_nums,
        counts,
        marker=_CHART_MARKER_STYLE,
        linewidth=_CHART_LINE_WIDTH,
        color=_CHART_COLOUR_BLUE,
    )
    axis.fill_between(date_nums, counts, alpha=_CHART_FILL_ALPHA, color=_CHART_COLOUR_BLUE)
    axis.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))  # type: ignore[no-untyped-call]
    axis.xaxis.set_major_locator(mdates.AutoDateLocator())  # type: ignore[no-untyped-call]
    fig.autofmt_xdate()
    axis.set_ylabel("Findings")
    axis.set_title("Findings Trend (Audit Log History)")
    axis.grid(axis="y", linestyle="--", alpha=0.5)
    fig.tight_layout()
    plt.close(fig)
    return fig


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE: str = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhiScan Report \u2014 {{ scan_target }}</title>
<style>
  :root { --font: 'Segoe UI', system-ui, -apple-system, sans-serif; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: var(--font); font-size: 14px; color: #2c3e50; background: #f8f9fa; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  header { background: #2c3e50; color: #fff; padding: 32px 24px; border-radius: 8px; margin-bottom: 24px; }
  header h1 { font-size: 26px; margin-bottom: 6px; }
  header .meta { font-size: 13px; opacity: 0.75; }
  .risk-badge {
    display: inline-block; padding: 6px 18px; border-radius: 20px;
    background: #{{ risk_colour }}; color: #fff; font-weight: bold;
    font-size: 15px; margin-top: 12px; letter-spacing: 1px; text-transform: uppercase;
  }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .card .label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px; }
  .card .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
  .card .sub { font-size: 12px; color: #95a5a6; margin-top: 4px; }
  section { background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 24px; }
  section h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; }
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .charts-grid img { width: 100%; border-radius: 6px; border: 1px solid #ecf0f1; }
  .full-width { grid-column: 1 / -1; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #34495e; color: #fff; padding: 8px 10px; text-align: left; font-weight: 600; position: sticky; top: 0; }
  td { padding: 7px 10px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
  tr:hover td { background: #f0f4f8; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-high    { background: #fadbd8; color: #c0392b; }
  .badge-medium  { background: #fdebd0; color: #e67e22; }
  .badge-low     { background: #d5f5e3; color: #27ae60; }
  .badge-info    { background: #ebf5fb; color: #2980b9; }
  details summary { cursor: pointer; color: #2980b9; font-size: 11px; margin-top: 4px; }
  details pre { background: #f4f6f7; padding: 8px; border-radius: 4px; font-size: 11px;
                overflow-x: auto; margin-top: 4px; white-space: pre-wrap; word-break: break-all; }
  .remediation-group { margin-bottom: 16px; }
  .remediation-group h3 { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
  .remediation-group p { font-size: 12px; color: #555; line-height: 1.5; }
  .checklist { padding-left: 20px; margin-top: 8px; }
  .checklist li { font-size: 13px; margin-bottom: 6px; line-height: 1.4; }
  footer { text-align: center; font-size: 12px; color: #95a5a6; padding: 16px 0 8px; }
  @media print {
    body { background: #fff; }
    section { box-shadow: none; break-inside: avoid; }
    details, details pre { display: block; }
  }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>PHI/PII Scan Report</h1>
  <div class="meta">
    Target: {{ scan_target }} &nbsp;|&nbsp;
    PhiScan v{{ version }} &nbsp;|&nbsp;
    {{ timestamp }}
  </div>
  <div class="risk-badge">{{ risk_level }}</div>
</header>

<div class="grid">
  <div class="card">
    <div class="label">Total Findings</div>
    <div class="value">{{ total_findings }}</div>
    <div class="sub">across {{ files_with_findings }} file(s)</div>
  </div>
  <div class="card">
    <div class="label">Files Scanned</div>
    <div class="value">{{ files_scanned }}</div>
    <div class="sub">{{ files_with_findings }} contain PHI</div>
  </div>
  <div class="card">
    <div class="label">High Severity</div>
    <div class="value" style="color:#c0392b">{{ count_high }}</div>
    <div class="sub">requires immediate action</div>
  </div>
  <div class="card">
    <div class="label">Medium Severity</div>
    <div class="value" style="color:#e67e22">{{ count_medium }}</div>
    <div class="sub">should be remediated</div>
  </div>
  <div class="card">
    <div class="label">Scan Duration</div>
    <div class="value">{{ scan_duration }}s</div>
    <div class="sub">wall-clock time</div>
  </div>
</div>

{% if charts %}
<section>
  <h2>Visual Summary</h2>
  <div class="charts-grid">
    {% if charts.category %}
    <div><img src="data:image/png;base64,{{ charts.category }}" alt="Findings by category"></div>
    {% endif %}
    {% if charts.severity %}
    <div><img src="data:image/png;base64,{{ charts.severity }}" alt="Severity distribution"></div>
    {% endif %}
    {% if charts.top_files %}
    <div class="full-width"><img src="data:image/png;base64,{{ charts.top_files }}" alt="Top files"></div>
    {% endif %}
    {% if charts.trend %}
    <div class="full-width"><img src="data:image/png;base64,{{ charts.trend }}" alt="Trend"></div>
    {% endif %}
  </div>
</section>
{% endif %}

<section>
  <h2>Findings ({{ total_findings }})</h2>
  {% if findings %}
  <div style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>#</th><th>File</th><th>Line</th><th>Entity Type</th>
        <th>HIPAA Category</th><th>Severity</th><th>Confidence</th>
        <th>Layer</th><th>Value Hash</th>
      </tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>
          {{ f.file_path }}
          {% if f.code_context %}
          <details>
            <summary>context</summary>
            <pre>{{ f.code_context }}</pre>
          </details>
          {% endif %}
        </td>
        <td>{{ f.line_number }}</td>
        <td><code>{{ f.entity_type }}</code></td>
        <td>{{ f.hipaa_category }}</td>
        <td><span class="badge badge-{{ f.severity }}">{{ f.severity|upper }}</span></td>
        <td>{{ "%.2f"|format(f.confidence) }}</td>
        <td>{{ f.detection_layer }}</td>
        <td style="font-family:monospace;font-size:10px">{{ f.value_hash[:16] }}&hellip;</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
  {% else %}
  <p style="color:#27ae60;font-weight:600">&#10003; No findings &mdash; codebase is clean.</p>
  {% endif %}
</section>

<section>
  <h2>Remediation Guidance</h2>
  {% for cat, guidance in remediation_by_category.items() %}
  <div class="remediation-group">
    <h3>{{ cat }}</h3>
    <p>{{ guidance }}</p>
  </div>
  {% endfor %}
  <h3 style="margin-top:16px;font-size:13px;font-weight:600">General Remediation Checklist</h3>
  <ul class="checklist">
  {% for item in checklist %}
    <li>{{ item }}</li>
  {% endfor %}
  </ul>
</section>

<section>
  <h2>Appendix &mdash; Scan Configuration</h2>
  <table style="width:auto">
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Scanner Version</td><td>PhiScan v{{ version }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Scan Target</td><td>{{ scan_target }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Timestamp</td><td>{{ timestamp }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Risk Level</td><td>{{ risk_level }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Files Scanned</td><td>{{ files_scanned }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Total Findings</td><td>{{ total_findings }}</td></tr>
    <tr><td style="font-weight:600;padding-right:24px;padding-bottom:4px">Scan Duration</td><td>{{ scan_duration }}s</td></tr>
  </table>
</section>

<footer>
  Generated by PhiScan v{{ version }} &mdash; HIPAA &amp; FHIR Compliant PHI/PII Scanner &mdash;
  All scanning executed locally. No PHI was transmitted externally.
</footer>

</div>
</body>
</html>
"""


def _build_html_context(
    scan_result: ScanResult,
    scan_target: Path,
    audit_rows: list[dict[str, object]],
) -> dict[str, object]:
    """Build the Jinja2 template context dict from a ScanResult."""
    present_categories: set[PhiCategory] = {f.hipaa_category for f in scan_result.findings}
    remediation_by_category: dict[str, str] = {
        cat.value.replace("_", " ").title(): HIPAA_REMEDIATION_GUIDANCE[cat]
        for cat in PhiCategory
        if cat in present_categories
    }

    charts: dict[str, str] = {}
    try:
        charts["category"] = _render_chart_to_base64(_build_category_chart(scan_result))
        charts["severity"] = _render_chart_to_base64(_build_severity_chart(scan_result))
        charts["top_files"] = _render_chart_to_base64(_build_top_files_chart(scan_result))
        charts["trend"] = _render_chart_to_base64(_build_trend_chart(audit_rows))
    except Exception as chart_error:  # noqa: BLE001
        _logger.warning("Chart generation failed — report will be text-only: %s", chart_error)
        charts = {}

    severity_counts = scan_result.severity_counts
    return {
        "version": __version__,
        "scan_target": str(scan_target),
        "timestamp": datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "risk_level": scan_result.risk_level.value.upper(),
        "risk_colour": _risk_colour(scan_result.risk_level),
        "total_findings": len(scan_result.findings),
        "files_scanned": scan_result.files_scanned,
        "files_with_findings": scan_result.files_with_findings,
        "scan_duration": f"{scan_result.scan_duration:.2f}",
        "count_high": severity_counts.get(SeverityLevel.HIGH, 0),
        "count_medium": severity_counts.get(SeverityLevel.MEDIUM, 0),
        "count_low": severity_counts.get(SeverityLevel.LOW, 0),
        "count_info": severity_counts.get(SeverityLevel.INFO, 0),
        "findings": scan_result.findings,
        "remediation_by_category": remediation_by_category,
        "checklist": _GENERAL_REMEDIATION_CHECKLIST,
        "charts": charts,
    }


def generate_html_report(
    scan_result: ScanResult,
    scan_target: Path,
    audit_rows: list[dict[str, object]] | None = None,
) -> bytes:
    """Render a self-contained HTML report from a ScanResult.

    Args:
        scan_result: Completed scan result.
        scan_target: Directory or file that was scanned.
        audit_rows: Optional rows from query_recent_scans for the trend chart.

    Returns:
        UTF-8 encoded HTML bytes of the complete self-contained report.
    """
    from jinja2 import Environment, Undefined

    env = Environment(undefined=Undefined, autoescape=True)  # noqa: S701
    template = env.from_string(_HTML_TEMPLATE)
    context = _build_html_context(scan_result, scan_target, audit_rows or [])
    return template.render(**context).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF helpers
# ---------------------------------------------------------------------------


def _pdf_set_font(pdf: object, style: str = "", size: int = _FONT_BODY) -> None:
    """Set the PDF font to Helvetica with the given style and size."""
    pdf.set_font("Helvetica", style=style, size=size)  # type: ignore[attr-defined]


def _pdf_add_section_heading(pdf: object, title: str) -> None:
    """Write a bold section heading with a dark underline bar."""
    pdf.ln(4)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_HEADING)
    pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]
    pdf.cell(0, 8, _pdf_safe(title), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
    pdf.set_fill_color(44, 62, 80)  # type: ignore[attr-defined]
    pdf.cell(0, 0.5, "", new_x="LMARGIN", new_y="NEXT", fill=True)  # type: ignore[attr-defined]
    pdf.ln(3)  # type: ignore[attr-defined]


def _pdf_write_cover_page(
    pdf: object,
    scan_result: ScanResult,
    scan_target: Path,
    timestamp: str,
) -> None:
    """Write the cover page of the PDF report."""
    risk_hex = _risk_colour(scan_result.risk_level)
    risk_rgb = _hex_to_rgb(risk_hex)

    pdf.add_page()  # type: ignore[attr-defined]
    pdf.set_fill_color(44, 62, 80)  # type: ignore[attr-defined]
    pdf.rect(0, 0, _PAGE_WIDTH_MM, 60, style="F")  # type: ignore[attr-defined]

    _pdf_set_font(pdf, style="B", size=_FONT_TITLE)
    pdf.set_text_color(255, 255, 255)  # type: ignore[attr-defined]
    pdf.set_y(18)  # type: ignore[attr-defined]
    pdf.cell(0, 10, "PHI / PII Scan Report", align="C", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    _pdf_set_font(pdf, size=_FONT_BODY)
    pdf.set_text_color(200, 210, 220)  # type: ignore[attr-defined]
    pdf.cell(  # type: ignore[attr-defined]
        0,
        6,
        _pdf_safe(f"PhiScan v{__version__}  |  {timestamp}"),
        align="C",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.set_y(72)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_HEADING)
    pdf.set_text_color(*risk_rgb)  # type: ignore[attr-defined]
    risk_label = f"RISK LEVEL: {scan_result.risk_level.value.upper()}"
    pdf.cell(0, 10, _pdf_safe(risk_label), align="C", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(8)  # type: ignore[attr-defined]
    pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]
    metadata_rows: list[tuple[str, str]] = [
        ("Scan Target", str(scan_target)),
        ("Total Findings", str(len(scan_result.findings))),
        ("Files Scanned", str(scan_result.files_scanned)),
        ("Files with Findings", str(scan_result.files_with_findings)),
        ("Scan Duration", f"{scan_result.scan_duration:.2f}s"),
        ("Timestamp", timestamp),
        ("Scanner Version", f"PhiScan v{__version__}"),
    ]
    for label, value in metadata_rows:
        _pdf_set_font(pdf, style="B", size=_FONT_BODY)
        pdf.cell(55, 7, _pdf_safe(label), border="B")  # type: ignore[attr-defined]
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(0, 7, _pdf_safe(value), border="B", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(10)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_SMALL)
    pdf.set_text_color(127, 140, 141)  # type: ignore[attr-defined]
    pdf.multi_cell(  # type: ignore[attr-defined]
        0,
        5,
        "This report was generated entirely locally. No PHI or PII was transmitted "
        "to any external service. All detected values are stored as SHA-256 hashes only.",
    )


def _pdf_write_summary_page(
    pdf: object,
    scan_result: ScanResult,
    charts: dict[str, bytes],
) -> None:
    """Write the executive summary page with severity/category tables and charts."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "Executive Summary")

    pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]
    severity_rows: list[tuple[str, int]] = [
        ("HIGH", scan_result.severity_counts.get(SeverityLevel.HIGH, 0)),
        ("MEDIUM", scan_result.severity_counts.get(SeverityLevel.MEDIUM, 0)),
        ("LOW", scan_result.severity_counts.get(SeverityLevel.LOW, 0)),
        ("INFO", scan_result.severity_counts.get(SeverityLevel.INFO, 0)),
    ]
    for severity_label, count in severity_rows:
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(50, 6, f"{severity_label}:")  # type: ignore[attr-defined]
        _pdf_set_font(pdf, style="B", size=_FONT_BODY)
        pdf.cell(0, 6, str(count), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(4)  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "HIPAA Category Breakdown")
    non_zero_cats = [
        (cat.value.replace("_", " ").title(), count)
        for cat, count in scan_result.category_counts.items()
        if count > 0
    ]
    if non_zero_cats:
        for cat_name, count in sorted(non_zero_cats, key=lambda p: p[1], reverse=True):
            _pdf_set_font(pdf, size=_FONT_BODY)
            pdf.cell(60, 5, _pdf_safe(cat_name))  # type: ignore[attr-defined]
            _pdf_set_font(pdf, style="B", size=_FONT_BODY)
            pdf.cell(0, 5, str(count), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
    else:
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(0, 5, "No findings.", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    # Embed category and severity charts one per page
    for chart_key in ("category", "severity"):
        png_bytes = charts.get(chart_key)
        if not png_bytes:
            continue
        pdf.add_page()  # type: ignore[attr-defined]
        img_buffer = io.BytesIO(png_bytes)
        try:
            pdf.image(img_buffer, x=_MARGIN_MM, y=None, w=_CONTENT_WIDTH_MM)  # type: ignore[attr-defined]
        except Exception as embed_error:  # noqa: BLE001
            _logger.warning("Could not embed chart %r: %s", chart_key, embed_error)


def _pdf_write_findings_table(pdf: object, scan_result: ScanResult) -> None:
    """Write the paginated findings table."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, f"Detailed Findings ({len(scan_result.findings)})")

    if not scan_result.findings:
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.set_text_color(39, 174, 96)  # type: ignore[attr-defined]
        pdf.cell(0, 8, "No findings - codebase is clean.", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
        return

    def _write_table_header() -> None:
        pdf.set_fill_color(52, 73, 94)  # type: ignore[attr-defined]
        pdf.set_text_color(255, 255, 255)  # type: ignore[attr-defined]
        _pdf_set_font(pdf, style="B", size=_FONT_TABLE_HEADER)
        for header, width in zip(_PDF_COL_HEADERS, _PDF_COL_WIDTHS):
            pdf.cell(width, _PDF_HEADER_HEIGHT, header, border=1, fill=True)  # type: ignore[attr-defined]
        pdf.ln()  # type: ignore[attr-defined]

    _write_table_header()

    for row_index, finding in enumerate(scan_result.findings):
        if pdf.get_y() > _PDF_PAGE_BREAK_Y_MM:  # type: ignore[attr-defined]
            pdf.add_page()  # type: ignore[attr-defined]
            _write_table_header()

        row_rgb = _hex_to_rgb(_severity_row_colour(finding.severity))
        pdf.set_fill_color(*row_rgb)  # type: ignore[attr-defined]
        pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]
        _pdf_set_font(pdf, size=_FONT_TABLE_BODY)

        file_str = str(finding.file_path)
        if len(file_str) > 30:
            file_str = "..." + file_str[-29:]
        entity_str = (
            finding.entity_type[:17] + "..."
            if len(finding.entity_type) > 18
            else finding.entity_type
        )

        row_cells: tuple[str, ...] = (
            str(row_index + 1),
            file_str,
            str(finding.line_number),
            entity_str,
            finding.hipaa_category.value.replace("_", " ").title(),
            finding.severity.value.upper(),
            f"{finding.confidence:.2f}",
            finding.detection_layer.value,
        )
        for cell_text, width in zip(row_cells, _PDF_COL_WIDTHS):
            pdf.cell(width, _PDF_ROW_HEIGHT, _pdf_safe(cell_text), border="B", fill=True)  # type: ignore[attr-defined]
        pdf.ln()  # type: ignore[attr-defined]


def _pdf_write_remediation_section(pdf: object, scan_result: ScanResult) -> None:
    """Write the remediation guidance section."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "Remediation Guidance")

    present_categories = {f.hipaa_category for f in scan_result.findings}
    pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]

    for category in PhiCategory:
        if category not in present_categories:
            continue
        _pdf_set_font(pdf, style="B", size=_FONT_SUBHEADING)
        pdf.cell(  # type: ignore[attr-defined]
            0, 6, _pdf_safe(category.value.replace("_", " ").title()), new_x="LMARGIN", new_y="NEXT"
        )
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.multi_cell(  # type: ignore[attr-defined]
            0, 5, _pdf_safe(textwrap.fill(HIPAA_REMEDIATION_GUIDANCE[category], width=110))
        )
        pdf.ln(2)  # type: ignore[attr-defined]

    pdf.ln(4)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_SUBHEADING)
    pdf.cell(0, 6, "General Remediation Checklist", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_BODY)
    for item in _GENERAL_REMEDIATION_CHECKLIST:
        pdf.multi_cell(0, 5, _pdf_safe(textwrap.fill(f"- {item}", width=110)))  # type: ignore[attr-defined]
        pdf.ln(1)  # type: ignore[attr-defined]


def _pdf_write_appendix(
    pdf: object,
    scan_result: ScanResult,
    scan_target: Path,
    timestamp: str,
) -> None:
    """Write the appendix page with scan configuration details and HIPAA reference."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "Appendix - Scan Configuration")

    pdf.set_text_color(44, 62, 80)  # type: ignore[attr-defined]
    appendix_rows: list[tuple[str, str]] = [
        ("Scanner Version", f"PhiScan v{__version__}"),
        ("Scan Target", str(scan_target)),
        ("Timestamp", timestamp),
        ("Risk Level", scan_result.risk_level.value.upper()),
        ("Files Scanned", str(scan_result.files_scanned)),
        ("Files with Findings", str(scan_result.files_with_findings)),
        ("Total Findings", str(len(scan_result.findings))),
        ("Scan Duration", f"{scan_result.scan_duration:.2f}s"),
    ]
    for label, value in appendix_rows:
        _pdf_set_font(pdf, style="B", size=_FONT_BODY)
        pdf.cell(60, 6, _pdf_safe(label))  # type: ignore[attr-defined]
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(0, 6, _pdf_safe(value), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(8)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_SMALL)
    pdf.set_text_color(127, 140, 141)  # type: ignore[attr-defined]
    pdf.multi_cell(  # type: ignore[attr-defined]
        0,
        5,
        "HIPAA Safe Harbor De-identification (45 CFR SS164.514(b)(2)) requires removal "
        "of all 18 named identifier categories. This report covers all Safe Harbor "
        "categories plus additional regulated identifiers (42 CFR Part 2 SUD records, "
        "quasi-identifier combinations). Expert Determination (SS164.514(b)(1)) requires "
        "a qualified statistician and cannot be certified by automated tooling alone.",
    )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def generate_pdf_report(
    scan_result: ScanResult,
    scan_target: Path,
    audit_rows: list[dict[str, object]] | None = None,
) -> bytes:
    """Render a professional PDF report from a ScanResult.

    Args:
        scan_result: Completed scan result.
        scan_target: Directory or file that was scanned.
        audit_rows: Optional rows from query_recent_scans for the trend chart.

    Returns:
        Raw PDF bytes of the complete multi-page report.
    """
    import fpdf as fpdf_module

    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")

    charts: dict[str, bytes] = {}
    try:
        charts["category"] = _render_chart_to_bytes(_build_category_chart(scan_result))
        charts["severity"] = _render_chart_to_bytes(_build_severity_chart(scan_result))
        charts["top_files"] = _render_chart_to_bytes(_build_top_files_chart(scan_result))
        charts["trend"] = _render_chart_to_bytes(_build_trend_chart(audit_rows or []))
    except Exception as chart_error:  # noqa: BLE001
        _logger.warning("Chart generation failed — PDF will be chart-free: %s", chart_error)

    pdf = fpdf_module.FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=_MARGIN_MM)
    pdf.set_margins(_MARGIN_MM, _MARGIN_MM, _MARGIN_MM)

    _pdf_write_cover_page(pdf, scan_result, scan_target, timestamp)
    _pdf_write_summary_page(pdf, scan_result, charts)
    _pdf_write_findings_table(pdf, scan_result)
    _pdf_write_remediation_section(pdf, scan_result)
    _pdf_write_appendix(pdf, scan_result, scan_target, timestamp)

    return bytes(pdf.output())
