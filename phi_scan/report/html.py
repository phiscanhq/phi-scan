"""HTML report rendering — Jinja2 template and public entry point."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from phi_scan import __version__
from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    HIPAA_REMEDIATION_GUIDANCE,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.logging_config import get_logger
from phi_scan.report._shared import (
    _GENERAL_REMEDIATION_CHECKLIST,
    _configure_matplotlib_backend,
    _get_risk_colour,
    _render_chart_to_base64,
)
from phi_scan.report.charts import (
    _build_category_chart,
    _build_severity_chart,
    _build_top_files_chart,
    _build_trend_chart,
    _extract_trend_data_points,
)
from phi_scan.report.tables import _build_compliance_matrix_rows

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from phi_scan.compliance import ComplianceControl
    from phi_scan.models import ScanResult

_logger = get_logger("report")

# Maximum code-context characters shown per finding in reports
_MAX_CONTEXT_CHARS: int = 200


def _truncate_code_context(context: str) -> str:
    """Truncate code context for report rendering, stripping unredacted content.

    The scanner layer is expected to substitute detected PHI values with
    CODE_CONTEXT_REDACTED_VALUE before populating ScanFinding.code_context.  When the
    marker is absent from a non-empty context, the content may contain raw PHI —
    the entire context is replaced with CODE_CONTEXT_REDACTED_VALUE and a warning is logged
    so that any scanner redaction regression surfaces immediately without
    allowing PHI to escape into report output.
    """
    if context and CODE_CONTEXT_REDACTED_VALUE not in context:
        _logger.warning(
            "code_context passed to report without '%s' marker — "
            "stripping content to prevent PHI leaking into report output",
            CODE_CONTEXT_REDACTED_VALUE,
        )
        return CODE_CONTEXT_REDACTED_VALUE
    return context[:_MAX_CONTEXT_CHARS]


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
  .framework-tag { display: inline-block; margin: 1px 2px; padding: 1px 6px; border-radius: 10px;
                   font-size: 10px; font-weight: 600; background: #eaf0fb; color: #2471a3; }
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
            <pre>{{ truncate_code_context(f.code_context) }}</pre>
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

{% if compliance_matrix_rows %}
<section>
  <h2>Compliance Matrix</h2>
  <p style="font-size:12px;color:#555;margin-bottom:12px">
    Applicable regulatory controls per finding. HIPAA Safe Harbor is always shown;
    additional frameworks reflect your <code>--framework</code> selection.
  </p>
  <div style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>#</th><th>File</th><th>Line</th><th>Category</th><th>Applicable Controls</th>
      </tr>
    </thead>
    <tbody>
    {% for row in compliance_matrix_rows %}
      <tr>
        <td>{{ row.index }}</td>
        <td style="font-size:11px">{{ row.file_path }}</td>
        <td>{{ row.line_number }}</td>
        <td>{{ row.category }}</td>
        <td>
          {% for fw, control_ids in row.frameworks.items() %}
            <div style="margin-bottom:3px">
              <strong style="font-size:10px;color:#2c3e50">{{ fw }}</strong>
              {% for cid in control_ids %}
                <span class="framework-tag">{{ cid }}</span>
              {% endfor %}
            </div>
          {% endfor %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
</section>
{% endif %}

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
  Generated by PhiScan v{{ version }} &mdash; PHI/PII Scanner for HIPAA-Aligned Environments &mdash;
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
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None = None,
) -> dict[str, object]:
    """Build the Jinja2 template context dict from a ScanResult."""
    present_categories: set[PhiCategory] = {f.hipaa_category for f in scan_result.findings}
    remediation_by_category: dict[str, str] = {
        cat.value.replace("_", " ").title(): HIPAA_REMEDIATION_GUIDANCE[cat]
        for cat in PhiCategory
        if cat in present_categories
    }

    charts: dict[str, str] = {}
    _configure_matplotlib_backend()
    try:
        charts["category"] = _render_chart_to_base64(_build_category_chart(scan_result))
        charts["severity"] = _render_chart_to_base64(_build_severity_chart(scan_result))
        charts["top_files"] = _render_chart_to_base64(_build_top_files_chart(scan_result))
        charts["trend"] = _render_chart_to_base64(
            _build_trend_chart(_extract_trend_data_points(audit_rows))
        )
    except Exception as chart_error:  # noqa: BLE001
        _logger.warning("Chart generation failed — report will be text-only: %s", chart_error)
        charts = {}

    severity_counts = scan_result.severity_counts
    return {
        "version": __version__,
        "scan_target": str(scan_target),
        "timestamp": datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "risk_level": scan_result.risk_level.value.upper(),
        "risk_colour": _get_risk_colour(scan_result.risk_level),
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
        "compliance_matrix_rows": _build_compliance_matrix_rows(scan_result, framework_annotations),
    }


def generate_html_report(
    scan_result: ScanResult,
    scan_target: Path,
    audit_rows: list[dict[str, object]] | None = None,
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None = None,
) -> bytes:
    """Render a self-contained HTML report from a ScanResult."""
    from jinja2 import Environment, Undefined

    env = Environment(undefined=Undefined, autoescape=True)  # noqa: S701
    # Expose the context truncation guard as a template global so the template
    # cannot accidentally render raw code_context without going through the guard.
    env.globals["truncate_code_context"] = _truncate_code_context
    template = env.from_string(_HTML_TEMPLATE)
    context = _build_html_context(scan_result, scan_target, audit_rows or [], framework_annotations)
    return template.render(**context).encode("utf-8")
