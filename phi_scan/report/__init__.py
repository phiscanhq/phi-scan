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

    html_bytes = generate_html_report(scan_result, scan_target=Path("."))
    pdf_bytes  = generate_pdf_report(scan_result, scan_target=Path("."))
"""

from __future__ import annotations

from phi_scan.report._shared import (
    _GENERAL_REMEDIATION_CHECKLIST,
    _render_chart_to_bytes,
)
from phi_scan.report.charts import (
    _build_category_chart,
    _build_severity_chart,
    _build_top_files_chart,
    _build_trend_chart,
    _TrendDataPoint,
)
from phi_scan.report.html import generate_html_report
from phi_scan.report.pdf import generate_pdf_report

# Private symbols listed in __all__ so tests can import them directly from
# `phi_scan.report` without reaching into submodules. The canonical home for
# each is the corresponding sibling module; this package root is a
# compatibility / re-export layer only.
__all__ = [
    "_GENERAL_REMEDIATION_CHECKLIST",
    "_TrendDataPoint",
    "_build_category_chart",
    "_build_severity_chart",
    "_build_top_files_chart",
    "_build_trend_chart",
    "_render_chart_to_bytes",
    "generate_html_report",
    "generate_pdf_report",
]
