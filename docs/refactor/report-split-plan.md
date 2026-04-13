# `phi_scan/report.py` decomposition plan

**Status:** PLANNED — deferred from the pristine-closure pass.
**Module size:** 1408 lines, ~35 functions, 2 public entry points
(`generate_html_report`, `generate_pdf_report`).

This document specifies the exact decomposition target for
`phi_scan/report.py` so the next pass can execute mechanically.

## Why deferred

- Chart helpers (`_build_category_chart`, `_build_severity_chart`,
  `_build_top_files_chart`, `_build_trend_chart`) are consumed by **both**
  HTML and PDF rendering paths. A naïve split risks circular imports.
- `matplotlib.use("Agg")` is called unconditionally at module import; moving
  that side effect requires a deliberate decision about where it should live
  in the new layout.
- Both rendering paths share buffer/base64 conversion helpers
  (`_render_chart_to_buffer`, `_render_chart_to_base64`,
  `_render_chart_to_bytes`) — these must live in `_shared` and be imported
  by both.

## Target layout

```
phi_scan/report/
    __init__.py          # re-export generate_html_report, generate_pdf_report
    _shared.py           # colour helpers, matplotlib backend config,
                         # chart-to-buffer/base64/bytes helpers, shared
                         # truncation helpers
    charts.py            # _build_*_chart builders + chart data preparers
                         # (_prepare_category_chart_data, etc.)
    tables.py            # _build_compliance_matrix_rows and any shared
                         # tabular builders used by both HTML and PDF
    html.py              # _build_html_context + generate_html_report
    pdf.py               # all _pdf_* helpers + generate_pdf_report
```

## Function-to-module mapping

| Current (in `report.py`) | Target |
|---|---|
| `_convert_hex_to_rgb`, `_get_risk_colour`, `_get_severity_row_colour` | `_shared.py` |
| `_encode_pdf_text_as_latin1`, `_truncate_code_context`, `_truncate_chart_label` | `_shared.py` |
| `_configure_matplotlib_backend`, `_render_chart_to_*`, `_HorizontalBarChartSpec`, `_render_horizontal_bar_figure` | `_shared.py` |
| `_prepare_*_chart_data`, `_build_*_chart`, `_extract_trend_data_points`, `_TrendDataPoint` | `charts.py` |
| `_build_compliance_matrix_rows` | `tables.py` |
| `_build_html_context`, `generate_html_report` | `html.py` |
| `_pdf_*`, `_PdfTableColumn`, `generate_pdf_report` | `pdf.py` |

## Shim strategy

`phi_scan/report.py` becomes a top-level re-export shim:

```python
from phi_scan.report.html import generate_html_report  # noqa: F401
from phi_scan.report.pdf import generate_pdf_report  # noqa: F401
```

No deprecation warning. Matches the `cli_*.py` shim pattern established in
the pristine-closure pass.

## Risk checklist

- [ ] Verify `matplotlib.use("Agg")` runs exactly once, before any pyplot
      import in `charts.py`.
- [ ] Verify `_MatplotlibFigure` Protocol stays reachable from both
      `charts.py` and `_shared.py` without creating a cycle.
- [ ] Golden output parity: run `uv run pytest tests/test_report_formats.py`
      before/after; byte-compare the produced HTML and PDF against the
      existing fixtures.
- [ ] No new module-import side effects (e.g. reading env vars at import
      time) that the monolith did not already perform.

## Test strategy

- `tests/test_report_formats.py` is the primary safety net. Do not modify
  it during the split; its byte-exact assertions prove zero-behavior drift.
- After the split, optionally mirror tests into `tests/report/test_html.py`,
  `tests/report/test_pdf.py`, `tests/report/test_charts.py` — but only if
  the existing monolithic test is already slow or mixes concerns.
