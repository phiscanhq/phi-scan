"""PDF report rendering — fpdf2 page layout, tables, and public entry point."""

from __future__ import annotations

import io
import textwrap
import types
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from phi_scan import __version__
from phi_scan.constants import (
    HIPAA_REMEDIATION_GUIDANCE,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.logging_config import get_logger
from phi_scan.report._shared import (
    _GENERAL_REMEDIATION_CHECKLIST,
    _configure_matplotlib_backend,
    _convert_hex_to_rgb,
    _get_risk_colour,
    _render_chart_to_bytes,
)
from phi_scan.report.charts import (
    _build_category_chart,
    _build_severity_chart,
    _build_top_files_chart,
    _build_trend_chart,
    _extract_trend_data_points,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from phi_scan.compliance import ComplianceControl
    from phi_scan.models import ScanResult

_logger = get_logger("report")

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
_PAGE_SIDE_MARGIN_COUNT: int = 2  # one left margin + one right margin
_CONTENT_WIDTH_MM: float = _PAGE_WIDTH_MM - _PAGE_SIDE_MARGIN_COUNT * _MARGIN_MM

# PDF font sizes
_FONT_TITLE: int = 22
_FONT_HEADING: int = 14
_FONT_SUBHEADING: int = 11
_FONT_BODY: int = 9
_FONT_SMALL: int = 8
_FONT_TABLE_HEADER: int = 8
_FONT_TABLE_BODY: int = 7

_PDF_ROW_HEIGHT: float = 5.5
_PDF_HEADER_HEIGHT: float = 7.0

# Height reserved at the bottom of each PDF page for the footer area.
# The page-break threshold is derived from this so the two values stay in sync.
_PDF_FOOTER_HEIGHT_MM: float = 25.0
# Page-break threshold for findings table (stop before footer area)
_PDF_PAGE_BREAK_Y_MM: float = _PAGE_HEIGHT_MM - _PDF_FOOTER_HEIGHT_MM

# Named RGB tuples for direct fpdf2 set_fill_color / set_text_color calls.
# fpdf2 core font rendering requires integer (R, G, B) tuples — hex strings cannot be
# used directly with these methods, so we maintain a parallel set of RGB constants.
_COLOUR_NAVY_RGB: tuple[int, int, int] = (44, 62, 80)  # dark header and body text
_COLOUR_WHITE_RGB: tuple[int, int, int] = (255, 255, 255)  # white text on dark fill
_COLOUR_LIGHT_SILVER_RGB: tuple[int, int, int] = (200, 210, 220)  # cover subtitle text
_COLOUR_MUTED_GRAY_RGB: tuple[int, int, int] = (127, 140, 141)  # footer and small text
_COLOUR_CLEAN_GREEN_RGB: tuple[int, int, int] = (39, 174, 96)  # clean / no-findings label
_COLOUR_DARK_BLUE_RGB: tuple[int, int, int] = (52, 73, 94)  # table header fill

# Y-axis positions on the PDF cover page (millimetres from top of page).
_PDF_COVER_TITLE_Y_MM: float = 18.0  # vertical position for the report title
_PDF_COVER_RISK_Y_MM: float = 72.0  # vertical position for the risk-level label


# Map of Unicode characters that Helvetica (latin-1) cannot encode → ASCII fallbacks.
# fpdf2 raises FPDFUnicodeEncodingException for any character outside latin-1 when
# using the built-in core fonts.  We replace the most common typographic characters
# before passing text to any fpdf cell/multi_cell call.
_PDF_CHAR_REPLACEMENTS: types.MappingProxyType[str, str] = types.MappingProxyType(
    {
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
)


@dataclass(frozen=True)
class _PdfTableColumn:
    """Header label and width in mm for a single PDF findings table column."""

    header: str
    width_mm: float


_PDF_TABLE_COLUMNS: tuple[_PdfTableColumn, ...] = (
    _PdfTableColumn(header="#", width_mm=8.0),
    _PdfTableColumn(header="File Path", width_mm=52.0),
    _PdfTableColumn(header="Line", width_mm=10.0),
    _PdfTableColumn(header="Entity Type", width_mm=28.0),
    _PdfTableColumn(header="HIPAA Category", width_mm=26.0),
    _PdfTableColumn(header="Severity", width_mm=16.0),
    _PdfTableColumn(header="Conf.", width_mm=14.0),
    _PdfTableColumn(header="Layer", width_mm=16.0),
)


def _encode_pdf_text_as_latin1(text: str) -> str:
    """Replace Unicode characters with ASCII fallbacks, then encode to latin-1 for fpdf2."""
    for char, replacement in _PDF_CHAR_REPLACEMENTS.items():
        text = text.replace(char, replacement)
    # Final fallback: drop any remaining non-latin-1 characters
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _get_severity_row_colour(severity: SeverityLevel) -> str:
    """Return the light-tint hex colour for a severity-level table row."""
    tint_map: dict[SeverityLevel, str] = {
        SeverityLevel.HIGH: _COLOUR_HIGH_TINT,
        SeverityLevel.MEDIUM: _COLOUR_MEDIUM_TINT,
        SeverityLevel.LOW: _COLOUR_LOW_TINT,
        SeverityLevel.INFO: _COLOUR_INFO_TINT,
    }
    return tint_map.get(severity, _COLOUR_WHITE)


def _pdf_set_font(pdf: object, style: str = "", size: int = _FONT_BODY) -> None:
    """Set the PDF font to Helvetica with the given style and size."""
    pdf.set_font("Helvetica", style=style, size=size)  # type: ignore[attr-defined]


def _pdf_add_section_heading(pdf: object, title: str) -> None:
    """Write a bold section heading with a dark underline bar."""
    pdf.ln(4)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_HEADING)
    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
    pdf.cell(0, 8, _encode_pdf_text_as_latin1(title), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
    pdf.set_fill_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
    pdf.cell(0, 0.5, "", new_x="LMARGIN", new_y="NEXT", fill=True)  # type: ignore[attr-defined]
    pdf.ln(3)  # type: ignore[attr-defined]


def _pdf_write_cover_page(
    pdf: object,
    scan_result: ScanResult,
    scan_target: Path,
    timestamp: str,
) -> None:
    """Write the cover page of the PDF report."""
    risk_hex = _get_risk_colour(scan_result.risk_level)
    risk_rgb = _convert_hex_to_rgb(risk_hex)

    pdf.add_page()  # type: ignore[attr-defined]
    pdf.set_fill_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
    pdf.rect(0, 0, _PAGE_WIDTH_MM, 60, style="F")  # type: ignore[attr-defined]

    _pdf_set_font(pdf, style="B", size=_FONT_TITLE)
    pdf.set_text_color(*_COLOUR_WHITE_RGB)  # type: ignore[attr-defined]
    pdf.set_y(_PDF_COVER_TITLE_Y_MM)  # type: ignore[attr-defined]
    pdf.cell(0, 10, "PHI / PII Scan Report", align="C", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    _pdf_set_font(pdf, size=_FONT_BODY)
    pdf.set_text_color(*_COLOUR_LIGHT_SILVER_RGB)  # type: ignore[attr-defined]
    pdf.cell(  # type: ignore[attr-defined]
        0,
        6,
        _encode_pdf_text_as_latin1(f"PhiScan v{__version__}  |  {timestamp}"),
        align="C",
        new_x="LMARGIN",
        new_y="NEXT",
    )

    pdf.set_y(_PDF_COVER_RISK_Y_MM)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_HEADING)
    pdf.set_text_color(*risk_rgb)  # type: ignore[attr-defined]
    risk_label = f"RISK LEVEL: {scan_result.risk_level.value.upper()}"
    pdf.cell(  # type: ignore[attr-defined]
        0, 10, _encode_pdf_text_as_latin1(risk_label), align="C", new_x="LMARGIN", new_y="NEXT"
    )

    pdf.ln(8)  # type: ignore[attr-defined]
    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
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
        pdf.cell(55, 7, _encode_pdf_text_as_latin1(label), border="B")  # type: ignore[attr-defined]
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(0, 7, _encode_pdf_text_as_latin1(value), border="B", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(10)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_SMALL)
    pdf.set_text_color(*_COLOUR_MUTED_GRAY_RGB)  # type: ignore[attr-defined]
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

    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
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
            pdf.cell(60, 5, _encode_pdf_text_as_latin1(cat_name))  # type: ignore[attr-defined]
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
        pdf.set_text_color(*_COLOUR_CLEAN_GREEN_RGB)  # type: ignore[attr-defined]
        pdf.cell(0, 8, "No findings - codebase is clean.", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
        return

    def _write_table_header() -> None:
        pdf.set_fill_color(*_COLOUR_DARK_BLUE_RGB)  # type: ignore[attr-defined]
        pdf.set_text_color(*_COLOUR_WHITE_RGB)  # type: ignore[attr-defined]
        _pdf_set_font(pdf, style="B", size=_FONT_TABLE_HEADER)
        for column in _PDF_TABLE_COLUMNS:
            pdf.cell(column.width_mm, _PDF_HEADER_HEIGHT, column.header, border=1, fill=True)  # type: ignore[attr-defined]
        pdf.ln()  # type: ignore[attr-defined]

    _write_table_header()

    for row_index, finding in enumerate(scan_result.findings):
        if pdf.get_y() > _PDF_PAGE_BREAK_Y_MM:  # type: ignore[attr-defined]
            pdf.add_page()  # type: ignore[attr-defined]
            _write_table_header()

        row_rgb = _convert_hex_to_rgb(_get_severity_row_colour(finding.severity))
        pdf.set_fill_color(*row_rgb)  # type: ignore[attr-defined]
        pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
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
        for cell_text, column in zip(row_cells, _PDF_TABLE_COLUMNS):
            pdf.cell(  # type: ignore[attr-defined]
                column.width_mm,
                _PDF_ROW_HEIGHT,
                _encode_pdf_text_as_latin1(cell_text),
                border="B",
                fill=True,
            )
        pdf.ln()  # type: ignore[attr-defined]


def _pdf_write_remediation_section(pdf: object, scan_result: ScanResult) -> None:
    """Write the remediation guidance section."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "Remediation Guidance")

    present_categories = {f.hipaa_category for f in scan_result.findings}
    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]

    for category in PhiCategory:
        if category not in present_categories:
            continue
        _pdf_set_font(pdf, style="B", size=_FONT_SUBHEADING)
        pdf.cell(  # type: ignore[attr-defined]
            0,
            6,
            _encode_pdf_text_as_latin1(category.value.replace("_", " ").title()),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.multi_cell(  # type: ignore[attr-defined]
            0,
            5,
            _encode_pdf_text_as_latin1(
                textwrap.fill(HIPAA_REMEDIATION_GUIDANCE[category], width=110)
            ),
        )
        pdf.ln(2)  # type: ignore[attr-defined]

    pdf.ln(4)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, style="B", size=_FONT_SUBHEADING)
    pdf.cell(0, 6, "General Remediation Checklist", new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_BODY)
    for item in _GENERAL_REMEDIATION_CHECKLIST:
        pdf.multi_cell(0, 5, _encode_pdf_text_as_latin1(textwrap.fill(f"- {item}", width=110)))  # type: ignore[attr-defined]
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

    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
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
        pdf.cell(60, 6, _encode_pdf_text_as_latin1(label))  # type: ignore[attr-defined]
        _pdf_set_font(pdf, size=_FONT_BODY)
        pdf.cell(0, 6, _encode_pdf_text_as_latin1(value), new_x="LMARGIN", new_y="NEXT")  # type: ignore[attr-defined]

    pdf.ln(8)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_SMALL)
    pdf.set_text_color(*_COLOUR_MUTED_GRAY_RGB)  # type: ignore[attr-defined]
    pdf.multi_cell(  # type: ignore[attr-defined]
        0,
        5,
        "HIPAA Safe Harbor De-identification (45 CFR SS164.514(b)(2)) requires removal "
        "of all 18 named identifier categories. This report covers all Safe Harbor "
        "categories plus additional regulated identifiers (42 CFR Part 2 SUD records, "
        "quasi-identifier combinations). Expert Determination (SS164.514(b)(1)) requires "
        "a qualified statistician and cannot be certified by automated tooling alone.",
    )


def _pdf_write_compliance_matrix(
    pdf: object,
    scan_result: ScanResult,
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]],
) -> None:
    """Write the compliance matrix section listing controls per finding."""
    pdf.add_page()  # type: ignore[attr-defined]
    _pdf_add_section_heading(pdf, "Compliance Matrix")

    pdf.set_text_color(*_COLOUR_NAVY_RGB)  # type: ignore[attr-defined]
    _pdf_set_font(pdf, size=_FONT_SMALL)
    pdf.multi_cell(  # type: ignore[attr-defined]
        0,
        5,
        "Applicable regulatory controls per finding. HIPAA Safe Harbor is always shown; "
        "additional frameworks reflect the --framework selection.",
    )
    pdf.ln(4)  # type: ignore[attr-defined]

    for idx, finding in enumerate(scan_result.findings):
        controls = framework_annotations.get(idx, ())
        if not controls:
            continue
        if pdf.get_y() > _PDF_PAGE_BREAK_Y_MM:  # type: ignore[attr-defined]
            pdf.add_page()  # type: ignore[attr-defined]

        _pdf_set_font(pdf, style="B", size=_FONT_BODY)
        finding_label = (
            f"#{idx + 1}  {finding.file_path}:{finding.line_number}"
            f"  [{finding.hipaa_category.value}]"
        )
        pdf.cell(  # type: ignore[attr-defined]
            0,
            5,
            _encode_pdf_text_as_latin1(finding_label[:100]),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        _pdf_set_font(pdf, size=_FONT_SMALL)
        by_framework: dict[str, list[str]] = {}
        for control in controls:
            fw_label = control.framework.value.upper()
            by_framework.setdefault(fw_label, []).append(control.control_id)
        for fw_label, control_ids in by_framework.items():
            ids_str = ", ".join(control_ids)
            line = f"  {fw_label}: {ids_str}"
            pdf.cell(  # type: ignore[attr-defined]
                0,
                4,
                _encode_pdf_text_as_latin1(line[:120]),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        pdf.ln(2)  # type: ignore[attr-defined]


def generate_pdf_report(
    scan_result: ScanResult,
    scan_target: Path,
    audit_rows: list[dict[str, object]] | None = None,
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None = None,
) -> bytes:
    """Render a professional PDF report from a ScanResult."""
    import fpdf as fpdf_module

    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")

    charts: dict[str, bytes] = {}
    _configure_matplotlib_backend()
    try:
        charts["category"] = _render_chart_to_bytes(_build_category_chart(scan_result))
        charts["severity"] = _render_chart_to_bytes(_build_severity_chart(scan_result))
        charts["top_files"] = _render_chart_to_bytes(_build_top_files_chart(scan_result))
        charts["trend"] = _render_chart_to_bytes(
            _build_trend_chart(_extract_trend_data_points(audit_rows or []))
        )
    except Exception as chart_error:  # noqa: BLE001
        _logger.warning("Chart generation failed — PDF will be chart-free: %s", chart_error)

    pdf = fpdf_module.FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=_MARGIN_MM)
    pdf.set_margins(_MARGIN_MM, _MARGIN_MM, _MARGIN_MM)

    _pdf_write_cover_page(pdf, scan_result, scan_target, timestamp)
    _pdf_write_summary_page(pdf, scan_result, charts)
    _pdf_write_findings_table(pdf, scan_result)
    _pdf_write_remediation_section(pdf, scan_result)
    if framework_annotations:
        _pdf_write_compliance_matrix(pdf, scan_result, framework_annotations)
    _pdf_write_appendix(pdf, scan_result, scan_target, timestamp)

    return bytes(pdf.output())
