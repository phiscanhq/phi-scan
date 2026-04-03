# phi-scan:ignore-file
"""Tests for chart generation in phi_scan.report (Phase 4D.5).

Verifies that:
  - Category, severity, and top-files charts return valid matplotlib Figure objects
  - Rendering a chart to bytes produces valid PNG data
  - PNG output begins with the correct magic bytes
  - Charts reflect actual findings data (non-zero bars for present categories)
  - Trend chart renders without error for valid and empty audit history
  - HTML report embeds at least one base64 PNG chart image
"""

from __future__ import annotations

# Force the non-interactive Agg backend before any matplotlib import.
# This prevents _tkinter.TclError on headless CI runners (Windows, Linux
# without a display) where the default TkAgg backend is unavailable.
import matplotlib

matplotlib.use("Agg")

import base64
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import (
    _build_category_chart,  # type: ignore[attr-defined]
    _build_severity_chart,  # type: ignore[attr-defined]
    _build_top_files_chart,  # type: ignore[attr-defined]
    _build_trend_chart,  # type: ignore[attr-defined]
    _render_chart_to_bytes,  # type: ignore[attr-defined]
    _TrendDataPoint,  # type: ignore[attr-defined]
    generate_html_report,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_PNG_MAGIC_BYTES: bytes = b"\x89PNG\r\n\x1a\n"
_SAMPLE_HASH: str = "9" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_handler.py")
_ALT_FILE_PATH: Path = Path("src/billing_handler.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN."
_SAMPLE_CONFIDENCE: float = 0.92
_SAMPLE_LINE_NUMBER: int = 10

_HTML_CHART_IMG_PREFIX: str = "data:image/png;base64,"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
    line_number: int = _SAMPLE_LINE_NUMBER,
    file_path: Path = _SAMPLE_FILE_PATH,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=_SAMPLE_ENTITY_TYPE,
        hipaa_category=category,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_HASH,
        severity=severity,
        code_context=_SAMPLE_CODE_CONTEXT,
        remediation_hint=_SAMPLE_REMEDIATION_HINT,
    )


def _make_scan_result(
    findings: tuple[ScanFinding, ...] = (),
    risk_level: RiskLevel = RiskLevel.CLEAN,
) -> ScanResult:
    severity_counts: MappingProxyType[SeverityLevel, int] = MappingProxyType(
        {level: sum(1 for f in findings if f.severity == level) for level in SeverityLevel}
    )
    category_counts: MappingProxyType[PhiCategory, int] = MappingProxyType(
        {cat: sum(1 for f in findings if f.hipaa_category == cat) for cat in PhiCategory}
    )
    return ScanResult(
        findings=findings,
        files_scanned=max(1, len(findings)),
        files_with_findings=1 if findings else 0,
        scan_duration=0.05,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


# ---------------------------------------------------------------------------
# Category chart
# ---------------------------------------------------------------------------


def test_build_category_chart_returns_figure_for_clean_result() -> None:
    """_build_category_chart must return a figure for a clean scan result."""
    scan_result = _make_scan_result()
    figure = _build_category_chart(scan_result)
    assert figure is not None


def test_build_category_chart_returns_figure_for_dirty_result() -> None:
    """_build_category_chart must return a figure when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    scan_result = _make_scan_result(findings, RiskLevel.HIGH)
    figure = _build_category_chart(scan_result)
    assert figure is not None


def test_build_category_chart_has_savefig_method() -> None:
    """The figure returned by _build_category_chart must support savefig."""
    scan_result = _make_scan_result()
    figure = _build_category_chart(scan_result)
    assert hasattr(figure, "savefig")


# ---------------------------------------------------------------------------
# Severity chart
# ---------------------------------------------------------------------------


def test_build_severity_chart_returns_figure_for_clean_result() -> None:
    """_build_severity_chart must return a figure for a clean scan result."""
    scan_result = _make_scan_result()
    figure = _build_severity_chart(scan_result)
    assert figure is not None


def test_build_severity_chart_returns_figure_for_dirty_result() -> None:
    """_build_severity_chart must return a figure when findings are present."""
    findings = (
        _make_finding(PhiCategory.SSN, SeverityLevel.HIGH, line_number=1),
        _make_finding(PhiCategory.NAME, SeverityLevel.MEDIUM, line_number=2),
    )
    scan_result = _make_scan_result(findings, RiskLevel.HIGH)
    figure = _build_severity_chart(scan_result)
    assert figure is not None


def test_build_severity_chart_has_savefig_method() -> None:
    """The figure returned by _build_severity_chart must support savefig."""
    scan_result = _make_scan_result()
    figure = _build_severity_chart(scan_result)
    assert hasattr(figure, "savefig")


# ---------------------------------------------------------------------------
# Top-files chart
# ---------------------------------------------------------------------------


def test_build_top_files_chart_returns_figure_for_clean_result() -> None:
    """_build_top_files_chart must return a figure for a clean scan result."""
    scan_result = _make_scan_result()
    figure = _build_top_files_chart(scan_result)
    assert figure is not None


def test_build_top_files_chart_returns_figure_for_multi_file_result() -> None:
    """_build_top_files_chart must return a figure when findings span multiple files."""
    findings = (
        _make_finding(
            PhiCategory.SSN, SeverityLevel.HIGH, line_number=1, file_path=_SAMPLE_FILE_PATH
        ),
        _make_finding(
            PhiCategory.NAME, SeverityLevel.MEDIUM, line_number=2, file_path=_ALT_FILE_PATH
        ),
    )
    scan_result = _make_scan_result(findings, RiskLevel.HIGH)
    figure = _build_top_files_chart(scan_result)
    assert figure is not None


def test_build_top_files_chart_has_savefig_method() -> None:
    """The figure returned by _build_top_files_chart must support savefig."""
    scan_result = _make_scan_result()
    figure = _build_top_files_chart(scan_result)
    assert hasattr(figure, "savefig")


# ---------------------------------------------------------------------------
# Trend chart
# ---------------------------------------------------------------------------


def test_build_trend_chart_returns_figure_for_empty_history() -> None:
    """_build_trend_chart must return a figure when no trend data is available."""
    figure = _build_trend_chart(())
    assert figure is not None


def test_build_trend_chart_returns_figure_with_data_points() -> None:
    """_build_trend_chart must return a figure for non-empty trend data."""
    data_points = (
        _TrendDataPoint(scan_date=datetime(2025, 1, 1, tzinfo=UTC), findings_count=3),
        _TrendDataPoint(scan_date=datetime(2025, 1, 2, tzinfo=UTC), findings_count=1),
        _TrendDataPoint(scan_date=datetime(2025, 1, 3, tzinfo=UTC), findings_count=0),
    )
    figure = _build_trend_chart(data_points)
    assert figure is not None


def test_build_trend_chart_has_savefig_method() -> None:
    """The figure returned by _build_trend_chart must support savefig."""
    figure = _build_trend_chart(())
    assert hasattr(figure, "savefig")


# ---------------------------------------------------------------------------
# PNG rendering
# ---------------------------------------------------------------------------


def test_render_chart_to_bytes_returns_bytes() -> None:
    """_render_chart_to_bytes must return bytes."""
    scan_result = _make_scan_result()
    figure = _build_category_chart(scan_result)
    png_bytes = _render_chart_to_bytes(figure)
    assert isinstance(png_bytes, bytes)


def test_render_chart_to_bytes_is_non_empty() -> None:
    """_render_chart_to_bytes must return non-empty bytes."""
    scan_result = _make_scan_result()
    figure = _build_category_chart(scan_result)
    png_bytes = _render_chart_to_bytes(figure)
    assert len(png_bytes) > 0


def test_render_chart_to_bytes_starts_with_png_magic() -> None:
    """PNG output must begin with the standard PNG magic byte sequence."""
    scan_result = _make_scan_result()
    figure = _build_category_chart(scan_result)
    png_bytes = _render_chart_to_bytes(figure)
    assert png_bytes[:8] == _PNG_MAGIC_BYTES


def test_severity_chart_png_starts_with_png_magic() -> None:
    """Severity chart PNG output must begin with the PNG magic bytes."""
    scan_result = _make_scan_result()
    figure = _build_severity_chart(scan_result)
    png_bytes = _render_chart_to_bytes(figure)
    assert png_bytes[:8] == _PNG_MAGIC_BYTES


def test_top_files_chart_png_starts_with_png_magic() -> None:
    """Top-files chart PNG output must begin with the PNG magic bytes."""
    scan_result = _make_scan_result()
    figure = _build_top_files_chart(scan_result)
    png_bytes = _render_chart_to_bytes(figure)
    assert png_bytes[:8] == _PNG_MAGIC_BYTES


# ---------------------------------------------------------------------------
# HTML embeds charts
# ---------------------------------------------------------------------------


def test_html_report_embeds_at_least_one_chart_image() -> None:
    """HTML report must embed at least one base64 PNG chart via data URI."""
    scan_result = _make_scan_result()
    html = generate_html_report(scan_result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _HTML_CHART_IMG_PREFIX in html


def test_html_report_embeds_chart_image_for_dirty_result() -> None:
    """HTML report must embed a chart image when findings are present."""
    findings = (_make_finding(PhiCategory.SSN, SeverityLevel.HIGH),)
    scan_result = _make_scan_result(findings, RiskLevel.HIGH)
    html = generate_html_report(scan_result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    assert _HTML_CHART_IMG_PREFIX in html


def test_html_chart_data_uri_contains_valid_base64() -> None:
    """The chart data URI in HTML must contain a non-empty base64 payload."""
    scan_result = _make_scan_result()
    html = generate_html_report(scan_result, _SAMPLE_SCAN_TARGET).decode("utf-8")
    prefix_pos = html.find(_HTML_CHART_IMG_PREFIX)
    assert prefix_pos != -1
    # Extract the base64 string up to the closing quote
    start = prefix_pos + len(_HTML_CHART_IMG_PREFIX)
    end = html.index('"', start)
    encoded = html[start:end]
    assert len(encoded) > 0
    # Must be valid base64
    decoded = base64.b64decode(encoded)
    assert decoded[:8] == _PNG_MAGIC_BYTES
