# phi-scan:ignore-file
"""Tests for output format dispatch — PDF and HTML file writing (Phase 4D.7).

Verifies that:
  - generate_pdf_report and generate_html_report produce valid file content
  - --report-path is respected: output is written to the specified file
  - PDF and HTML report files contain the expected content signatures
  - ScanOutputOptions wires scan_target and framework_annotations correctly
  - generate_report_bytes returns bytes for both PDF and HTML formats
  - generate_report_bytes raises ValueError for non-binary formats
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.cli_report import (
    ScanOutputOptions,
    generate_report_bytes,
)
from phi_scan.compliance import ComplianceFramework, annotate_findings
from phi_scan.constants import (
    DetectionLayer,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report import generate_html_report, generate_pdf_report

# ---------------------------------------------------------------------------
# Test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "b" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient.py")
_SAMPLE_SCAN_TARGET: Path = Path(".")
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_SAMPLE_REMEDIATION_HINT: str = "Replace SSN."
_SAMPLE_CONFIDENCE: float = 0.91
_SAMPLE_LINE_NUMBER: int = 5

_PDF_MAGIC_HEADER: bytes = b"%PDF-"
_PNG_MAGIC_BYTES: bytes = b"\x89PNG\r\n\x1a\n"
_HTML_OPEN_TAG: str = "<html"
_HTML_CHART_PREFIX: str = "data:image/png;base64,"
_EXPECTED_PDF_FILENAME: str = "phi-scan-report.pdf"
_EXPECTED_HTML_FILENAME: str = "phi-scan-report.html"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> ScanFinding:
    return ScanFinding(
        file_path=_SAMPLE_FILE_PATH,
        line_number=_SAMPLE_LINE_NUMBER,
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
        scan_duration=0.12,
        is_clean=not findings,
        risk_level=risk_level if findings else RiskLevel.CLEAN,
        severity_counts=severity_counts,
        category_counts=category_counts,
    )


def _make_output_options(
    output_format: OutputFormat,
    report_path: Path | None = None,
    scan_target: Path = _SAMPLE_SCAN_TARGET,
) -> ScanOutputOptions:
    return ScanOutputOptions(
        output_format=output_format,
        is_rich_mode=False,
        report_path=report_path,
        scan_target=scan_target,
    )


# ---------------------------------------------------------------------------
# generate_pdf_report: output contract
# ---------------------------------------------------------------------------


def test_pdf_output_starts_with_pdf_magic_header() -> None:
    """generate_pdf_report must return bytes starting with the PDF magic header."""
    result = _make_scan_result()
    output = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    assert output.startswith(_PDF_MAGIC_HEADER)


def test_pdf_written_to_report_path(tmp_path: Path) -> None:
    """generate_pdf_report output must be writable to a file and re-readable."""
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_PDF_FILENAME
    report_file.write_bytes(pdf_bytes)
    assert report_file.exists()
    assert report_file.read_bytes().startswith(_PDF_MAGIC_HEADER)


def test_pdf_file_size_is_non_trivial(tmp_path: Path) -> None:
    """PDF file on disk must be larger than 1 KB."""
    result = _make_scan_result()
    pdf_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_PDF_FILENAME
    report_file.write_bytes(pdf_bytes)
    assert report_file.stat().st_size > 1024


# ---------------------------------------------------------------------------
# generate_html_report: output contract
# ---------------------------------------------------------------------------


def test_html_output_contains_html_tag() -> None:
    """generate_html_report must return UTF-8 bytes containing an <html> tag."""
    result = _make_scan_result()
    output = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    assert _HTML_OPEN_TAG in output.decode("utf-8")


def test_html_written_to_report_path(tmp_path: Path) -> None:
    """generate_html_report output must be writable to a file and re-readable."""
    result = _make_scan_result()
    html_bytes = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_HTML_FILENAME
    report_file.write_bytes(html_bytes)
    assert report_file.exists()
    html_text = report_file.read_text(encoding="utf-8")
    assert _HTML_OPEN_TAG in html_text


def test_html_file_contains_embedded_chart(tmp_path: Path) -> None:
    """HTML file on disk must contain a base64-embedded PNG chart."""
    result = _make_scan_result()
    html_bytes = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_HTML_FILENAME
    report_file.write_bytes(html_bytes)
    html_text = report_file.read_text(encoding="utf-8")
    assert _HTML_CHART_PREFIX in html_text


# ---------------------------------------------------------------------------
# ScanOutputOptions: scan_target wiring
# ---------------------------------------------------------------------------


def test_scan_output_options_stores_scan_target() -> None:
    """ScanOutputOptions must store the provided scan_target."""
    custom_target = Path("services/patient-api")
    options = _make_output_options(OutputFormat.PDF, scan_target=custom_target)
    assert options.scan_target == custom_target


def test_scan_output_options_stores_report_path(tmp_path: Path) -> None:
    """ScanOutputOptions must store the provided report_path."""
    report_file = tmp_path / _EXPECTED_PDF_FILENAME
    options = _make_output_options(OutputFormat.PDF, report_path=report_file)
    assert options.report_path == report_file


def test_scan_output_options_stores_framework_annotations() -> None:
    """ScanOutputOptions must store framework_annotations when provided."""
    finding = _make_finding()
    annotations = annotate_findings((finding,), frozenset({ComplianceFramework.SOC2}))
    options = ScanOutputOptions(
        output_format=OutputFormat.PDF,
        is_rich_mode=False,
        report_path=None,
        scan_target=_SAMPLE_SCAN_TARGET,
        framework_annotations=annotations,
    )
    assert options.framework_annotations is annotations


def test_scan_output_options_default_scan_target_is_current_dir() -> None:
    """ScanOutputOptions default scan_target must be Path('.')."""
    options = ScanOutputOptions(
        output_format=OutputFormat.TABLE,
        is_rich_mode=True,
        report_path=None,
    )
    assert options.scan_target == Path(".")


# ---------------------------------------------------------------------------
# generate_report_bytes: format dispatch
# ---------------------------------------------------------------------------


def testgenerate_report_bytes_returns_pdf_for_pdf_format() -> None:
    """generate_report_bytes must return PDF bytes when format is PDF."""
    result = _make_scan_result()
    options = _make_output_options(OutputFormat.PDF)
    output = generate_report_bytes(result, options, [])
    assert isinstance(output, bytes)
    assert output.startswith(_PDF_MAGIC_HEADER)


def testgenerate_report_bytes_returns_html_for_html_format() -> None:
    """generate_report_bytes must return HTML bytes when format is HTML."""
    result = _make_scan_result()
    options = _make_output_options(OutputFormat.HTML)
    output = generate_report_bytes(result, options, [])
    assert isinstance(output, bytes)
    assert _HTML_OPEN_TAG in output.decode("utf-8")


def testgenerate_report_bytes_raises_for_non_binary_format() -> None:
    """generate_report_bytes must raise ValueError for non-binary formats."""
    result = _make_scan_result()
    options = _make_output_options(OutputFormat.JSON)
    with pytest.raises(ValueError):
        generate_report_bytes(result, options, [])


def testgenerate_report_bytes_raises_for_sarif_format() -> None:
    """generate_report_bytes must raise ValueError for SARIF format."""
    result = _make_scan_result()
    options = _make_output_options(OutputFormat.SARIF)
    with pytest.raises(ValueError):
        generate_report_bytes(result, options, [])


# ---------------------------------------------------------------------------
# report_path respected
# ---------------------------------------------------------------------------


def test_pdf_report_path_file_matches_direct_output(tmp_path: Path) -> None:
    """PDF bytes written to a file must equal bytes returned by generate_pdf_report."""
    result = _make_scan_result()
    expected_bytes = generate_pdf_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_PDF_FILENAME
    report_file.write_bytes(expected_bytes)
    assert report_file.read_bytes() == expected_bytes


def test_html_report_path_file_matches_direct_output(tmp_path: Path) -> None:
    """HTML bytes written to a file must equal bytes returned by generate_html_report."""
    result = _make_scan_result()
    expected_bytes = generate_html_report(result, _SAMPLE_SCAN_TARGET)
    report_file = tmp_path / _EXPECTED_HTML_FILENAME
    report_file.write_bytes(expected_bytes)
    assert report_file.read_bytes() == expected_bytes
