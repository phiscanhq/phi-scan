"""Runtime execution tests for the Plugin API v1.

Covers the scan-time integration: plugin findings reach the scan result,
exceptions in ``detect`` are isolated per line, malformed findings are
dropped with a warning, scans without installed plugins behave exactly
as before, parallel workers produce identical findings, and the loader
is invoked exactly once per ``execute_scan`` invocation.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from phi_scan.constants import DetectionLayer, SeverityLevel
from phi_scan.models import ScanConfig, ScanFinding
from phi_scan.plugin_api import BaseRecognizer, ScanContext
from phi_scan.plugin_api import ScanFinding as PluginScanFinding
from phi_scan.plugin_loader import LoadedPlugin, PluginRegistry
from phi_scan.plugin_runtime import _MAX_WARNINGS_PER_RECOGNIZER, execute_plugin_pass
from phi_scan.scanner import _load_cached_plugin_registry, execute_scan

_ACME_ENTITY_TYPE: str = "ACME_EMPLOYEE_ID"
_ACME_RECOGNIZER_NAME: str = "acme_employee_id"
_ACME_CONFIDENCE: float = 0.9
_PLUGIN_SAMPLE_LINE: str = "employee_id = EMP-123456"
_RATE_LIMIT_TEST_LINE_COUNT: int = 20
_OFFSET_OVERRUN_EXTRA: int = 50
_CONFIDENCE_THRESHOLD_ABOVE_ACME: float = 0.99


class _AcmeRecognizer(BaseRecognizer):
    """Simple recognizer that matches ``EMP-######`` patterns."""

    name = _ACME_RECOGNIZER_NAME
    entity_types = (_ACME_ENTITY_TYPE,)
    plugin_api_version = "1.0"
    version = "0.1.0"
    description = "Test ACME employee ID recognizer."

    def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
        match = re.search(r"\bEMP-\d{6}\b", line)
        if match is None:
            return []
        return [
            PluginScanFinding(
                entity_type=_ACME_ENTITY_TYPE,
                start_offset=match.start(),
                end_offset=match.end(),
                confidence=_ACME_CONFIDENCE,
            )
        ]


class _RaisingRecognizer(BaseRecognizer):
    name = "raising_recognizer"
    entity_types = ("RAISING_TEST",)
    plugin_api_version = "1.0"

    def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
        raise RuntimeError("simulated plugin failure")


class _OffsetOverrunRecognizer(BaseRecognizer):
    name = "offset_overrun"
    entity_types = ("OVERRUN_TEST",)
    plugin_api_version = "1.0"

    def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
        return [
            PluginScanFinding(
                entity_type="OVERRUN_TEST",
                start_offset=0,
                end_offset=len(line) + _OFFSET_OVERRUN_EXTRA,
                confidence=_ACME_CONFIDENCE,
            )
        ]


class _UndeclaredEntityTypeRecognizer(BaseRecognizer):
    name = "undeclared_entity"
    entity_types = ("DECLARED_ONLY",)
    plugin_api_version = "1.0"

    def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
        return [
            PluginScanFinding(
                entity_type="NOT_DECLARED",
                start_offset=0,
                end_offset=5,
                confidence=_ACME_CONFIDENCE,
            )
        ]


def _build_registry(*recognizers: BaseRecognizer) -> PluginRegistry:
    loaded = tuple(
        LoadedPlugin(
            entry_point_name=recognizer.name,
            distribution_name=f"{recognizer.name}-dist",
            recognizer=recognizer,
        )
        for recognizer in recognizers
    )
    return PluginRegistry(loaded=loaded)


@pytest.fixture(autouse=True)
def _clear_scan_registry_cache() -> Iterator[None]:
    _load_cached_plugin_registry.cache_clear()
    yield
    _load_cached_plugin_registry.cache_clear()


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    target = tmp_path / "source.py"
    target.write_text(_PLUGIN_SAMPLE_LINE + "\n", encoding="utf-8")
    return target


@pytest.fixture
def scan_config() -> ScanConfig:
    return ScanConfig(confidence_threshold=0.0, severity_threshold=SeverityLevel.INFO)


# ---------------------------------------------------------------------------
# execute_plugin_pass unit tests
# ---------------------------------------------------------------------------


def test_execute_plugin_pass_returns_empty_list_when_no_plugins_loaded() -> None:
    findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("source.py"), PluginRegistry())
    assert findings == []


def test_execute_plugin_pass_emits_finding_with_host_computed_fields() -> None:
    registry = _build_registry(_AcmeRecognizer())

    findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("source.py"), registry)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, ScanFinding)
    assert finding.entity_type == _ACME_ENTITY_TYPE
    assert finding.detection_layer == DetectionLayer.PLUGIN
    assert finding.confidence == _ACME_CONFIDENCE
    assert "[REDACTED]" in finding.code_context
    assert "EMP-123456" not in finding.code_context
    assert len(finding.value_hash) == 64


def test_execute_plugin_pass_isolates_exception_raised_by_detect(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_RaisingRecognizer(), _AcmeRecognizer())

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("s.py"), registry)

    acme_findings = [f for f in findings if f.entity_type == _ACME_ENTITY_TYPE]
    assert len(acme_findings) == 1
    assert any("simulated plugin failure" in record.message for record in caplog.records)


def test_execute_plugin_pass_drops_finding_whose_end_offset_overruns_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_OffsetOverrunRecognizer())

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("s.py"), registry)

    assert findings == []
    assert any("end_offset" in record.message for record in caplog.records)


def test_execute_plugin_pass_drops_finding_with_undeclared_entity_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_UndeclaredEntityTypeRecognizer())

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("s.py"), registry)

    assert findings == []
    assert any("not declared in entity_types" in record.message for record in caplog.records)


def test_execute_plugin_pass_rate_limits_warnings_per_recognizer(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_RaisingRecognizer())
    content = "\n".join([_PLUGIN_SAMPLE_LINE] * _RATE_LIMIT_TEST_LINE_COUNT)

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        execute_plugin_pass(content, Path("s.py"), registry)

    per_line_records = [
        record for record in caplog.records if "simulated plugin failure" in record.message
    ]
    summary_records = [
        record
        for record in caplog.records
        if "produced" in record.message and "warnings" in record.message
    ]
    assert len(per_line_records) == _MAX_WARNINGS_PER_RECOGNIZER
    assert len(summary_records) == 1


def test_execute_plugin_pass_drops_non_list_return_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _ReturnsNoneRecognizer(BaseRecognizer):
        name = "returns_none"
        entity_types = ("NONE_TEST",)
        plugin_api_version = "1.0"

        def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
            return None  # type: ignore[return-value]

    registry = _build_registry(_ReturnsNoneRecognizer())

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("s.py"), registry)

    assert findings == []
    assert any("NoneType" in record.message for record in caplog.records)


def test_execute_plugin_pass_drops_list_entries_that_are_not_scan_findings(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _ReturnsWrongTypeRecognizer(BaseRecognizer):
        name = "returns_wrong_type"
        entity_types = ("WRONG_TYPE_TEST",)
        plugin_api_version = "1.0"

        def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
            return ["not a scan finding"]  # type: ignore[list-item]

    registry = _build_registry(_ReturnsWrongTypeRecognizer())

    with caplog.at_level(logging.WARNING, logger="phi_scan.plugin_runtime"):
        findings = execute_plugin_pass(_PLUGIN_SAMPLE_LINE, Path("s.py"), registry)

    assert findings == []
    assert any("expected ScanFinding" in record.message for record in caplog.records)


def test_execute_plugin_pass_sorts_findings_deterministically() -> None:
    content = "\n".join([_PLUGIN_SAMPLE_LINE, _PLUGIN_SAMPLE_LINE, _PLUGIN_SAMPLE_LINE])
    registry = _build_registry(_AcmeRecognizer())

    findings = execute_plugin_pass(content, Path("source.py"), registry)

    line_numbers = [finding.line_number for finding in findings]
    assert line_numbers == sorted(line_numbers)


# ---------------------------------------------------------------------------
# Scanner integration tests
# ---------------------------------------------------------------------------


def test_execute_scan_includes_plugin_findings(sample_file: Path, scan_config: ScanConfig) -> None:
    registry = _build_registry(_AcmeRecognizer())

    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        result = execute_scan([sample_file], scan_config)

    plugin_findings = [f for f in result.findings if f.detection_layer == DetectionLayer.PLUGIN]
    assert len(plugin_findings) == 1
    assert plugin_findings[0].entity_type == _ACME_ENTITY_TYPE


def test_execute_scan_without_plugins_produces_no_plugin_findings(
    sample_file: Path, scan_config: ScanConfig
) -> None:
    with patch("phi_scan.scanner.load_plugin_registry", return_value=PluginRegistry()):
        result = execute_scan([sample_file], scan_config)

    assert not any(f.detection_layer == DetectionLayer.PLUGIN for f in result.findings)


def test_execute_scan_loads_plugin_registry_exactly_once(
    tmp_path: Path, scan_config: ScanConfig
) -> None:
    registry = _build_registry(_AcmeRecognizer())
    for index in range(3):
        (tmp_path / f"file_{index}.py").write_text(_PLUGIN_SAMPLE_LINE + "\n", encoding="utf-8")
    scan_targets = sorted(tmp_path.glob("*.py"))

    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry) as mock_loader:
        execute_scan(scan_targets, scan_config)

    assert mock_loader.call_count == 1


def test_execute_scan_plugin_failure_does_not_abort_scan(
    sample_file: Path, scan_config: ScanConfig
) -> None:
    registry = _build_registry(_RaisingRecognizer(), _AcmeRecognizer())

    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        result = execute_scan([sample_file], scan_config)

    acme_findings = [f for f in result.findings if f.entity_type == _ACME_ENTITY_TYPE]
    assert len(acme_findings) == 1


def test_execute_scan_parallel_workers_match_sequential_with_plugins(
    tmp_path: Path, scan_config: ScanConfig
) -> None:
    for index in range(10):
        (tmp_path / f"file_{index}.py").write_text(_PLUGIN_SAMPLE_LINE + "\n", encoding="utf-8")
    scan_targets = sorted(tmp_path.glob("*.py"))
    registry = _build_registry(_AcmeRecognizer())

    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        sequential_result = execute_scan(scan_targets, scan_config, worker_count=1)
        _load_cached_plugin_registry.cache_clear()
        parallel_result = execute_scan(scan_targets, scan_config, worker_count=4)

    sequential_plugin_findings = sorted(
        (str(f.file_path), f.line_number, f.value_hash)
        for f in sequential_result.findings
        if f.detection_layer == DetectionLayer.PLUGIN
    )
    parallel_plugin_findings = sorted(
        (str(f.file_path), f.line_number, f.value_hash)
        for f in parallel_result.findings
        if f.detection_layer == DetectionLayer.PLUGIN
    )
    assert sequential_plugin_findings == parallel_plugin_findings
    assert len(sequential_plugin_findings) == 10


def test_execute_scan_plugin_findings_respect_confidence_threshold(
    sample_file: Path,
) -> None:
    registry = _build_registry(_AcmeRecognizer())
    config = ScanConfig(
        confidence_threshold=_CONFIDENCE_THRESHOLD_ABOVE_ACME,
        severity_threshold=SeverityLevel.INFO,
    )

    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        result = execute_scan([sample_file], config)

    plugin_findings = [f for f in result.findings if f.detection_layer == DetectionLayer.PLUGIN]
    assert plugin_findings == []
