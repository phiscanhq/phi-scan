"""Runtime execution tests for the Plugin API v1.1 suppressor hook.

Covers the suppressor pipeline stage: suppressors are consulted in
deterministic order, the first ``is_suppressed=True`` wins, exceptions
in ``evaluate`` are isolated per finding, malformed return values are
dropped with a warning, and the stage runs after inline suppression
but before the confidence/severity filters.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from phi_scan.constants import DetectionLayer, PhiCategory, SeverityLevel
from phi_scan.models import ScanConfig, ScanFinding
from phi_scan.plugin_api import (
    PLUGIN_API_VERSION,
    SUPPRESSOR_API_VERSION,
    BaseRecognizer,
    BaseSuppressor,
    ScanContext,
    SuppressDecision,
    SuppressorFindingView,
)
from phi_scan.plugin_api import ScanFinding as PluginScanFinding
from phi_scan.plugin_loader import LoadedPlugin, LoadedSuppressor, PluginRegistry
from phi_scan.scanner import _load_cached_plugin_registry, execute_scan
from phi_scan.suppressor_runtime import (
    _MAX_WARNINGS_PER_SUPPRESSOR,
    apply_suppressor_pass,
)

_SAMPLE_LINE: str = "employee_id = EMP-123456"
_SAMPLE_FILE_NAME: str = "source.py"
_EMP_ENTITY_TYPE: str = "ACME_EMPLOYEE_ID"
_EMP_RECOGNIZER_NAME: str = "acme_employee_id"
_EMP_CONFIDENCE: float = 0.9
_VALUE_HASH_STUB: str = "0" * 64
_REDACTED_CONTEXT_STUB: str = "employee_id = [REDACTED]"
_REMEDIATION_HINT_STUB: str = "Review the value."
_RATE_LIMIT_TEST_FINDING_COUNT: int = 20
_ZERO_CONFIDENCE: float = 0.0


def _build_finding(line_number: int = 1, entity_type: str = _EMP_ENTITY_TYPE) -> ScanFinding:
    return ScanFinding(
        file_path=Path(_SAMPLE_FILE_NAME),
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=PhiCategory.UNIQUE_ID,
        confidence=_EMP_CONFIDENCE,
        detection_layer=DetectionLayer.PLUGIN,
        value_hash=_VALUE_HASH_STUB,
        severity=SeverityLevel.MEDIUM,
        code_context=_REDACTED_CONTEXT_STUB,
        remediation_hint=_REMEDIATION_HINT_STUB,
    )


class _SuppressAllSuppressor(BaseSuppressor):
    name = "suppress_all"
    plugin_api_version = SUPPRESSOR_API_VERSION

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del finding, line
        return SuppressDecision(is_suppressed=True, reason="suppressed by test")


class _PassThroughSuppressor(BaseSuppressor):
    name = "pass_through"
    plugin_api_version = SUPPRESSOR_API_VERSION

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del finding, line
        return SuppressDecision(is_suppressed=False, reason="no opinion")


class _RaisingSuppressor(BaseSuppressor):
    name = "raising_suppressor"
    plugin_api_version = SUPPRESSOR_API_VERSION

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del finding, line
        raise RuntimeError("simulated suppressor failure")


class _MalformedReturnSuppressor(BaseSuppressor):
    name = "malformed_return"
    plugin_api_version = SUPPRESSOR_API_VERSION

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del finding, line
        return "not a decision"  # type: ignore[return-value]


class _OrderRecordingSuppressor(BaseSuppressor):
    """Records evaluation order in a class-level list for determinism tests."""

    name = "order_recorder"
    plugin_api_version = SUPPRESSOR_API_VERSION
    evaluation_log: list[str] = []

    def __init__(self, tag: str, is_suppressed: bool = False) -> None:
        self._tag = tag
        self._is_suppressed = is_suppressed

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del finding, line
        self.evaluation_log.append(self._tag)
        return SuppressDecision(is_suppressed=self._is_suppressed, reason=self._tag)


def _build_registry(*suppressors: BaseSuppressor) -> PluginRegistry:
    loaded_suppressors = tuple(
        LoadedSuppressor(
            entry_point_name=suppressor.name,
            distribution_name=f"{suppressor.name}-dist",
            suppressor=suppressor,
        )
        for suppressor in suppressors
    )
    return PluginRegistry(loaded_suppressors=loaded_suppressors)


# ---------------------------------------------------------------------------
# Type-signature sanity
# ---------------------------------------------------------------------------


def test_suppress_decision_is_frozen_dataclass() -> None:
    decision = SuppressDecision(is_suppressed=True, reason="why")
    with pytest.raises(Exception):
        decision.reason = "mutated"  # type: ignore[misc]


def test_finding_view_exposes_plugin_stable_fields() -> None:
    view = SuppressorFindingView(
        entity_type="EMAIL_ADDRESS",
        confidence=0.8,
        line_number=3,
        file_path=Path("a.py"),
        file_extension=".py",
    )
    assert view.entity_type == "EMAIL_ADDRESS"
    assert view.confidence == 0.8


def test_base_suppressor_defaults_to_suppressor_api_version() -> None:
    assert _SuppressAllSuppressor.plugin_api_version == SUPPRESSOR_API_VERSION


# ---------------------------------------------------------------------------
# apply_suppressor_pass unit behaviour
# ---------------------------------------------------------------------------


def test_apply_suppressor_pass_returns_input_when_no_suppressors_loaded() -> None:
    findings = [_build_finding()]
    result = apply_suppressor_pass(findings, PluginRegistry(), _SAMPLE_LINE)
    assert result == findings


def test_apply_suppressor_pass_drops_finding_when_any_suppressor_says_suppress() -> None:
    registry = _build_registry(_SuppressAllSuppressor())
    result = apply_suppressor_pass([_build_finding()], registry, _SAMPLE_LINE)
    assert result == []


def test_apply_suppressor_pass_retains_finding_when_all_suppressors_pass_through() -> None:
    registry = _build_registry(_PassThroughSuppressor())
    findings = [_build_finding()]
    result = apply_suppressor_pass(findings, registry, _SAMPLE_LINE)
    assert result == findings


def test_apply_suppressor_pass_first_suppressor_decision_wins() -> None:
    _OrderRecordingSuppressor.evaluation_log = []
    first = _OrderRecordingSuppressor(tag="first", is_suppressed=True)
    second = _OrderRecordingSuppressor(tag="second", is_suppressed=False)
    registry = _build_registry(first, second)
    apply_suppressor_pass([_build_finding()], registry, _SAMPLE_LINE)
    assert _OrderRecordingSuppressor.evaluation_log == ["first"]


def test_apply_suppressor_pass_consults_all_when_none_suppress() -> None:
    _OrderRecordingSuppressor.evaluation_log = []
    first = _OrderRecordingSuppressor(tag="first", is_suppressed=False)
    second = _OrderRecordingSuppressor(tag="second", is_suppressed=False)
    registry = _build_registry(first, second)
    apply_suppressor_pass([_build_finding()], registry, _SAMPLE_LINE)
    assert _OrderRecordingSuppressor.evaluation_log == ["first", "second"]


def test_apply_suppressor_pass_preserves_registry_order_across_findings() -> None:
    _OrderRecordingSuppressor.evaluation_log = []
    first = _OrderRecordingSuppressor(tag="a", is_suppressed=False)
    second = _OrderRecordingSuppressor(tag="b", is_suppressed=False)
    registry = _build_registry(first, second)
    apply_suppressor_pass(
        [_build_finding(line_number=1), _build_finding(line_number=2)],
        registry,
        _SAMPLE_LINE,
    )
    assert _OrderRecordingSuppressor.evaluation_log == ["a", "b", "a", "b"]


# ---------------------------------------------------------------------------
# Isolation semantics
# ---------------------------------------------------------------------------


def test_raising_suppressor_does_not_abort_scan(caplog: pytest.LogCaptureFixture) -> None:
    registry = _build_registry(_RaisingSuppressor())
    with caplog.at_level(logging.WARNING, logger="phi_scan.suppressor_runtime"):
        result = apply_suppressor_pass([_build_finding()], registry, _SAMPLE_LINE)
    assert len(result) == 1
    assert any("simulated suppressor failure" in record.message for record in caplog.records)


def test_raising_suppressor_does_not_block_later_suppressor_that_suppresses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_RaisingSuppressor(), _SuppressAllSuppressor())
    with caplog.at_level(logging.WARNING, logger="phi_scan.suppressor_runtime"):
        result = apply_suppressor_pass([_build_finding()], registry, _SAMPLE_LINE)
    assert result == []


def test_malformed_return_value_is_treated_as_pass_through(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = _build_registry(_MalformedReturnSuppressor())
    findings = [_build_finding()]
    with caplog.at_level(logging.WARNING, logger="phi_scan.suppressor_runtime"):
        result = apply_suppressor_pass(findings, registry, _SAMPLE_LINE)
    assert result == findings
    assert any("instead of SuppressDecision" in record.message for record in caplog.records)


def test_warnings_are_rate_limited_per_suppressor(caplog: pytest.LogCaptureFixture) -> None:
    registry = _build_registry(_RaisingSuppressor())
    findings = [_build_finding(line_number=i + 1) for i in range(_RATE_LIMIT_TEST_FINDING_COUNT)]
    with caplog.at_level(logging.WARNING, logger="phi_scan.suppressor_runtime"):
        apply_suppressor_pass(findings, registry, _SAMPLE_LINE)
    per_finding_records = [
        record for record in caplog.records if "simulated suppressor failure" in record.message
    ]
    summary_records = [
        record
        for record in caplog.records
        if "produced" in record.message and "warnings" in record.message
    ]
    assert len(per_finding_records) == _MAX_WARNINGS_PER_SUPPRESSOR
    assert len(summary_records) == 1


# ---------------------------------------------------------------------------
# Pipeline integration — confirms position before confidence/severity gates
# ---------------------------------------------------------------------------


class _EmpRecognizer(BaseRecognizer):
    name = _EMP_RECOGNIZER_NAME
    entity_types = (_EMP_ENTITY_TYPE,)
    plugin_api_version = PLUGIN_API_VERSION

    def detect(self, line: str, context: ScanContext) -> list[PluginScanFinding]:
        del context
        match = re.search(r"\bEMP-\d{6}\b", line)
        if match is None:
            return []
        return [
            PluginScanFinding(
                entity_type=_EMP_ENTITY_TYPE,
                start_offset=match.start(),
                end_offset=match.end(),
                confidence=_EMP_CONFIDENCE,
            )
        ]


class _DropEmpSuppressor(BaseSuppressor):
    name = "drop_emp"
    plugin_api_version = SUPPRESSOR_API_VERSION

    def evaluate(self, finding: SuppressorFindingView, line: str) -> SuppressDecision:
        del line
        return SuppressDecision(
            is_suppressed=finding.entity_type == _EMP_ENTITY_TYPE,
            reason="drop EMP",
        )


@pytest.fixture(autouse=True)
def _clear_scan_registry_cache() -> Iterator[None]:
    _load_cached_plugin_registry.cache_clear()
    yield
    _load_cached_plugin_registry.cache_clear()


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    target = tmp_path / _SAMPLE_FILE_NAME
    target.write_text(_SAMPLE_LINE + "\n", encoding="utf-8")
    return target


@pytest.fixture
def permissive_scan_config() -> ScanConfig:
    return ScanConfig(confidence_threshold=_ZERO_CONFIDENCE, severity_threshold=SeverityLevel.INFO)


def test_suppressor_runs_before_confidence_filter(
    sample_file: Path, permissive_scan_config: ScanConfig
) -> None:
    """A finding dropped by a suppressor never reaches confidence/severity gates."""
    registry = PluginRegistry(
        loaded=(
            LoadedPlugin(
                entry_point_name=_EMP_RECOGNIZER_NAME,
                distribution_name="acme-dist",
                recognizer=_EmpRecognizer(),
            ),
        ),
        loaded_suppressors=(
            LoadedSuppressor(
                entry_point_name="drop_emp",
                distribution_name="drop-dist",
                suppressor=_DropEmpSuppressor(),
            ),
        ),
    )
    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        result = execute_scan([sample_file], permissive_scan_config)
    plugin_findings = [f for f in result.findings if f.detection_layer == DetectionLayer.PLUGIN]
    assert plugin_findings == []


def test_suppressor_pipeline_is_no_op_without_suppressors(
    sample_file: Path, permissive_scan_config: ScanConfig
) -> None:
    """Existing v1.0 recognizer-only behaviour is preserved."""
    registry = PluginRegistry(
        loaded=(
            LoadedPlugin(
                entry_point_name=_EMP_RECOGNIZER_NAME,
                distribution_name="acme-dist",
                recognizer=_EmpRecognizer(),
            ),
        ),
    )
    with patch("phi_scan.scanner.load_plugin_registry", return_value=registry):
        result = execute_scan([sample_file], permissive_scan_config)
    plugin_findings = [f for f in result.findings if f.detection_layer == DetectionLayer.PLUGIN]
    assert len(plugin_findings) == 1
