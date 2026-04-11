# phi-scan:ignore-file
"""Golden contract tests for JSON, SARIF, CSV, and JUnit output formats (T6/T7).

These tests freeze the byte layout of the four output formats that downstream
CI/CD integrations, dashboards, and parsers depend on. Any intentional change
to serializer output must be accompanied by a regeneration of the goldens so
that the diff is explicit in review.

Scope split with ``tests/test_output_contracts.py``:

- ``test_output_contracts.py`` pins structural invariants (JSON key names,
  SARIF version string, CSV header order, exit codes).
- This module pins byte-exact output for a small set of handwritten
  ``ScanResult`` fixtures. A drift here means a consumer that pinned the
  exact layout of a field value or whitespace position would break.

Regenerating goldens
--------------------
When a serializer change is intentional, run::

    UPDATE_GOLDENS=1 uv run pytest tests/test_output_goldens.py

Every test will overwrite its stored golden with the live rendered output
and pass. Review the resulting diff under ``tests/fixtures/goldens/`` and
commit it together with the serializer change. A test that only passes
because its golden was silently overwritten is not a passing test — the
regeneration step is a human-in-the-loop gate.

Normalization
-------------
Only one field in the four target formats is truly volatile at render
time: SARIF's ``tool.driver.version``, which reads ``phi_scan.__version__``
through the serializer module binding. The rendering helper patches that
binding to the literal token ``<VERSION>`` before calling ``format_sarif``,
so goldens contain a stable token instead of a moving version string.

``scan_duration`` is hardcoded to ``0.0`` in every fixture so no duration
normalization is required. ``ScanFinding.file_path`` is already forced
relative by the model layer, so no path normalization is required.
``value_hash`` digests are derived from stable fixture inputs via
``_compute_fixture_hash_digest``, so fingerprints and hashes are
deterministic without any normalization.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    DEFAULT_TEXT_ENCODING,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.output.serializers import (
    format_csv,
    format_json,
    format_junit,
    format_sarif,
)

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

_GOLDEN_FIXTURE_ROOT: Path = Path(__file__).parent / "fixtures" / "goldens"

_UPDATE_GOLDENS_ENV_VAR: str = "UPDATE_GOLDENS"
_UPDATE_GOLDENS_ENABLED_VALUE: str = "1"

_VERSION_NORMALIZATION_TOKEN: str = "<VERSION>"
_SERIALIZER_VERSION_PATCH_TARGET: str = "phi_scan.output.serializers.__version__"

_FORMAT_NAME_JSON: str = "json"
_FORMAT_NAME_SARIF: str = "sarif"
_FORMAT_NAME_CSV: str = "csv"
_FORMAT_NAME_JUNIT: str = "junit"

_SCENARIO_CONTAINS_SSN: str = "contains_ssn"
_SCENARIO_CONTAINS_EMAIL: str = "contains_email"
_SCENARIO_CLEAN: str = "clean"
_SCENARIO_MULTI_FINDING: str = "multi_finding"

_GOLDEN_EXTENSION_BY_FORMAT: MappingProxyType[str, str] = MappingProxyType(
    {
        _FORMAT_NAME_JSON: ".json",
        _FORMAT_NAME_SARIF: ".sarif.json",
        _FORMAT_NAME_CSV: ".csv",
        _FORMAT_NAME_JUNIT: ".xml",
    }
)

_ENTITY_TYPE_SSN: str = "us_ssn"
_ENTITY_TYPE_EMAIL: str = "email_address"
_ENTITY_TYPE_PHONE: str = "phone_number"

_REMEDIATION_HINT_SSN: str = "Replace with a synthetic SSN from the reserved 999 range."
_REMEDIATION_HINT_EMAIL: str = "Use an example.com address from the RFC 2606 reserved list."
_REMEDIATION_HINT_PHONE: str = "Use a 555-0100 through 555-0199 fictional phone number."

_HIGH_SEVERITY_CONFIDENCE: float = 0.95
_MEDIUM_SEVERITY_CONFIDENCE: float = 0.75
_LOW_SEVERITY_CONFIDENCE: float = 0.65

_FIXTURE_SCAN_DURATION: float = 0.0
_FIXTURE_HASH_SEED_FORMAT: str = "phi-scan-golden:{entity_type}:{line_number}"

_HISTOGRAM_INITIAL_COUNT: int = 0
_HISTOGRAM_INCREMENT: int = 1


def _compute_fixture_hash_digest(entity_type: str, line_number: int) -> str:
    """Return a deterministic SHA-256 hex digest for a fixture finding.

    The seed is derived from non-PHI metadata (entity type and line number)
    so every test run produces the same digest without depending on any
    runtime state.
    """
    seed_string = _FIXTURE_HASH_SEED_FORMAT.format(
        entity_type=entity_type,
        line_number=line_number,
    )
    return hashlib.sha256(seed_string.encode(DEFAULT_TEXT_ENCODING)).hexdigest()


# ---------------------------------------------------------------------------
# Module-level finding constants
#
# ScanFinding is frozen, so shared module-level instances are safe. Line
# numbers, file paths, confidence scores, and remediation hints are all
# fixed so the derived hash digests and SARIF rule identifiers are stable.
# ---------------------------------------------------------------------------

_FINDING_SSN_CONTAINS_SSN_SCENARIO: ScanFinding = ScanFinding(
    file_path=Path("src/contains_ssn.py"),
    line_number=10,
    entity_type=_ENTITY_TYPE_SSN,
    hipaa_category=PhiCategory.SSN,
    confidence=_HIGH_SEVERITY_CONFIDENCE,
    detection_layer=DetectionLayer.REGEX,
    value_hash=_compute_fixture_hash_digest(_ENTITY_TYPE_SSN, 10),
    severity=SeverityLevel.HIGH,
    code_context=f"patient_ssn = {CODE_CONTEXT_REDACTED_VALUE}",
    remediation_hint=_REMEDIATION_HINT_SSN,
)

_FINDING_EMAIL_CONTAINS_EMAIL_SCENARIO: ScanFinding = ScanFinding(
    file_path=Path("src/contains_email.py"),
    line_number=12,
    entity_type=_ENTITY_TYPE_EMAIL,
    hipaa_category=PhiCategory.EMAIL,
    confidence=_MEDIUM_SEVERITY_CONFIDENCE,
    detection_layer=DetectionLayer.REGEX,
    value_hash=_compute_fixture_hash_digest(_ENTITY_TYPE_EMAIL, 12),
    severity=SeverityLevel.MEDIUM,
    code_context=f"contact_email = {CODE_CONTEXT_REDACTED_VALUE}",
    remediation_hint=_REMEDIATION_HINT_EMAIL,
)

_FINDING_SSN_MULTI_FINDING_SCENARIO: ScanFinding = ScanFinding(
    file_path=Path("src/a.py"),
    line_number=10,
    entity_type=_ENTITY_TYPE_SSN,
    hipaa_category=PhiCategory.SSN,
    confidence=_HIGH_SEVERITY_CONFIDENCE,
    detection_layer=DetectionLayer.REGEX,
    value_hash=_compute_fixture_hash_digest(_ENTITY_TYPE_SSN, 10),
    severity=SeverityLevel.HIGH,
    code_context=f"patient_ssn = {CODE_CONTEXT_REDACTED_VALUE}",
    remediation_hint=_REMEDIATION_HINT_SSN,
)

_FINDING_EMAIL_MULTI_FINDING_SCENARIO: ScanFinding = ScanFinding(
    file_path=Path("src/a.py"),
    line_number=42,
    entity_type=_ENTITY_TYPE_EMAIL,
    hipaa_category=PhiCategory.EMAIL,
    confidence=_MEDIUM_SEVERITY_CONFIDENCE,
    detection_layer=DetectionLayer.REGEX,
    value_hash=_compute_fixture_hash_digest(_ENTITY_TYPE_EMAIL, 42),
    severity=SeverityLevel.MEDIUM,
    code_context=f"contact_email = {CODE_CONTEXT_REDACTED_VALUE}",
    remediation_hint=_REMEDIATION_HINT_EMAIL,
)

_FINDING_PHONE_MULTI_FINDING_SCENARIO: ScanFinding = ScanFinding(
    file_path=Path("src/b.py"),
    line_number=5,
    entity_type=_ENTITY_TYPE_PHONE,
    hipaa_category=PhiCategory.PHONE,
    confidence=_LOW_SEVERITY_CONFIDENCE,
    detection_layer=DetectionLayer.REGEX,
    value_hash=_compute_fixture_hash_digest(_ENTITY_TYPE_PHONE, 5),
    severity=SeverityLevel.LOW,
    code_context=f"callback_number = {CODE_CONTEXT_REDACTED_VALUE}",
    remediation_hint=_REMEDIATION_HINT_PHONE,
)


# ---------------------------------------------------------------------------
# ScanResult builders — one per scenario
# ---------------------------------------------------------------------------


def _build_severity_counts_from_findings(
    findings: tuple[ScanFinding, ...],
) -> MappingProxyType[SeverityLevel, int]:
    """Return an immutable severity-level histogram over findings."""
    counts: dict[SeverityLevel, int] = {
        SeverityLevel.INFO: _HISTOGRAM_INITIAL_COUNT,
        SeverityLevel.LOW: _HISTOGRAM_INITIAL_COUNT,
        SeverityLevel.MEDIUM: _HISTOGRAM_INITIAL_COUNT,
        SeverityLevel.HIGH: _HISTOGRAM_INITIAL_COUNT,
    }
    for finding in findings:
        counts[finding.severity] += _HISTOGRAM_INCREMENT
    return MappingProxyType(counts)


def _build_category_counts_from_findings(
    findings: tuple[ScanFinding, ...],
) -> MappingProxyType[PhiCategory, int]:
    """Return an immutable PHI-category histogram over findings."""
    counts: dict[PhiCategory, int] = {}
    for finding in findings:
        previous_count = counts.get(finding.hipaa_category, _HISTOGRAM_INITIAL_COUNT)
        counts[finding.hipaa_category] = previous_count + _HISTOGRAM_INCREMENT
    return MappingProxyType(counts)


def _build_contains_ssn_scan_result() -> ScanResult:
    """Return the ScanResult for the contains_ssn scenario — one HIGH SSN finding."""
    findings: tuple[ScanFinding, ...] = (_FINDING_SSN_CONTAINS_SSN_SCENARIO,)
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=1,
        scan_duration=_FIXTURE_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.HIGH,
        severity_counts=_build_severity_counts_from_findings(findings),
        category_counts=_build_category_counts_from_findings(findings),
    )


def _build_contains_email_scan_result() -> ScanResult:
    """Return the ScanResult for the contains_email scenario — one MEDIUM email finding."""
    findings: tuple[ScanFinding, ...] = (_FINDING_EMAIL_CONTAINS_EMAIL_SCENARIO,)
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=1,
        scan_duration=_FIXTURE_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.MODERATE,
        severity_counts=_build_severity_counts_from_findings(findings),
        category_counts=_build_category_counts_from_findings(findings),
    )


def _build_clean_scan_result() -> ScanResult:
    """Return the ScanResult for the clean scenario — zero findings."""
    findings: tuple[ScanFinding, ...] = ()
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=0,
        scan_duration=_FIXTURE_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=_build_severity_counts_from_findings(findings),
        category_counts=_build_category_counts_from_findings(findings),
    )


def _build_multi_finding_scan_result() -> ScanResult:
    """Return the ScanResult for the multi_finding scenario — three findings across two files.

    Findings are pre-sorted in the stable order the serializer layer expects
    (file path then line number): SSN at src/a.py:10, EMAIL at src/a.py:42,
    PHONE at src/b.py:5. This exercises both within-file and cross-file
    ordering stability.
    """
    findings: tuple[ScanFinding, ...] = (
        _FINDING_SSN_MULTI_FINDING_SCENARIO,
        _FINDING_EMAIL_MULTI_FINDING_SCENARIO,
        _FINDING_PHONE_MULTI_FINDING_SCENARIO,
    )
    return ScanResult(
        findings=findings,
        files_scanned=2,
        files_with_findings=2,
        scan_duration=_FIXTURE_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.HIGH,
        severity_counts=_build_severity_counts_from_findings(findings),
        category_counts=_build_category_counts_from_findings(findings),
    )


# ---------------------------------------------------------------------------
# Dispatch tables and rendering helpers
# ---------------------------------------------------------------------------

_SCAN_RESULT_BUILDER_BY_SCENARIO: MappingProxyType[str, Callable[[], ScanResult]] = (
    MappingProxyType(
        {
            _SCENARIO_CONTAINS_SSN: _build_contains_ssn_scan_result,
            _SCENARIO_CONTAINS_EMAIL: _build_contains_email_scan_result,
            _SCENARIO_CLEAN: _build_clean_scan_result,
            _SCENARIO_MULTI_FINDING: _build_multi_finding_scan_result,
        }
    )
)

_FORMATTER_BY_FORMAT_NAME: MappingProxyType[str, Callable[[ScanResult], str]] = MappingProxyType(
    {
        _FORMAT_NAME_JSON: format_json,
        _FORMAT_NAME_SARIF: format_sarif,
        _FORMAT_NAME_CSV: format_csv,
        _FORMAT_NAME_JUNIT: format_junit,
    }
)

_ALL_SCENARIO_NAMES: tuple[str, ...] = (
    _SCENARIO_CONTAINS_SSN,
    _SCENARIO_CONTAINS_EMAIL,
    _SCENARIO_CLEAN,
    _SCENARIO_MULTI_FINDING,
)

_ALL_FORMAT_NAMES: tuple[str, ...] = (
    _FORMAT_NAME_JSON,
    _FORMAT_NAME_SARIF,
    _FORMAT_NAME_CSV,
    _FORMAT_NAME_JUNIT,
)


def _render_format_with_stable_version(
    scan_result: ScanResult,
    format_name: str,
) -> str:
    """Render a scan result in the requested format with SARIF version normalized.

    For every format except SARIF this is a direct dispatch. SARIF embeds the
    live ``phi_scan.__version__`` into ``tool.driver.version`` at render time,
    so the serializer-module binding is patched to ``<VERSION>`` for the
    duration of the call. The resulting golden contains the stable token
    instead of a moving version string.
    """
    formatter = _FORMATTER_BY_FORMAT_NAME[format_name]
    if format_name != _FORMAT_NAME_SARIF:
        return formatter(scan_result)
    with patch(_SERIALIZER_VERSION_PATCH_TARGET, new=_VERSION_NORMALIZATION_TOKEN):
        return formatter(scan_result)


def _resolve_golden_file_path(format_name: str, scenario_name: str) -> Path:
    """Return the filesystem path for the golden file of a (format, scenario) pair."""
    extension = _GOLDEN_EXTENSION_BY_FORMAT[format_name]
    return _GOLDEN_FIXTURE_ROOT / format_name / f"{scenario_name}{extension}"


def _is_golden_update_mode_enabled() -> bool:
    """Return True when the regeneration environment variable is set to the enabled value."""
    return os.environ.get(_UPDATE_GOLDENS_ENV_VAR) == _UPDATE_GOLDENS_ENABLED_VALUE


def _write_golden_file(golden_path: Path, rendered_text: str) -> None:
    """Overwrite the golden file at the given path with rendered_text.

    Writes bytes directly rather than text so that line-ending translation is
    never applied: the CSV serializer emits ``\\r\\n`` per RFC 4180 and text-mode
    reads apply universal-newlines translation, which would cause a spurious
    drift on every CSV comparison.
    """
    golden_path.parent.mkdir(parents=True, exist_ok=True)
    golden_path.write_bytes(rendered_text.encode(DEFAULT_TEXT_ENCODING))


def _assert_golden_file_matches_rendered_text(
    rendered_text: str,
    golden_path: Path,
) -> None:
    """Assert that the golden file at golden_path equals rendered_text byte-for-byte.

    Comparison is performed in bytes so that line-ending preservation is
    exact — see ``_write_golden_file`` for the CSV CRLF rationale.
    """
    assert golden_path.exists(), (
        f"golden file missing: {golden_path} — run "
        f"`{_UPDATE_GOLDENS_ENV_VAR}={_UPDATE_GOLDENS_ENABLED_VALUE} "
        f"uv run pytest tests/test_output_goldens.py` to create it"
    )
    expected_bytes = golden_path.read_bytes()
    rendered_bytes = rendered_text.encode(DEFAULT_TEXT_ENCODING)
    assert rendered_bytes == expected_bytes, (
        f"golden drift: {golden_path} does not match rendered output. "
        f"If this change is intentional, regenerate with "
        f"`{_UPDATE_GOLDENS_ENV_VAR}={_UPDATE_GOLDENS_ENABLED_VALUE} "
        f"uv run pytest tests/test_output_goldens.py`"
    )


# ---------------------------------------------------------------------------
# Parametrized golden contract test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_name", _ALL_SCENARIO_NAMES)
@pytest.mark.parametrize("format_name", _ALL_FORMAT_NAMES)
def test_output_format_matches_stored_golden_file(
    format_name: str,
    scenario_name: str,
) -> None:
    """Every (format, scenario) pair must render byte-exact to its stored golden file.

    In regular mode (default), the rendered output is compared against the
    stored golden and the test fails on any drift. In update mode
    (``UPDATE_GOLDENS=1``), the stored golden is overwritten with the live
    output and the test passes — used to regenerate goldens after an
    intentional serializer change.
    """
    scan_result = _SCAN_RESULT_BUILDER_BY_SCENARIO[scenario_name]()
    rendered_text = _render_format_with_stable_version(scan_result, format_name)
    golden_path = _resolve_golden_file_path(format_name, scenario_name)
    if _is_golden_update_mode_enabled():
        _write_golden_file(golden_path, rendered_text)
        return
    _assert_golden_file_matches_rendered_text(rendered_text, golden_path)
