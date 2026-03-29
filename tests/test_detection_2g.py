"""Phase 2G — Detection Testing.

Fixture-based scanning (2G.1 / 2G.2 / 2G.4), confidence → severity mapping
(2G.5), performance benchmarks (2G.6), and variable-name boosting integration
(2G.7).

Tasks 2G.8–2G.12 are covered by tests/test_fixer.py.
Task 2G.13 is covered by tests/test_nlp_detector.py (graceful-degradation tests).
Task 2G.14 is covered by tests/test_integration.py (end-to-end pipeline).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from phi_scan.constants import (
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_SCORE_MAXIMUM,
    VARIABLE_CONTEXT_CONFIDENCE_BOOST,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.detection_coordinator import detect_phi_in_text_content
from phi_scan.hashing import severity_from_confidence
from phi_scan.models import ScanConfig, ScanFinding
from phi_scan.scanner import collect_scan_targets, execute_scan, scan_file

# ---------------------------------------------------------------------------
# NLP availability guard — skip NLP-dependent tests when presidio is absent
# ---------------------------------------------------------------------------

try:
    from presidio_analyzer import AnalyzerEngine as _AnalyzerEngine  # noqa: F401

    _IS_NLP_AVAILABLE: bool = True
except ImportError:
    _IS_NLP_AVAILABLE = False

# Reason string extracted so the skipif decorator contains no string literals.
_NLP_SKIP_REASON: str = "presidio_analyzer not installed — run 'pip install phi-scan[nlp]'"

_requires_nlp = pytest.mark.skipif(not _IS_NLP_AVAILABLE, reason=_NLP_SKIP_REASON)

# ---------------------------------------------------------------------------
# Fixture corpus paths and manifest
# ---------------------------------------------------------------------------

_FIXTURE_ROOT: Path = Path(__file__).parent / "fixtures"
_PHI_FIXTURE_DIR: Path = _FIXTURE_ROOT / "phi"
_CLEAN_FIXTURE_DIR: Path = _FIXTURE_ROOT / "clean"
_MANIFEST_PATH: Path = _FIXTURE_ROOT / "manifest.json"

_FIXTURE_MANIFEST: dict[str, Any] = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))

_PHI_FIXTURE_ENTRIES: list[dict[str, Any]] = [
    entry for entry in _FIXTURE_MANIFEST["fixtures"] if entry["category"] == "phi"
]
_CLEAN_FIXTURE_ENTRIES: list[dict[str, Any]] = [
    entry for entry in _FIXTURE_MANIFEST["fixtures"] if entry["category"] == "clean"
]

# Manifest JSON keys — no string literals in logic
_MANIFEST_KEY_PATH: str = "path"
_MANIFEST_KEY_EXPECTED_MIN_FINDINGS: str = "expected_min_findings"
_MANIFEST_KEY_NOTES: str = "notes"

# Fixture note substring that marks NLP-only fixtures
_NLP_REQUIRED_NOTE: str = "NLP layer required"

# Filename of the names fixture — used by the NLP-layer test
_NAMES_FIXTURE_FILE_NAME: str = "names.py"

# ---------------------------------------------------------------------------
# Scan configuration constants
# ---------------------------------------------------------------------------

# Low threshold used for fixture detection tests — ensures all layers are evaluated.
_LOW_CONFIDENCE_THRESHOLD: float = 0.3

# ---------------------------------------------------------------------------
# Nested directory test content constants
# ---------------------------------------------------------------------------

_NESTED_DIR_PARTS: tuple[str, ...] = ("depth_a", "depth_b", "depth_c")
_NESTED_DEEP_DIR_PARTS: tuple[str, ...] = ("depth_a", "depth_b", "depth_c", "depth_d")

# Synthetic file content used as scanner input — values are provably fictional.
# SSN 321-54-9870 is outside all reserved ranges and has no real-world equivalent.
_NESTED_SSN_FILE_CONTENT: str = 'patient_ssn = "321-54-9870"\n'

# Email uses hospital-records.org (non-documentation domain) — triggers the regex
# layer. Documentation domains (example.com, example.org, test.com) are excluded
# by the email pattern to reduce false positives on fixture comments.
# Value is provably fictional — no such domain is operated for patient records.
_NESTED_EMAIL_FILE_CONTENT: str = 'contact_email = "patient@hospital-records.org"\n'

_NESTED_PYTHON_EXTENSION: str = ".py"

# ---------------------------------------------------------------------------
# Variable-context boosting test content constants
# ---------------------------------------------------------------------------

# ISO date that the regex layer detects as DATE.
_DATE_VALUE: str = "1978-11-23"

# Assignment with a PHI-suggestive variable name → triggers VARIABLE_CONTEXT_CONFIDENCE_BOOST.
# "dob" is in PHI_SUGGESTIVE_VARIABLE_PATTERNS.
_BOOSTED_DATE_LINE: str = f'patient_dob = "{_DATE_VALUE}"\n'

# Assignment with a non-suggestive variable name → no confidence boost.
_UNBOOSTED_DATE_LINE: str = f'config_value = "{_DATE_VALUE}"\n'

_DATE_ENTITY_TYPE: str = "DATE"

# Baseline confidence the DATE regex layer assigns before any variable-name boost.
# Used in the cap test to confirm base + boost exceeds CONFIDENCE_SCORE_MAXIMUM.
_DATE_REGEX_BASELINE_CONFIDENCE: float = 0.88

# Prefix prepended to the fixture notes string when skipping an NLP-only fixture.
_NLP_SKIP_MESSAGE_PREFIX: str = "NLP required — "

# ---------------------------------------------------------------------------
# Confidence → severity band boundary values
# ---------------------------------------------------------------------------

# Step used to place boundary test scores just below a floor constant.
# Small enough to stay within the same band, large enough to remain representable
# as a float without rounding issues.
_CONFIDENCE_BOUNDARY_STEP: float = 0.01

# A score below all named bands → INFO.
_CONFIDENCE_BELOW_LOW_FLOOR: float = CONFIDENCE_LOW_FLOOR - _CONFIDENCE_BOUNDARY_STEP

# ---------------------------------------------------------------------------
# Clean-fixture false-positive check: categories that must be absent
# ---------------------------------------------------------------------------

# The clean fixtures (no_phi, ssn_reserved, version_numbers) must never produce
# findings for these specific HIPAA categories. Other categories (e.g. health_plan)
# may fire on comment-line tokens and are tracked separately as known noisy patterns.
_STRICT_FALSE_POSITIVE_CATEGORIES: frozenset[PhiCategory] = frozenset(
    {
        PhiCategory.SSN,
        PhiCategory.EMAIL,
        PhiCategory.PHONE,
    }
)

# ---------------------------------------------------------------------------
# Performance benchmark constants
# ---------------------------------------------------------------------------

_BENCHMARK_FILE_COUNT: int = 1000
_BENCHMARK_TIME_BUDGET_SECONDS: float = 120.0
_BENCHMARK_SUBDIR_COUNT: int = 10
_BENCHMARK_FILES_PER_DIR: int = 100
_BENCHMARK_SUBDIR_NAME_PREFIX: str = "pkg_"
_BENCHMARK_SUBDIR_INDEX_FORMAT: str = "02d"
_BENCHMARK_FILE_NAME_PREFIX: str = "module_"
_BENCHMARK_FILE_INDEX_FORMAT: str = "03d"
_BENCHMARK_CLEAN_FILE_CONTENT: str = "x = 1\n"

# ---------------------------------------------------------------------------
# FHIR resource type test constants (2G.3)
#
# Synthetic PHI fixture: All field values below are fictional and exist solely
# to exercise the FHIR R4 pattern scanner. No real patient or provider data is
# used. All names, dates, and identifiers are invented.
#
# Security note: detect_phi_in_text_content executes entirely locally — it
# delegates only to the regex layer, local spaCy NLP, and FHIR regex patterns.
# No content is forwarded to any external API or cloud service. This is a
# non-negotiable design constraint enforced by the scanner architecture.
# ---------------------------------------------------------------------------

_FHIR_PATIENT_JSON: str = (
    '{"resourceType": "Patient", "name": [{"family": "Doe", "given": ["John"]}], '
    '"birthDate": "1978-11-23", "address": [{"city": "Springfield", "postalCode": "62701"}]}'
)

_FHIR_OBSERVATION_JSON: str = (
    '{"resourceType": "Observation", "effectiveDateTime": "2024-01-15T10:00:00Z", '
    '"subject": {"reference": "Patient/example"}}'
)

# Synthetic NPI value intentionally omits Luhn check digit validation —
# it is structurally representative but will not resolve to any real provider.
_FHIR_PRACTITIONER_JSON: str = (
    '{"resourceType": "Practitioner", "name": [{"family": "Smith", "given": ["Jane"]}], '
    '"identifier": [{"system": "http://hl7.org/fhir/sid/us-npi", "npi": "1234567890"}]}'
)

_FHIR_CONDITION_JSON: str = (
    '{"resourceType": "Condition", "onsetDateTime": "2023-06-15", '
    '"recordedDate": "2023-06-16", "subject": {"reference": "Patient/example"}}'
)

_FHIR_ENCOUNTER_JSON: str = (
    '{"resourceType": "Encounter", "subject": {"reference": "Patient/example"}, '
    '"participant": [{"individual": {"reference": "Practitioner/example"}}]}'
)

_FHIR_ALLERGY_JSON: str = (
    '{"resourceType": "AllergyIntolerance", "patient": {"reference": "Patient/example"}, '
    '"recordedDate": "2024-03-01"}'
)

# ---------------------------------------------------------------------------
# 2G.1 — Nested directory dataset
# ---------------------------------------------------------------------------


def test_scan_discovers_files_at_depth_three(tmp_path: Path) -> None:
    """Files nested three directory levels deep are returned by collect_scan_targets."""
    nested_dir = tmp_path.joinpath(*_NESTED_DIR_PARTS)
    nested_dir.mkdir(parents=True)
    nested_file = nested_dir / f"phi{_NESTED_PYTHON_EXTENSION}"
    nested_file.write_text(_NESTED_SSN_FILE_CONTENT, encoding="utf-8")

    config = ScanConfig()
    scan_targets = collect_scan_targets(tmp_path, [], config)

    assert nested_file in scan_targets


def test_scan_discovers_files_at_depth_four(tmp_path: Path) -> None:
    """Files nested four directory levels deep are returned by collect_scan_targets."""
    nested_dir = tmp_path.joinpath(*_NESTED_DEEP_DIR_PARTS)
    nested_dir.mkdir(parents=True)
    nested_file = nested_dir / f"email_phi{_NESTED_PYTHON_EXTENSION}"
    nested_file.write_text(_NESTED_EMAIL_FILE_CONTENT, encoding="utf-8")

    config = ScanConfig()
    scan_targets = collect_scan_targets(tmp_path, [], config)

    assert nested_file in scan_targets


def test_scan_finds_phi_in_deeply_nested_file(tmp_path: Path) -> None:
    """execute_scan returns findings from files at depth three."""
    nested_dir = tmp_path.joinpath(*_NESTED_DIR_PARTS)
    nested_dir.mkdir(parents=True)
    (nested_dir / f"phi{_NESTED_PYTHON_EXTENSION}").write_text(
        _NESTED_SSN_FILE_CONTENT, encoding="utf-8"
    )

    config = ScanConfig(confidence_threshold=_LOW_CONFIDENCE_THRESHOLD)
    scan_targets = collect_scan_targets(tmp_path, [], config)
    depth_three_ssn_report = execute_scan(scan_targets, config)

    ssn_findings = [
        f for f in depth_three_ssn_report.findings if f.hipaa_category == PhiCategory.SSN
    ]
    assert len(ssn_findings) >= 1


def test_scan_finds_phi_in_multiple_nested_depths(tmp_path: Path) -> None:
    """Findings are aggregated from files at depth 3 and depth 4 simultaneously."""
    depth_three_dir = tmp_path.joinpath(*_NESTED_DIR_PARTS)
    depth_three_dir.mkdir(parents=True)
    (depth_three_dir / f"ssn{_NESTED_PYTHON_EXTENSION}").write_text(
        _NESTED_SSN_FILE_CONTENT, encoding="utf-8"
    )

    depth_four_dir = depth_three_dir / _NESTED_DEEP_DIR_PARTS[-1]
    depth_four_dir.mkdir()
    (depth_four_dir / f"email{_NESTED_PYTHON_EXTENSION}").write_text(
        _NESTED_EMAIL_FILE_CONTENT, encoding="utf-8"
    )

    config = ScanConfig(confidence_threshold=_LOW_CONFIDENCE_THRESHOLD)
    scan_targets = collect_scan_targets(tmp_path, [], config)
    multi_depth_findings_report = execute_scan(scan_targets, config)

    file_paths_with_findings = {f.file_path for f in multi_depth_findings_report.findings}
    assert len(file_paths_with_findings) >= 2


# ---------------------------------------------------------------------------
# 2G.2 — PHI fixture detection (parametrized)
# ---------------------------------------------------------------------------


def _is_nlp_only_fixture(fixture_entry: dict[str, Any]) -> bool:
    """Return True when the fixture notes indicate NLP is required for detection."""
    notes = fixture_entry.get(_MANIFEST_KEY_NOTES, "")
    return _NLP_REQUIRED_NOTE in notes


def _format_phi_fixture_id(fixture_entry: dict[str, Any]) -> str:
    """Return the fixture filename stem as the parametrize ID."""
    return Path(fixture_entry[_MANIFEST_KEY_PATH]).stem


@pytest.mark.parametrize(
    "fixture_entry",
    _PHI_FIXTURE_ENTRIES,
    ids=[_format_phi_fixture_id(e) for e in _PHI_FIXTURE_ENTRIES],
)
def test_phi_fixture_produces_minimum_expected_findings(
    fixture_entry: dict[str, Any],
) -> None:
    """Each PHI fixture produces at least expected_min_findings total findings.

    NLP-only fixtures are skipped when the NLP layer is unavailable.
    """
    if _is_nlp_only_fixture(fixture_entry) and not _IS_NLP_AVAILABLE:
        pytest.skip(f"{_NLP_SKIP_MESSAGE_PREFIX}{fixture_entry[_MANIFEST_KEY_NOTES]!r}")

    fixture_path = _FIXTURE_ROOT / fixture_entry[_MANIFEST_KEY_PATH]
    expected_minimum = fixture_entry[_MANIFEST_KEY_EXPECTED_MIN_FINDINGS]
    config = ScanConfig(confidence_threshold=_LOW_CONFIDENCE_THRESHOLD)

    findings = scan_file(fixture_path, config)

    assert len(findings) >= expected_minimum, (
        f"{fixture_path.name}: expected >= {expected_minimum} findings, got {len(findings)}"
    )


# ---------------------------------------------------------------------------
# 2G.3 — FHIR resource type detection
# ---------------------------------------------------------------------------


def test_fhir_patient_resource_produces_phi_findings() -> None:
    """Patient FHIR resource JSON produces at least one PHI finding."""
    findings = detect_phi_in_text_content(_FHIR_PATIENT_JSON, Path("patient.json"))

    assert len(findings) >= 1


def test_fhir_patient_resource_detects_name_field() -> None:
    """family/given fields in a Patient FHIR resource are detected."""
    findings = detect_phi_in_text_content(_FHIR_PATIENT_JSON, Path("patient.json"))

    name_findings = [f for f in findings if f.hipaa_category == PhiCategory.NAME]
    assert len(name_findings) >= 1


def test_fhir_patient_resource_detects_birth_date() -> None:
    """birthDate field in a Patient FHIR resource is detected."""
    findings = detect_phi_in_text_content(_FHIR_PATIENT_JSON, Path("patient.json"))

    date_findings = [f for f in findings if f.hipaa_category == PhiCategory.DATE]
    assert len(date_findings) >= 1


def test_fhir_observation_resource_produces_phi_findings() -> None:
    """Observation FHIR resource JSON with effectiveDateTime produces a PHI finding."""
    findings = detect_phi_in_text_content(_FHIR_OBSERVATION_JSON, Path("observation.json"))

    assert len(findings) >= 1


def test_fhir_condition_resource_detects_onset_date() -> None:
    """Condition FHIR resource JSON with onsetDateTime produces a DATE finding."""
    findings = detect_phi_in_text_content(_FHIR_CONDITION_JSON, Path("condition.json"))

    date_findings = [f for f in findings if f.hipaa_category == PhiCategory.DATE]
    assert len(date_findings) >= 1


def test_fhir_practitioner_resource_detects_name() -> None:
    """Practitioner FHIR resource JSON produces at least one finding."""
    findings = detect_phi_in_text_content(_FHIR_PRACTITIONER_JSON, Path("practitioner.json"))

    assert len(findings) >= 1


def test_fhir_allergy_resource_detects_recorded_date() -> None:
    """AllergyIntolerance FHIR resource with recordedDate produces a DATE finding."""
    findings = detect_phi_in_text_content(_FHIR_ALLERGY_JSON, Path("allergy.json"))

    date_findings = [f for f in findings if f.hipaa_category == PhiCategory.DATE]
    assert len(date_findings) >= 1


# ---------------------------------------------------------------------------
# 2G.4 — False positive rate on clean fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_entry",
    _CLEAN_FIXTURE_ENTRIES,
    ids=[_format_phi_fixture_id(e) for e in _CLEAN_FIXTURE_ENTRIES],
)
@pytest.mark.parametrize(
    "guarded_category",
    list(_STRICT_FALSE_POSITIVE_CATEGORIES),
    ids=[cat.value for cat in _STRICT_FALSE_POSITIVE_CATEGORIES],
)
def test_clean_fixture_produces_no_findings_for_category(
    fixture_entry: dict[str, Any],
    guarded_category: PhiCategory,
) -> None:
    """Clean fixture produces zero findings for the guarded PHI category.

    High false-positive categories (health_plan, unique_id) are excluded from
    the guard — they fire on comment-line tokens and are a known limitation
    tracked separately. The categories that must be zero are SSN, EMAIL, PHONE.
    """
    fixture_path = _FIXTURE_ROOT / fixture_entry[_MANIFEST_KEY_PATH]
    config = ScanConfig()

    findings = scan_file(fixture_path, config)

    category_findings = [f for f in findings if f.hipaa_category == guarded_category]
    assert category_findings == [], (
        f"{fixture_path.name}: found {len(category_findings)} unexpected "
        f"{guarded_category.value!r} findings"
    )


# ---------------------------------------------------------------------------
# 2G.5 — Confidence → severity mapping
# ---------------------------------------------------------------------------


def test_confidence_at_high_floor_produces_high_severity() -> None:
    """A confidence at CONFIDENCE_HIGH_FLOOR maps to SeverityLevel.HIGH."""
    mapped_severity = severity_from_confidence(CONFIDENCE_HIGH_FLOOR)

    assert mapped_severity == SeverityLevel.HIGH


def test_confidence_at_maximum_produces_high_severity() -> None:
    """A confidence of CONFIDENCE_SCORE_MAXIMUM maps to SeverityLevel.HIGH."""
    mapped_severity = severity_from_confidence(CONFIDENCE_SCORE_MAXIMUM)

    assert mapped_severity == SeverityLevel.HIGH


def test_confidence_at_medium_floor_produces_medium_severity() -> None:
    """A confidence at CONFIDENCE_MEDIUM_FLOOR maps to SeverityLevel.MEDIUM."""
    mapped_severity = severity_from_confidence(CONFIDENCE_MEDIUM_FLOOR)

    assert mapped_severity == SeverityLevel.MEDIUM


def test_confidence_just_below_high_floor_produces_medium_severity() -> None:
    """A confidence just below CONFIDENCE_HIGH_FLOOR maps to SeverityLevel.MEDIUM."""
    just_below_high = CONFIDENCE_HIGH_FLOOR - _CONFIDENCE_BOUNDARY_STEP

    mapped_severity = severity_from_confidence(just_below_high)

    assert mapped_severity == SeverityLevel.MEDIUM


def test_confidence_at_low_floor_produces_low_severity() -> None:
    """A confidence at CONFIDENCE_LOW_FLOOR maps to SeverityLevel.LOW."""
    mapped_severity = severity_from_confidence(CONFIDENCE_LOW_FLOOR)

    assert mapped_severity == SeverityLevel.LOW


def test_confidence_just_below_medium_floor_produces_low_severity() -> None:
    """A confidence just below CONFIDENCE_MEDIUM_FLOOR maps to SeverityLevel.LOW."""
    just_below_medium = CONFIDENCE_MEDIUM_FLOOR - _CONFIDENCE_BOUNDARY_STEP

    mapped_severity = severity_from_confidence(just_below_medium)

    assert mapped_severity == SeverityLevel.LOW


def test_confidence_below_low_floor_produces_info_severity() -> None:
    """A confidence below CONFIDENCE_LOW_FLOOR maps to SeverityLevel.INFO."""
    mapped_severity = severity_from_confidence(_CONFIDENCE_BELOW_LOW_FLOOR)

    assert mapped_severity == SeverityLevel.INFO


def test_scan_finding_severity_matches_confidence_band(tmp_path: Path) -> None:
    """A finding produced by scan_file has severity consistent with its confidence band.

    Writes a file containing a known SSN value. The regex layer assigns confidence
    in [CONFIDENCE_REGEX_MIN, CONFIDENCE_SCORE_MAXIMUM], which maps to HIGH severity.
    """
    phi_file = tmp_path / "test.py"
    phi_file.write_text(_NESTED_SSN_FILE_CONTENT, encoding="utf-8")

    config = ScanConfig(confidence_threshold=_LOW_CONFIDENCE_THRESHOLD)
    findings = scan_file(phi_file, config)

    ssn_findings = [f for f in findings if f.hipaa_category == PhiCategory.SSN]
    assert len(ssn_findings) >= 1
    for finding in ssn_findings:
        expected_severity = severity_from_confidence(finding.confidence)
        assert finding.severity == expected_severity


# ---------------------------------------------------------------------------
# 2G.6 — Performance benchmark: 1 000-file synthetic repo
# ---------------------------------------------------------------------------


def _write_benchmark_files_to_directory(target_directory: Path) -> None:
    """Write BENCHMARK_FILES_PER_DIR clean Python files into target_directory."""
    for file_index in range(_BENCHMARK_FILES_PER_DIR):
        file_name = f"{_BENCHMARK_FILE_NAME_PREFIX}{file_index:{_BENCHMARK_FILE_INDEX_FORMAT}}.py"
        file_path = target_directory / file_name
        file_path.write_text(_BENCHMARK_CLEAN_FILE_CONTENT, encoding="utf-8")


def _build_benchmark_repository(root: Path) -> None:
    """Populate root with BENCHMARK_FILE_COUNT clean Python files across flat subdirectories."""
    for subdir_index in range(_BENCHMARK_SUBDIR_COUNT):
        subdir_index_str = format(subdir_index, _BENCHMARK_SUBDIR_INDEX_FORMAT)
        subdir = root / (_BENCHMARK_SUBDIR_NAME_PREFIX + subdir_index_str)
        subdir.mkdir()
        _write_benchmark_files_to_directory(subdir)


def test_scan_1000_clean_files_within_time_budget(tmp_path: Path) -> None:
    """Scanning 1000 clean files completes within BENCHMARK_TIME_BUDGET_SECONDS seconds."""
    _build_benchmark_repository(tmp_path)

    config = ScanConfig()
    scan_targets = collect_scan_targets(tmp_path, [], config)

    assert len(scan_targets) == _BENCHMARK_FILE_COUNT

    start_time = time.monotonic()
    benchmark_scan_report = execute_scan(scan_targets, config)
    elapsed_seconds = time.monotonic() - start_time

    assert benchmark_scan_report.files_scanned == _BENCHMARK_FILE_COUNT
    assert elapsed_seconds < _BENCHMARK_TIME_BUDGET_SECONDS, (
        f"Benchmark exceeded budget: {elapsed_seconds:.1f}s > "
        f"{_BENCHMARK_TIME_BUDGET_SECONDS}s for {_BENCHMARK_FILE_COUNT} files"
    )


# ---------------------------------------------------------------------------
# 2G.7 — Variable-name context boosting integration
# ---------------------------------------------------------------------------


def _extract_date_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Return only findings whose entity_type is DATE."""
    return [f for f in findings if f.entity_type == _DATE_ENTITY_TYPE]


def test_phi_suggestive_variable_name_boosts_confidence() -> None:
    """A PHI-suggestive variable name (patient_dob) raises the finding confidence.

    patient_dob contains "dob" which is in PHI_SUGGESTIVE_VARIABLE_PATTERNS.
    The boosted confidence must be strictly greater than the unboosted confidence.
    """
    boosted_findings = detect_phi_in_text_content(_BOOSTED_DATE_LINE, Path("test.py"))
    unboosted_findings = detect_phi_in_text_content(_UNBOOSTED_DATE_LINE, Path("test.py"))

    boosted_dates = _extract_date_findings(boosted_findings)
    unboosted_dates = _extract_date_findings(unboosted_findings)

    assert len(boosted_dates) >= 1, "No DATE finding produced for boosted line"
    assert len(unboosted_dates) >= 1, "No DATE finding produced for unboosted line"

    boosted_max = max(f.confidence for f in boosted_dates)
    unboosted_max = max(f.confidence for f in unboosted_dates)

    assert boosted_max > unboosted_max, (
        f"Expected boost: {boosted_max:.3f} should be > {unboosted_max:.3f}"
    )


def test_phi_suggestive_boost_applies_cap_at_maximum() -> None:
    """The boosted confidence is capped at CONFIDENCE_SCORE_MAXIMUM.

    The DATE regex baseline (_DATE_REGEX_BASELINE_CONFIDENCE = 0.88) plus
    VARIABLE_CONTEXT_CONFIDENCE_BOOST (0.15) gives 1.03, which exceeds
    CONFIDENCE_SCORE_MAXIMUM (1.0). The cap is applied, so the resulting
    confidence must equal CONFIDENCE_SCORE_MAXIMUM.
    """
    boosted_findings = detect_phi_in_text_content(_BOOSTED_DATE_LINE, Path("test.py"))

    boosted_dates = _extract_date_findings(boosted_findings)
    assert len(boosted_dates) >= 1

    boosted_capped = max(f.confidence for f in boosted_dates)

    # Named baseline confirms the boost would overflow without the cap.
    uncapped = _DATE_REGEX_BASELINE_CONFIDENCE + VARIABLE_CONTEXT_CONFIDENCE_BOOST
    assert uncapped > CONFIDENCE_SCORE_MAXIMUM
    # Confirm the cap is applied.
    assert boosted_capped == CONFIDENCE_SCORE_MAXIMUM


def test_non_phi_variable_name_does_not_reach_maximum_confidence() -> None:
    """A non-PHI variable name (config_value) leaves confidence below CONFIDENCE_SCORE_MAXIMUM.

    config_value contains no substring from PHI_SUGGESTIVE_VARIABLE_PATTERNS,
    so the boost is not applied and the score stays at the baseline regex value.
    """
    unboosted_findings = detect_phi_in_text_content(_UNBOOSTED_DATE_LINE, Path("test.py"))

    unboosted_dates = _extract_date_findings(unboosted_findings)
    assert len(unboosted_dates) >= 1

    unboosted_max = max(f.confidence for f in unboosted_dates)

    # Without boost the score must remain strictly below the maximum.
    assert unboosted_max < CONFIDENCE_SCORE_MAXIMUM


@_requires_nlp
def test_names_fixture_produces_name_category_findings_with_nlp() -> None:
    """names.py PHI fixture produces NAME-category findings when NLP is available."""
    names_fixture_path = _PHI_FIXTURE_DIR / _NAMES_FIXTURE_FILE_NAME
    config = ScanConfig(confidence_threshold=_LOW_CONFIDENCE_THRESHOLD)

    findings = scan_file(names_fixture_path, config)

    name_findings = [f for f in findings if f.hipaa_category == PhiCategory.NAME]
    assert len(name_findings) >= 1
