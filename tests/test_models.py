"""Tests for phi_scan.models — ScanFinding, ScanResult, ScanConfig dataclasses."""

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.constants import (
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    MAX_FILE_SIZE_MB,
    SHA256_HEX_DIGEST_LENGTH,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError, PhiDetectionError
from phi_scan.models import ScanConfig, ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# ScanFinding fixture data — all fields required, no defaults
# ---------------------------------------------------------------------------

_FINDING_FILE_PATH: Path = Path("/project/src/patient_handler.py")
_FINDING_LINE_NUMBER: int = 42
_FINDING_ENTITY_TYPE: str = "us_ssn"
_FINDING_HIPAA_CATEGORY: PhiCategory = PhiCategory.SSN
_FINDING_CONFIDENCE: float = 0.95
_FINDING_DETECTION_LAYER: DetectionLayer = DetectionLayer.REGEX
_FINDING_VALUE_HASH: str = "a" * SHA256_HEX_DIGEST_LENGTH
_FINDING_SEVERITY: SeverityLevel = SeverityLevel.HIGH
_FINDING_CODE_CONTEXT: str = "patient_ssn = '***-**-****'"
_FINDING_REMEDIATION_HINT: str = "Replace SSN with synthetic value using 000-00-0000 format."

_INVALID_LINE_NUMBER_ZERO: int = 0
_INVALID_LINE_NUMBER_NEGATIVE: int = -1
_INVALID_VALUE_HASH_TOO_SHORT: str = "a" * (SHA256_HEX_DIGEST_LENGTH - 1)
_INVALID_VALUE_HASH_TOO_LONG: str = "a" * (SHA256_HEX_DIGEST_LENGTH + 1)
# Correct length but non-hex characters — exposes the weakness in length-only checks.
_INVALID_VALUE_HASH_NON_HEX: str = "z" * SHA256_HEX_DIGEST_LENGTH
# Uppercase hex is not a valid SHA-256 hex digest — must be lowercase [0-9a-f].
_INVALID_VALUE_HASH_UPPERCASE_HEX: str = "A" * SHA256_HEX_DIGEST_LENGTH
# Arbitrary confidence value used to exercise FrozenInstanceError — the exact
# value is irrelevant; any valid score in [0.0, 1.0] triggers the same error.
_ARBITRARY_CONFIDENCE_FOR_MUTATION_ATTEMPT: float = 0.5


def _build_scan_finding() -> ScanFinding:
    """Return a fully populated ScanFinding for use across multiple tests."""
    return ScanFinding(
        file_path=_FINDING_FILE_PATH,
        line_number=_FINDING_LINE_NUMBER,
        entity_type=_FINDING_ENTITY_TYPE,
        hipaa_category=_FINDING_HIPAA_CATEGORY,
        confidence=_FINDING_CONFIDENCE,
        detection_layer=_FINDING_DETECTION_LAYER,
        value_hash=_FINDING_VALUE_HASH,
        severity=_FINDING_SEVERITY,
        code_context=_FINDING_CODE_CONTEXT,
        remediation_hint=_FINDING_REMEDIATION_HINT,
    )


# ---------------------------------------------------------------------------
# ScanFinding tests
# ---------------------------------------------------------------------------


def test_scan_finding_stores_file_path() -> None:
    finding = _build_scan_finding()

    assert finding.file_path == _FINDING_FILE_PATH


def test_scan_finding_stores_line_number() -> None:
    finding = _build_scan_finding()

    assert finding.line_number == _FINDING_LINE_NUMBER


def test_scan_finding_stores_entity_type() -> None:
    finding = _build_scan_finding()

    assert finding.entity_type == _FINDING_ENTITY_TYPE


def test_scan_finding_stores_hipaa_category() -> None:
    finding = _build_scan_finding()

    assert finding.hipaa_category == _FINDING_HIPAA_CATEGORY


def test_scan_finding_stores_confidence() -> None:
    finding = _build_scan_finding()

    assert finding.confidence == _FINDING_CONFIDENCE


def test_scan_finding_stores_detection_layer() -> None:
    finding = _build_scan_finding()

    assert finding.detection_layer == _FINDING_DETECTION_LAYER


def test_scan_finding_stores_value_hash() -> None:
    finding = _build_scan_finding()

    assert finding.value_hash == _FINDING_VALUE_HASH


def test_scan_finding_stores_severity() -> None:
    finding = _build_scan_finding()

    assert finding.severity == _FINDING_SEVERITY


def test_scan_finding_stores_code_context() -> None:
    finding = _build_scan_finding()

    assert finding.code_context == _FINDING_CODE_CONTEXT


def test_scan_finding_stores_remediation_hint() -> None:
    finding = _build_scan_finding()

    assert finding.remediation_hint == _FINDING_REMEDIATION_HINT


def test_scan_finding_is_immutable() -> None:
    # frozen=True prevents mutation of findings after they are produced by
    # the detection engine — findings are immutable records of observed PHI.
    finding = _build_scan_finding()

    with pytest.raises(FrozenInstanceError):
        finding.confidence = _ARBITRARY_CONFIDENCE_FOR_MUTATION_ATTEMPT  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ScanFinding — line_number validation
# ---------------------------------------------------------------------------


def test_scan_finding_raises_phi_detection_error_for_line_number_zero() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_INVALID_LINE_NUMBER_ZERO,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_FINDING_VALUE_HASH,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_finding_raises_phi_detection_error_for_negative_line_number() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_INVALID_LINE_NUMBER_NEGATIVE,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_FINDING_VALUE_HASH,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


# ---------------------------------------------------------------------------
# ScanFinding — value_hash validation
# ---------------------------------------------------------------------------


def test_scan_finding_raises_phi_detection_error_for_value_hash_too_short() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_INVALID_VALUE_HASH_TOO_SHORT,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_finding_raises_phi_detection_error_for_value_hash_too_long() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_INVALID_VALUE_HASH_TOO_LONG,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_finding_raises_phi_detection_error_for_value_hash_with_non_hex_characters() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_INVALID_VALUE_HASH_NON_HEX,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_finding_raises_phi_detection_error_for_value_hash_with_uppercase_hex() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_FINDING_CONFIDENCE,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_INVALID_VALUE_HASH_UPPERCASE_HEX,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------

_RESULT_FILES_SCANNED: int = 10
_RESULT_FILES_WITH_FINDINGS: int = 1
_RESULT_FILES_WITH_FINDINGS_ZERO: int = 0
_RESULT_SCAN_DURATION: float = 0.42
_RESULT_RISK_LEVEL: RiskLevel = RiskLevel.HIGH

_INVALID_FILES_SCANNED_NEGATIVE: int = -1
_INVALID_FILES_WITH_FINDINGS_NEGATIVE: int = -1
# files_with_findings must not exceed files_scanned — use a value clearly above the ceiling.
_INVALID_FILES_WITH_FINDINGS_TOO_HIGH: int = _RESULT_FILES_SCANNED + 1
_INVALID_SCAN_DURATION_NEGATIVE: float = -0.001


def _build_scan_result() -> ScanResult:
    """Return a populated ScanResult for use across multiple tests."""
    return ScanResult(
        findings=(_build_scan_finding(),),
        files_scanned=_RESULT_FILES_SCANNED,
        files_with_findings=_RESULT_FILES_WITH_FINDINGS,
        scan_duration=_RESULT_SCAN_DURATION,
        is_clean=False,
        risk_level=_RESULT_RISK_LEVEL,
        severity_counts=MappingProxyType({SeverityLevel.HIGH: 1}),
        category_counts=MappingProxyType({PhiCategory.SSN: 1}),
    )


def test_scan_result_stores_findings() -> None:
    expected_finding = _build_scan_finding()

    scan_result = _build_scan_result()

    assert scan_result.findings == (expected_finding,)


def test_scan_result_stores_files_scanned() -> None:
    scan_result = _build_scan_result()

    assert scan_result.files_scanned == _RESULT_FILES_SCANNED


def test_scan_result_stores_files_with_findings() -> None:
    scan_result = _build_scan_result()

    assert scan_result.files_with_findings == _RESULT_FILES_WITH_FINDINGS


def test_scan_result_stores_scan_duration() -> None:
    scan_result = _build_scan_result()

    assert scan_result.scan_duration == _RESULT_SCAN_DURATION


def test_scan_result_stores_is_clean() -> None:
    scan_result = _build_scan_result()

    assert scan_result.is_clean is False


def test_scan_result_stores_risk_level() -> None:
    scan_result = _build_scan_result()

    assert scan_result.risk_level == _RESULT_RISK_LEVEL


def test_scan_result_stores_severity_counts() -> None:
    expected_severity_counts = MappingProxyType({SeverityLevel.HIGH: 1})

    scan_result = _build_scan_result()

    assert scan_result.severity_counts == expected_severity_counts


def test_scan_result_stores_category_counts() -> None:
    expected_category_counts = MappingProxyType({PhiCategory.SSN: 1})

    scan_result = _build_scan_result()

    assert scan_result.category_counts == expected_category_counts


def test_scan_result_is_clean_when_no_findings() -> None:
    clean_result = ScanResult(
        findings=(),
        files_scanned=_RESULT_FILES_SCANNED,
        files_with_findings=_RESULT_FILES_WITH_FINDINGS_ZERO,
        scan_duration=_RESULT_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({}),
        category_counts=MappingProxyType({}),
    )

    assert clean_result.is_clean is True
    assert clean_result.risk_level == RiskLevel.CLEAN


def test_scan_result_is_immutable() -> None:
    # frozen=True prevents field reassignment — ScanResult is a sealed record.
    scan_result = _build_scan_result()

    with pytest.raises(FrozenInstanceError):
        scan_result.files_scanned = 0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ScanResult — logical consistency validation
# ---------------------------------------------------------------------------


def test_scan_result_raises_phi_detection_error_when_is_clean_true_with_findings() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(_build_scan_finding(),),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_RESULT_FILES_WITH_FINDINGS,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=True,
            risk_level=RiskLevel.CLEAN,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_accepts_is_clean_false_with_empty_findings() -> None:
    # findings=() with is_clean=False is valid when all raw detections were below
    # the confidence threshold and filtered out before the result was built.
    filtered_scan_result = ScanResult(
        findings=(),
        files_scanned=_RESULT_FILES_SCANNED,
        files_with_findings=_RESULT_FILES_WITH_FINDINGS_ZERO,
        scan_duration=_RESULT_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.LOW,
        severity_counts=MappingProxyType({}),
        category_counts=MappingProxyType({}),
    )

    assert filtered_scan_result.is_clean is False
    assert filtered_scan_result.findings == ()


def test_scan_result_raises_phi_detection_error_when_files_scanned_is_negative() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(),
            files_scanned=_INVALID_FILES_SCANNED_NEGATIVE,
            files_with_findings=_RESULT_FILES_WITH_FINDINGS_ZERO,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=False,
            risk_level=RiskLevel.LOW,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_raises_phi_detection_error_when_files_with_findings_is_negative() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_INVALID_FILES_WITH_FINDINGS_NEGATIVE,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=False,
            risk_level=RiskLevel.LOW,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_raises_phi_detection_error_when_scan_duration_is_negative() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_RESULT_FILES_WITH_FINDINGS_ZERO,
            scan_duration=_INVALID_SCAN_DURATION_NEGATIVE,
            is_clean=False,
            risk_level=RiskLevel.LOW,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_raises_phi_detection_error_when_files_with_findings_exceeds_scanned() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_INVALID_FILES_WITH_FINDINGS_TOO_HIGH,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=False,
            risk_level=RiskLevel.LOW,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_raises_phi_detection_error_when_is_clean_true_with_wrong_risk_level() -> None:
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_RESULT_FILES_WITH_FINDINGS_ZERO,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=True,
            risk_level=RiskLevel.HIGH,
            severity_counts=MappingProxyType({}),
            category_counts=MappingProxyType({}),
        )


def test_scan_result_raises_phi_detection_error_when_is_clean_false_with_clean_risk_level() -> None:
    # is_clean=False with RiskLevel.CLEAN is a bi-conditional mismatch —
    # both directions are enforced by _reject_mismatched_clean_flag_and_risk_level.
    with pytest.raises(PhiDetectionError):
        ScanResult(
            findings=(_build_scan_finding(),),
            files_scanned=_RESULT_FILES_SCANNED,
            files_with_findings=_RESULT_FILES_WITH_FINDINGS,
            scan_duration=_RESULT_SCAN_DURATION,
            is_clean=False,
            risk_level=RiskLevel.CLEAN,
            severity_counts=MappingProxyType({SeverityLevel.HIGH: 1}),
            category_counts=MappingProxyType({PhiCategory.SSN: 1}),
        )


# ---------------------------------------------------------------------------
# ScanConfig tests
# ---------------------------------------------------------------------------


def test_scan_config_exclude_paths_defaults_to_empty_list() -> None:
    config = ScanConfig()

    assert config.exclude_paths == []


def test_scan_config_exclude_paths_are_independent_instances() -> None:
    # field(default_factory=list) ensures each ScanConfig gets its own list,
    # not a shared mutable default.
    config_a = ScanConfig()
    config_b = ScanConfig()

    config_a.exclude_paths.append("node_modules/")

    assert config_b.exclude_paths == []


def test_scan_config_severity_threshold_defaults_to_low() -> None:
    config = ScanConfig()

    assert config.severity_threshold == SeverityLevel.LOW


def test_scan_config_confidence_threshold_defaults_to_constant() -> None:
    config = ScanConfig()

    assert config.confidence_threshold == DEFAULT_CONFIDENCE_THRESHOLD


def test_scan_config_should_follow_symlinks_defaults_to_false() -> None:
    config = ScanConfig()

    assert config.should_follow_symlinks is False


def test_scan_config_max_file_size_mb_defaults_to_constant() -> None:
    config = ScanConfig()

    assert config.max_file_size_mb == MAX_FILE_SIZE_MB


def test_scan_config_include_extensions_defaults_to_none() -> None:
    config = ScanConfig()

    assert config.include_extensions is None


def test_scan_config_accepts_custom_exclude_paths() -> None:
    exclude_patterns = ["node_modules/", ".venv/", "*.min.js"]

    config = ScanConfig(exclude_paths=exclude_patterns)

    assert config.exclude_paths == exclude_patterns


def test_scan_config_accepts_include_extensions_allowlist() -> None:
    allowed_extensions = [".py", ".js", ".ts"]

    config = ScanConfig(include_extensions=allowed_extensions)

    assert config.include_extensions == allowed_extensions


def test_scan_config_exclude_paths_defensive_copy_isolates_caller() -> None:
    # Mutating the original list after construction must not affect the config.
    caller_paths = ["node_modules/"]

    config = ScanConfig(exclude_paths=caller_paths)
    caller_paths.append(".venv/")

    assert config.exclude_paths == ["node_modules/"]


def test_scan_config_include_extensions_defensive_copy_isolates_caller() -> None:
    # Mutating the original list after construction must not affect the config.
    caller_extensions = [".py"]

    config = ScanConfig(include_extensions=caller_extensions)
    caller_extensions.append(".js")

    assert config.include_extensions == [".py"]


# ---------------------------------------------------------------------------
# ScanConfig — max_file_size_mb validation
# ---------------------------------------------------------------------------

_INVALID_MAX_FILE_SIZE_MB_ZERO: int = 0
_INVALID_MAX_FILE_SIZE_MB_NEGATIVE: int = -1
# A float where int is required — was silently stored before _validate_max_file_size_mb
# used `not isinstance(value, int)` to catch non-int types.
_INVALID_MAX_FILE_SIZE_MB_FLOAT: float = 2.5
# An int value above CONFIDENCE_SCORE_MAXIMUM — exercises the gap where
# isinstance(value, float) would silently skip int inputs in __setattr__.
_INVALID_CONFIDENCE_THRESHOLD_AS_INT: int = 2
_INVALID_SEVERITY_THRESHOLD: str = "not_a_severity"
# String values passed where list fields are expected — must be rejected.
_INVALID_EXCLUDE_PATHS_NON_LIST: str = "*.py"
_INVALID_INCLUDE_EXTENSIONS_NON_LIST: str = ".py"
# A truthy non-bool — exercises the gap where `value is True` would silently
# pass 1 (or any other truthy int) as should_follow_symlinks.
_TRUTHY_NON_BOOL_SYMLINK_VALUE: int = 1
# Bool values used where int/float fields are expected — must be rejected
# explicitly so True (≡1) and False (≡0) cannot masquerade as valid counts.
_BOOL_AS_MAX_FILE_SIZE_MB: bool = True
_BOOL_AS_CONFIDENCE_THRESHOLD: bool = True


def test_scan_config_raises_configuration_error_for_max_file_size_mb_zero() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(max_file_size_mb=_INVALID_MAX_FILE_SIZE_MB_ZERO)


def test_scan_config_raises_configuration_error_for_max_file_size_mb_negative() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(max_file_size_mb=_INVALID_MAX_FILE_SIZE_MB_NEGATIVE)


def test_scan_config_raises_configuration_error_for_max_file_size_mb_float() -> None:
    # Float values bypass the isinstance(int) check and were silently stored;
    # _validate_max_file_size_mb now uses `not isinstance(int)` to catch them.
    with pytest.raises(ConfigurationError):
        ScanConfig(max_file_size_mb=_INVALID_MAX_FILE_SIZE_MB_FLOAT)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Confidence boundary tests
# ---------------------------------------------------------------------------

_CONFIDENCE_BELOW_MINIMUM: float = CONFIDENCE_SCORE_MINIMUM - 0.001
_CONFIDENCE_ABOVE_MAXIMUM: float = CONFIDENCE_SCORE_MAXIMUM + 0.001


def test_scan_finding_accepts_minimum_confidence_boundary() -> None:
    finding = ScanFinding(
        file_path=_FINDING_FILE_PATH,
        line_number=_FINDING_LINE_NUMBER,
        entity_type=_FINDING_ENTITY_TYPE,
        hipaa_category=_FINDING_HIPAA_CATEGORY,
        confidence=CONFIDENCE_SCORE_MINIMUM,
        detection_layer=_FINDING_DETECTION_LAYER,
        value_hash=_FINDING_VALUE_HASH,
        severity=_FINDING_SEVERITY,
        code_context=_FINDING_CODE_CONTEXT,
        remediation_hint=_FINDING_REMEDIATION_HINT,
    )

    assert finding.confidence == CONFIDENCE_SCORE_MINIMUM


def test_scan_finding_accepts_maximum_confidence_boundary() -> None:
    finding = ScanFinding(
        file_path=_FINDING_FILE_PATH,
        line_number=_FINDING_LINE_NUMBER,
        entity_type=_FINDING_ENTITY_TYPE,
        hipaa_category=_FINDING_HIPAA_CATEGORY,
        confidence=CONFIDENCE_SCORE_MAXIMUM,
        detection_layer=_FINDING_DETECTION_LAYER,
        value_hash=_FINDING_VALUE_HASH,
        severity=_FINDING_SEVERITY,
        code_context=_FINDING_CODE_CONTEXT,
        remediation_hint=_FINDING_REMEDIATION_HINT,
    )

    assert finding.confidence == CONFIDENCE_SCORE_MAXIMUM


def test_scan_finding_raises_phi_detection_error_for_confidence_below_minimum() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_CONFIDENCE_BELOW_MINIMUM,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_FINDING_VALUE_HASH,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_finding_raises_phi_detection_error_for_confidence_above_maximum() -> None:
    with pytest.raises(PhiDetectionError):
        ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=_FINDING_HIPAA_CATEGORY,
            confidence=_CONFIDENCE_ABOVE_MAXIMUM,
            detection_layer=_FINDING_DETECTION_LAYER,
            value_hash=_FINDING_VALUE_HASH,
            severity=_FINDING_SEVERITY,
            code_context=_FINDING_CODE_CONTEXT,
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )


def test_scan_config_raises_configuration_error_for_threshold_below_minimum() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(confidence_threshold=_CONFIDENCE_BELOW_MINIMUM)


def test_scan_config_raises_configuration_error_for_threshold_above_maximum() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(confidence_threshold=_CONFIDENCE_ABOVE_MAXIMUM)


def test_scan_config_raises_configuration_error_when_follow_symlinks_is_true() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(should_follow_symlinks=True)


# ---------------------------------------------------------------------------
# ScanConfig — __setattr__ post-construction mutation guards
# ---------------------------------------------------------------------------


def test_scan_config_raises_when_symlinks_set_true_post_construction() -> None:
    # Mutable ScanConfig must not allow security-critical invariants to be bypassed
    # by direct field assignment after the object is constructed.
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.should_follow_symlinks = True  # type: ignore[misc]


def test_scan_config_raises_when_symlinks_set_to_truthy_non_bool() -> None:
    # `value is True` would silently accept 1 or any truthy non-bool; the guard
    # must use truthiness (`value`) to cover all truthy inputs.
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.should_follow_symlinks = _TRUTHY_NON_BOOL_SYMLINK_VALUE  # type: ignore[assignment]


def test_scan_config_raises_when_max_file_size_mb_set_to_bool() -> None:
    # bool is a subclass of int — True (≡1) would pass the int range check
    # and be silently stored; bools must be explicitly rejected.
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.max_file_size_mb = _BOOL_AS_MAX_FILE_SIZE_MB  # type: ignore[assignment]


def test_scan_config_raises_when_confidence_threshold_set_to_bool() -> None:
    # bool is a subclass of int — True (≡1.0) is in [0.0, 1.0] and would pass
    # the range check; bools must be explicitly rejected.
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.confidence_threshold = _BOOL_AS_CONFIDENCE_THRESHOLD  # type: ignore[assignment]


def test_scan_config_raises_when_max_file_size_below_minimum_post_construction() -> None:
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.max_file_size_mb = _INVALID_MAX_FILE_SIZE_MB_ZERO


def test_scan_config_raises_when_confidence_threshold_out_of_range_post_construction() -> None:
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.confidence_threshold = _CONFIDENCE_ABOVE_MAXIMUM


def test_scan_config_raises_when_confidence_threshold_set_to_out_of_range_int() -> None:
    # int values must be range-checked — isinstance(value, float) would silently
    # skip ints, allowing config.confidence_threshold = 2 to succeed without error.
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.confidence_threshold = _INVALID_CONFIDENCE_THRESHOLD_AS_INT  # type: ignore[assignment]


def test_scan_config_raises_when_severity_threshold_set_to_invalid_value() -> None:
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.severity_threshold = _INVALID_SEVERITY_THRESHOLD  # type: ignore[assignment]


def test_scan_config_raises_when_exclude_paths_set_to_non_list() -> None:
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.exclude_paths = _INVALID_EXCLUDE_PATHS_NON_LIST  # type: ignore[assignment]


def test_scan_config_raises_when_include_extensions_set_to_non_list() -> None:
    config = ScanConfig()

    with pytest.raises(ConfigurationError):
        config.include_extensions = _INVALID_INCLUDE_EXTENSIONS_NON_LIST  # type: ignore[assignment]
