"""Tests for phi_scan.constants — named constants, enums, and derived values."""

import pytest

from phi_scan.constants import (
    AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX,
    AUDIT_RETENTION_DAYS,
    BYTES_PER_MEGABYTE,
    CONFIDENCE_HIGH_FLOOR,
    CONFIDENCE_LOW_FLOOR,
    CONFIDENCE_MEDIUM_FLOOR,
    CONFIDENCE_REGEX_MAX,
    CONFIDENCE_REGEX_MIN,
    CONFIDENCE_SCORE_MAXIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    HIPAA_REMEDIATION_GUIDANCE,
    KNOWN_BINARY_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)

# Cross-check: AUDIT_RETENTION_DAYS must equal the HIPAA-mandated 6-year minimum.
# 6 years worst-case: 4 standard years (365 days) + 2 leap years (366 days) = 2192 days.
# This concrete value is intentional — it guards against formula regressions.
_EXPECTED_HIPAA_RETENTION_DAYS: int = 2192


def test_max_file_size_bytes_equals_mb_times_bytes_per_megabyte() -> None:
    assert MAX_FILE_SIZE_BYTES == MAX_FILE_SIZE_MB * BYTES_PER_MEGABYTE


def test_audit_retention_days_equals_hipaa_six_year_minimum() -> None:
    assert AUDIT_RETENTION_DAYS == _EXPECTED_HIPAA_RETENTION_DAYS


def test_output_format_raises_value_error_for_unknown_string_value() -> None:
    # _missing_ returns None for unknown values; Python's enum machinery
    # then raises ValueError — callers should catch ValueError, not check None.
    with pytest.raises(ValueError):
        OutputFormat("unknown-format")


def test_output_format_raises_value_error_for_non_string_value() -> None:
    # _missing_ guard clause: non-string input returns None immediately,
    # causing Python's enum machinery to raise ValueError.
    with pytest.raises(ValueError):
        OutputFormat(42)  # type: ignore[arg-type]


def test_output_format_missing_matches_gitlab_sast_by_value() -> None:
    assert OutputFormat("gitlab-sast") is OutputFormat.GITLAB_SAST


def test_output_format_missing_is_case_insensitive() -> None:
    # StrEnum is case-sensitive by default: OutputFormat("TABLE") misses the
    # "table" member and falls through to _missing_, which calls lower() to match.
    assert OutputFormat("TABLE") is OutputFormat.TABLE


def test_hipaa_remediation_guidance_covers_every_phi_category() -> None:
    missing = [category for category in PhiCategory if category not in HIPAA_REMEDIATION_GUIDANCE]
    assert missing == [], f"Missing remediation guidance for: {missing}"


def test_known_binary_extensions_are_lowercase_dotted_strings() -> None:
    malformed = [
        ext for ext in KNOWN_BINARY_EXTENSIONS if not ext.startswith(".") or ext != ext.lower()
    ]
    assert malformed == [], f"Malformed extensions: {malformed}"


def test_known_binary_extensions_is_immutable() -> None:
    assert isinstance(KNOWN_BINARY_EXTENSIONS, frozenset)


def test_severity_level_resolves_high_by_value() -> None:
    assert SeverityLevel("high") is SeverityLevel.HIGH


def test_severity_level_resolves_info_by_value() -> None:
    assert SeverityLevel("info") is SeverityLevel.INFO


def test_risk_level_resolves_clean_by_value() -> None:
    assert RiskLevel("clean") is RiskLevel.CLEAN


def test_risk_level_resolves_critical_by_value() -> None:
    assert RiskLevel("critical") is RiskLevel.CRITICAL


def test_confidence_low_floor_is_below_default_threshold() -> None:
    assert CONFIDENCE_LOW_FLOOR < DEFAULT_CONFIDENCE_THRESHOLD


def test_default_confidence_threshold_is_below_medium_floor() -> None:
    assert DEFAULT_CONFIDENCE_THRESHOLD < CONFIDENCE_MEDIUM_FLOOR


def test_confidence_medium_floor_is_below_high_floor() -> None:
    assert CONFIDENCE_MEDIUM_FLOOR < CONFIDENCE_HIGH_FLOOR


def test_confidence_regex_max_equals_score_maximum() -> None:
    assert CONFIDENCE_REGEX_MAX == CONFIDENCE_SCORE_MAXIMUM


def test_confidence_regex_min_is_below_regex_max() -> None:
    assert CONFIDENCE_REGEX_MIN < CONFIDENCE_REGEX_MAX


def test_ai_layer_adjustment_max_is_below_high_floor() -> None:
    # Ensures the AI layer cannot push a LOW-confidence finding into HIGH territory
    # on its own — a delta this small requires a pre-existing high base score.
    assert AI_LAYER_CONFIDENCE_ADJUSTMENT_MAX < CONFIDENCE_HIGH_FLOOR
