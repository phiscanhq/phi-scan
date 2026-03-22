"""Tests for phi_scan.constants — named constants, enums, and derived values."""

import pytest

from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    HIPAA_REMEDIATION_GUIDANCE,
    KNOWN_BINARY_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    OutputFormat,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)

# HIPAA §164.530(j) 6-year minimum: 4 standard years + 2 leap years = 2192 days.
_EXPECTED_HIPAA_RETENTION_DAYS: int = 2192

# 10 MB expressed in bytes: 10 × 1024 × 1024.
_EXPECTED_MAX_FILE_SIZE_BYTES: int = 10_485_760


def test_max_file_size_bytes_equals_mb_times_bytes_per_megabyte() -> None:
    assert MAX_FILE_SIZE_BYTES == _EXPECTED_MAX_FILE_SIZE_BYTES


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
