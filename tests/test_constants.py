"""Tests for phi_scan.constants — named constants, enums, and derived values."""

import pytest

from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    MAX_FILE_SIZE_BYTES,
    OutputFormat,
)

# HIPAA §164.530(j) 6-year minimum: 4 standard years + 2 leap years = 2192 days.
_EXPECTED_HIPAA_RETENTION_DAYS: int = 2192


def test_max_file_size_bytes_equals_mb_times_bytes_per_megabyte() -> None:
    assert MAX_FILE_SIZE_BYTES == 10_485_760


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
        OutputFormat(42)  # type: ignore[call-arg]


def test_output_format_missing_matches_gitlab_sast_by_value() -> None:
    assert OutputFormat("gitlab-sast") is OutputFormat.GITLAB_SAST


def test_output_format_missing_is_case_insensitive() -> None:
    assert OutputFormat("TABLE") is OutputFormat.TABLE
