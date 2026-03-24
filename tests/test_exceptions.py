"""Tests for phi_scan.exceptions — custom exception hierarchy."""

import pytest

from phi_scan.exceptions import (
    AuditLogError,
    ConfigurationError,
    MissingOptionalDependencyError,
    PhiScanError,
    SchemaMigrationError,
    TraversalError,
)

# A path that cannot exist on any OS — avoids /tmp which is real (and a symlink on macOS).
_NONEXISTENT_PATH: str = "/nonexistent/phi-scan-test-path"
# Placeholder used in tests where the message content is not under test.
_PLACEHOLDER_ERROR_MESSAGE: str = "phi-scan-test-error"
_SAMPLE_CONFIG_ERROR_MESSAGE: str = (
    "invalid value 'foo' for key 'output_format': expected one of table, json"
)
_SAMPLE_TRAVERSAL_ERROR_MESSAGE: str = (
    f"path '{_NONEXISTENT_PATH}' does not exist or is not readable"
)
_SAMPLE_AUDIT_LOG_ERROR_MESSAGE: str = (
    f"cannot write to audit log at '{_NONEXISTENT_PATH}': permission denied"
)
_SAMPLE_SCHEMA_MIGRATION_ERROR_MESSAGE: str = (
    "cannot migrate schema from version 1 to version 3: version 2 migration missing"
)
_SAMPLE_MISSING_DEPENDENCY_ERROR_MESSAGE: str = (
    "hl7 is required for HL7 v2 scanning — install with: pip install phi-scan[hl7]"
)


def test_phi_scan_error_is_exception_subclass() -> None:
    assert issubclass(PhiScanError, Exception)


def test_configuration_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(ConfigurationError, PhiScanError)


def test_traversal_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(TraversalError, PhiScanError)


def test_audit_log_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(AuditLogError, PhiScanError)


def test_schema_migration_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(SchemaMigrationError, PhiScanError)


def test_phi_scan_error_preserves_message() -> None:
    raised_error = PhiScanError(_PLACEHOLDER_ERROR_MESSAGE)

    assert str(raised_error) == _PLACEHOLDER_ERROR_MESSAGE


def test_configuration_error_preserves_message() -> None:
    raised_error = ConfigurationError(_SAMPLE_CONFIG_ERROR_MESSAGE)

    assert str(raised_error) == _SAMPLE_CONFIG_ERROR_MESSAGE


def test_traversal_error_preserves_message() -> None:
    raised_error = TraversalError(_SAMPLE_TRAVERSAL_ERROR_MESSAGE)

    assert str(raised_error) == _SAMPLE_TRAVERSAL_ERROR_MESSAGE


def test_audit_log_error_preserves_message() -> None:
    raised_error = AuditLogError(_SAMPLE_AUDIT_LOG_ERROR_MESSAGE)

    assert str(raised_error) == _SAMPLE_AUDIT_LOG_ERROR_MESSAGE


def test_schema_migration_error_preserves_message() -> None:
    raised_error = SchemaMigrationError(_SAMPLE_SCHEMA_MIGRATION_ERROR_MESSAGE)

    assert str(raised_error) == _SAMPLE_SCHEMA_MIGRATION_ERROR_MESSAGE


def test_phi_scan_error_is_catchable_as_exception() -> None:
    with pytest.raises(Exception) as exc_info:
        raise PhiScanError(_PLACEHOLDER_ERROR_MESSAGE)

    assert str(exc_info.value) == _PLACEHOLDER_ERROR_MESSAGE


def test_missing_optional_dependency_error_is_phi_scan_error_subclass() -> None:
    assert issubclass(MissingOptionalDependencyError, PhiScanError)


def test_missing_optional_dependency_error_preserves_message() -> None:
    raised_error = MissingOptionalDependencyError(_SAMPLE_MISSING_DEPENDENCY_ERROR_MESSAGE)

    assert str(raised_error) == _SAMPLE_MISSING_DEPENDENCY_ERROR_MESSAGE


def test_missing_optional_dependency_error_is_catchable_as_phi_scan_error() -> None:
    # Callers that handle any PhiScan error with `except PhiScanError` must catch
    # MissingOptionalDependencyError too — it must not escape as a bare ImportError.
    with pytest.raises(PhiScanError):
        raise MissingOptionalDependencyError(_SAMPLE_MISSING_DEPENDENCY_ERROR_MESSAGE)
