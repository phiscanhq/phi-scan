"""Tests for phi_scan.exceptions — custom exception hierarchy."""

import pytest

from phi_scan.exceptions import (
    AuditLogError,
    ConfigurationError,
    PhiScanError,
    SchemaMigrationError,
    TraversalError,
)

# A path that cannot exist on any OS — avoids /tmp which is real (and a symlink on macOS).
_NONEXISTENT_PATH: str = "/nonexistent/phi-scan-test-path"
_AUDIT_DB_PATH: str = "/var/phi-scanner/audit.db"


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
    error_message = "something went wrong"

    raised_error = PhiScanError(error_message)

    assert str(raised_error) == error_message


def test_configuration_error_preserves_message() -> None:
    error_message = "invalid value 'foo' for key 'output_format': expected one of table, json"

    raised_error = ConfigurationError(error_message)

    assert str(raised_error) == error_message


def test_traversal_error_preserves_message() -> None:
    error_message = f"path '{_NONEXISTENT_PATH}' does not exist or is not readable"

    raised_error = TraversalError(error_message)

    assert str(raised_error) == error_message


def test_audit_log_error_preserves_message() -> None:
    error_message = f"cannot write to audit log at '{_AUDIT_DB_PATH}': permission denied"

    raised_error = AuditLogError(error_message)

    assert str(raised_error) == error_message


def test_schema_migration_error_preserves_message() -> None:
    error_message = "cannot migrate schema from version 1 to version 3: version 2 migration missing"

    raised_error = SchemaMigrationError(error_message)

    assert str(raised_error) == error_message


def test_phi_scan_error_is_catchable_as_exception() -> None:
    error_message = "base catch test"

    with pytest.raises(Exception) as exc_info:
        raise PhiScanError(error_message)

    assert str(exc_info.value) == error_message


def test_configuration_error_is_catchable_as_phi_scan_error() -> None:
    with pytest.raises(PhiScanError) as exc_info:
        raise ConfigurationError("test")

    assert isinstance(exc_info.value, ConfigurationError)


def test_traversal_error_is_catchable_as_phi_scan_error() -> None:
    with pytest.raises(PhiScanError) as exc_info:
        raise TraversalError("test")

    assert isinstance(exc_info.value, TraversalError)


def test_audit_log_error_is_catchable_as_phi_scan_error() -> None:
    with pytest.raises(PhiScanError) as exc_info:
        raise AuditLogError("test")

    assert isinstance(exc_info.value, AuditLogError)


def test_schema_migration_error_is_catchable_as_phi_scan_error() -> None:
    with pytest.raises(PhiScanError) as exc_info:
        raise SchemaMigrationError("test")

    assert isinstance(exc_info.value, SchemaMigrationError)
