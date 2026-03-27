"""Tests for phi_scan.audit — SQLite HIPAA-compliant audit logging."""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, patch

import pytest

from phi_scan import __version__
from phi_scan.audit import (
    _BOOLEAN_FALSE,
    _BOOLEAN_TRUE,
    _CREATED_AT_KEY,
    _SCAN_EVENTS_TABLE,
    _SCHEMA_META_TABLE,
    _SCHEMA_VERSION_KEY,
    _UNKNOWN_BRANCH,
    _get_current_branch,
    _get_current_timestamp,
    _get_repository_path,
    _open_database,
    _reject_symlink_database_path,
    _serialize_findings,
    create_audit_schema,
    get_last_scan,
    get_schema_version,
    insert_scan_event,
    migrate_schema,
    query_recent_scans,
)
from phi_scan.constants import (
    AUDIT_SCHEMA_VERSION,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import AuditLogError, SchemaMigrationError
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# Module-level test constants — no magic values in test logic
# ---------------------------------------------------------------------------

_SAMPLE_VALUE_HASH: str = "a" * 64
_SAMPLE_ENTITY_TYPE: str = "us_ssn"
_SAMPLE_LINE_NUMBER: int = 42
_SAMPLE_CONFIDENCE: float = 0.95
_SAMPLE_CODE_CONTEXT: str = "ssn = '123-45-6789'"
_SAMPLE_REMEDIATION_HINT: str = "Replace with synthetic SSN"
_SAMPLE_SCAN_DURATION: float = 1.23
_SAMPLE_FILES_SCANNED: int = 10
_SAMPLE_FILES_WITH_FINDINGS: int = 1
_SAMPLE_GIT_BRANCH: str = "main"
_SAMPLE_GIT_REPO_ROOT: str = "/repo"
_SAMPLE_GIT_BRANCH_OUTPUT: str = f"{_SAMPLE_GIT_BRANCH}\n"
_SAMPLE_GIT_REPO_OUTPUT: str = f"{_SAMPLE_GIT_REPO_ROOT}\n"
_EMPTY_GIT_OUTPUT: str = ""
_GIT_SUCCESS_RETURN_CODE: int = 0
_GIT_FAILURE_RETURN_CODE: int = 128
_SCHEMA_VERSION_FROM: int = 1
_SCHEMA_VERSION_TO: int = 2
_SAMPLE_MIGRATION_SQL: str = "ALTER TABLE scan_events ADD COLUMN extra TEXT"
_RECENT_SCANS_DAYS: int = 7
_ZERO_DAYS: int = 0
_SCAN_EVENTS_COUNT_QUERY: str = f"SELECT COUNT(*) FROM {_SCAN_EVENTS_TABLE}"
_SCHEMA_META_COUNT_QUERY: str = f"SELECT COUNT(*) FROM {_SCHEMA_META_TABLE}"
_SCHEMA_VERSION_QUERY: str = (
    f"SELECT value FROM {_SCHEMA_META_TABLE} WHERE key = '{_SCHEMA_VERSION_KEY}'"
)


# ---------------------------------------------------------------------------
# Shared fixtures and factory helpers
# ---------------------------------------------------------------------------


def _build_scan_finding(file_path: Path) -> ScanFinding:
    """Return a minimal ScanFinding with valid fields for audit tests."""
    return ScanFinding(
        file_path=file_path,
        line_number=_SAMPLE_LINE_NUMBER,
        entity_type=_SAMPLE_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_SAMPLE_CODE_CONTEXT,
        remediation_hint=_SAMPLE_REMEDIATION_HINT,
    )


def _build_clean_scan_result() -> ScanResult:
    """Return a ScanResult with zero findings."""
    return ScanResult(
        findings=(),
        files_scanned=_SAMPLE_FILES_SCANNED,
        files_with_findings=0,
        scan_duration=_SAMPLE_SCAN_DURATION,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({}),
        category_counts=MappingProxyType({}),
    )


def _build_dirty_scan_result(file_path: Path) -> ScanResult:
    """Return a ScanResult with one SSN finding."""
    finding = _build_scan_finding(file_path)
    return ScanResult(
        findings=(finding,),
        files_scanned=_SAMPLE_FILES_SCANNED,
        files_with_findings=_SAMPLE_FILES_WITH_FINDINGS,
        scan_duration=_SAMPLE_SCAN_DURATION,
        is_clean=False,
        risk_level=RiskLevel.HIGH,
        severity_counts=MappingProxyType({SeverityLevel.HIGH: 1}),
        category_counts=MappingProxyType({PhiCategory.SSN: 1}),
    )


def _build_subprocess_result(
    stdout: str = _EMPTY_GIT_OUTPUT,
    returncode: int = _GIT_SUCCESS_RETURN_CODE,
) -> MagicMock:
    """Return a MagicMock shaped like subprocess.CompletedProcess."""
    mock_result = MagicMock()
    mock_result.stdout = stdout
    mock_result.returncode = returncode
    return mock_result


def _setup_schema(database_path: Path) -> None:
    """Create the audit schema so other tests can insert/query rows."""
    create_audit_schema(database_path)


# ---------------------------------------------------------------------------
# _reject_symlink_database_path
# ---------------------------------------------------------------------------


def test_reject_symlink_database_path_raises_audit_log_error_for_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        _reject_symlink_database_path(symlink)


def test_reject_symlink_database_path_does_not_raise_for_regular_path(
    tmp_path: Path,
) -> None:
    regular_path = tmp_path / "audit.db"

    _reject_symlink_database_path(regular_path)  # must not raise


def test_reject_symlink_database_path_error_message_mentions_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError) as exc_info:
        _reject_symlink_database_path(symlink)

    assert "symlink" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# _open_database
# ---------------------------------------------------------------------------


def test_open_database_raises_audit_log_error_for_symlink_path(
    tmp_path: Path,
) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        _open_database(symlink)


def test_open_database_creates_parent_directories(tmp_path: Path) -> None:
    nested_path = tmp_path / "a" / "b" / "c" / "audit.db"

    connection = _open_database(nested_path)
    connection.close()

    assert nested_path.exists()


def test_open_database_sets_row_factory_to_sqlite_row(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    connection = _open_database(database_path)
    row_factory = connection.row_factory
    connection.close()

    assert row_factory is sqlite3.Row


def test_open_database_enables_wal_journal_mode(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    connection = _open_database(database_path)
    cursor = connection.execute("PRAGMA journal_mode")
    mode = cursor.fetchone()[0]
    connection.close()

    assert mode == "wal"


def test_open_database_returns_open_connection(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    connection = _open_database(database_path)
    try:
        cursor = connection.execute("SELECT 1")
        row = cursor.fetchone()
    finally:
        connection.close()

    assert row is not None


# ---------------------------------------------------------------------------
# create_audit_schema
# ---------------------------------------------------------------------------


def test_create_audit_schema_creates_scan_events_table(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    create_audit_schema(database_path)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(_SCAN_EVENTS_COUNT_QUERY)
    count = cursor.fetchone()[0]
    connection.close()
    assert count == 0  # table exists and is empty


def test_create_audit_schema_creates_schema_meta_table(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    create_audit_schema(database_path)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(_SCHEMA_META_COUNT_QUERY)
    count = cursor.fetchone()[0]
    connection.close()
    assert count >= 1  # at least schema_version key was seeded


def test_create_audit_schema_seeds_schema_version(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    create_audit_schema(database_path)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(_SCHEMA_VERSION_QUERY)
    version = cursor.fetchone()[0]
    connection.close()
    assert int(version) == AUDIT_SCHEMA_VERSION


def test_create_audit_schema_seeds_created_at(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    create_audit_schema(database_path)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(
        f"SELECT value FROM {_SCHEMA_META_TABLE} WHERE key = '{_CREATED_AT_KEY}'"
    )
    row = cursor.fetchone()
    connection.close()
    assert row is not None


def test_create_audit_schema_is_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"

    create_audit_schema(database_path)
    create_audit_schema(database_path)  # second call must not raise or corrupt

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(_SCHEMA_VERSION_QUERY)
    version = cursor.fetchone()[0]
    connection.close()
    assert int(version) == AUDIT_SCHEMA_VERSION


def test_create_audit_schema_raises_audit_log_error_for_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        create_audit_schema(symlink)


# ---------------------------------------------------------------------------
# insert_scan_event
# ---------------------------------------------------------------------------


def test_insert_scan_event_inserts_one_row(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(_SCAN_EVENTS_COUNT_QUERY)
    count = cursor.fetchone()[0]
    connection.close()
    assert count == 1


def test_insert_scan_event_sets_scanner_version(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(f"SELECT scanner_version FROM {_SCAN_EVENTS_TABLE}")
    version = cursor.fetchone()[0]
    connection.close()
    assert version == __version__


def test_insert_scan_event_sets_is_clean_true_for_clean_result(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(f"SELECT is_clean FROM {_SCAN_EVENTS_TABLE}")
    is_clean_value = cursor.fetchone()[0]
    connection.close()
    assert is_clean_value == _BOOLEAN_TRUE


def test_insert_scan_event_sets_is_clean_false_for_dirty_result(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_dirty_scan_result(tmp_path / "src" / "main.py")

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(f"SELECT is_clean FROM {_SCAN_EVENTS_TABLE}")
    is_clean_value = cursor.fetchone()[0]
    connection.close()
    assert is_clean_value == _BOOLEAN_FALSE


def test_insert_scan_event_stores_findings_count(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_dirty_scan_result(tmp_path / "src" / "main.py")

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(f"SELECT findings_count FROM {_SCAN_EVENTS_TABLE}")
    findings_count = cursor.fetchone()[0]
    connection.close()
    assert findings_count == len(scan_result.findings)


def test_insert_scan_event_stores_scan_duration(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    connection = sqlite3.connect(str(database_path))
    cursor = connection.execute(f"SELECT scan_duration FROM {_SCAN_EVENTS_TABLE}")
    stored_duration = cursor.fetchone()[0]
    connection.close()
    assert stored_duration == _SAMPLE_SCAN_DURATION


def test_insert_scan_event_raises_audit_log_error_for_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)
    scan_result = _build_clean_scan_result()

    with pytest.raises(AuditLogError):
        insert_scan_event(symlink, scan_result)


# ---------------------------------------------------------------------------
# query_recent_scans
# ---------------------------------------------------------------------------


def test_query_recent_scans_returns_empty_list_when_no_scans(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    result = query_recent_scans(database_path, _RECENT_SCANS_DAYS)

    assert result == []


def test_query_recent_scans_returns_scan_within_cutoff(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    rows = query_recent_scans(database_path, _RECENT_SCANS_DAYS)

    assert len(rows) == 1


def test_query_recent_scans_returns_dicts(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    rows = query_recent_scans(database_path, _RECENT_SCANS_DAYS)

    assert isinstance(rows[0], dict)


def test_query_recent_scans_excludes_events_older_than_cutoff(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    # Insert a row with a timestamp far in the past
    old_timestamp = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=_RECENT_SCANS_DAYS + 1)
    ).isoformat()
    connection = sqlite3.connect(str(database_path))
    connection.execute(
        f"INSERT INTO {_SCAN_EVENTS_TABLE} "
        "(timestamp, scanner_version, repository, branch, files_scanned, "
        "findings_count, findings_json, is_clean, scan_duration) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            old_timestamp,
            __version__,
            _SAMPLE_GIT_REPO_ROOT,
            _SAMPLE_GIT_BRANCH,
            _SAMPLE_FILES_SCANNED,
            0,
            "[]",
            _BOOLEAN_TRUE,
            _SAMPLE_SCAN_DURATION,
        ),
    )
    connection.commit()
    connection.close()

    rows = query_recent_scans(database_path, _RECENT_SCANS_DAYS)

    assert rows == []


def test_query_recent_scans_returns_rows_ordered_by_timestamp_descending(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)
        insert_scan_event(database_path, scan_result)

    rows = query_recent_scans(database_path, _RECENT_SCANS_DAYS)

    timestamps = [row["timestamp"] for row in rows]
    assert timestamps == sorted(timestamps, reverse=True)


def test_query_recent_scans_raises_audit_log_error_for_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        query_recent_scans(symlink, _RECENT_SCANS_DAYS)


# ---------------------------------------------------------------------------
# get_last_scan
# ---------------------------------------------------------------------------


def test_get_last_scan_returns_none_when_no_scans_exist(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    result = get_last_scan(database_path)

    assert result is None


def test_get_last_scan_returns_dict_after_scan_inserted(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    scan_result = _build_clean_scan_result()

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, scan_result)

    last = get_last_scan(database_path)

    assert isinstance(last, dict)


def test_get_last_scan_returns_most_recent_scan(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)
    clean_result = _build_clean_scan_result()
    dirty_result = _build_dirty_scan_result(tmp_path / "src" / "main.py")

    with (
        patch("phi_scan.audit._get_repository_path", return_value=_SAMPLE_GIT_REPO_ROOT),
        patch("phi_scan.audit._get_current_branch", return_value=_SAMPLE_GIT_BRANCH),
    ):
        insert_scan_event(database_path, clean_result)
        insert_scan_event(database_path, dirty_result)

    last = get_last_scan(database_path)

    assert last is not None
    assert last["is_clean"] == _BOOLEAN_FALSE  # dirty_result was inserted last


def test_get_last_scan_raises_audit_log_error_for_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        get_last_scan(symlink)


# ---------------------------------------------------------------------------
# get_schema_version
# ---------------------------------------------------------------------------


def test_get_schema_version_returns_audit_schema_version(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    version = get_schema_version(database_path)

    assert version == AUDIT_SCHEMA_VERSION


def test_get_schema_version_returns_integer(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    version = get_schema_version(database_path)

    assert isinstance(version, int)


def test_get_schema_version_raises_audit_log_error_when_key_absent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    # Create schema_meta table but omit the schema_version key
    connection = sqlite3.connect(str(database_path))
    connection.execute(
        f"CREATE TABLE {_SCHEMA_META_TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.commit()
    connection.close()

    with pytest.raises(AuditLogError):
        get_schema_version(database_path)


def test_get_schema_version_raises_audit_log_error_for_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        get_schema_version(symlink)


# ---------------------------------------------------------------------------
# migrate_schema
# ---------------------------------------------------------------------------


def test_migrate_schema_is_noop_when_from_equals_to(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    migrate_schema(database_path, AUDIT_SCHEMA_VERSION, AUDIT_SCHEMA_VERSION)  # must not raise


def test_migrate_schema_raises_schema_migration_error_for_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    with pytest.raises(SchemaMigrationError):
        migrate_schema(database_path, _SCHEMA_VERSION_TO, _SCHEMA_VERSION_FROM)


def test_migrate_schema_downgrade_error_mentions_versions(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    with pytest.raises(SchemaMigrationError) as exc_info:
        migrate_schema(database_path, _SCHEMA_VERSION_TO, _SCHEMA_VERSION_FROM)

    error_text = str(exc_info.value)
    assert str(_SCHEMA_VERSION_TO) in error_text
    assert str(_SCHEMA_VERSION_FROM) in error_text


def test_migrate_schema_raises_schema_migration_error_when_migration_missing(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    # _MIGRATIONS is empty for schema v1 — no path from 1 to 2 exists
    with pytest.raises(SchemaMigrationError):
        migrate_schema(database_path, _SCHEMA_VERSION_FROM, _SCHEMA_VERSION_TO)


def test_migrate_schema_applies_migration_and_updates_version(tmp_path: Path) -> None:
    database_path = tmp_path / "audit.db"
    _setup_schema(database_path)

    patched_migrations = {_SCHEMA_VERSION_FROM: _SAMPLE_MIGRATION_SQL}
    with patch("phi_scan.audit._MIGRATIONS", patched_migrations):
        migrate_schema(database_path, _SCHEMA_VERSION_FROM, _SCHEMA_VERSION_TO)

    version = get_schema_version(database_path)
    assert version == _SCHEMA_VERSION_TO


def test_migrate_schema_raises_audit_log_error_for_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.db"
    target.touch()
    symlink = tmp_path / "link.db"
    symlink.symlink_to(target)

    with pytest.raises(AuditLogError):
        migrate_schema(symlink, _SCHEMA_VERSION_FROM, _SCHEMA_VERSION_TO)


# ---------------------------------------------------------------------------
# _get_current_timestamp
# ---------------------------------------------------------------------------


def test_current_timestamp_returns_string() -> None:
    timestamp = _get_current_timestamp()

    assert isinstance(timestamp, str)


def test_current_timestamp_is_parseable_as_datetime() -> None:
    timestamp = _get_current_timestamp()

    parsed = datetime.datetime.fromisoformat(timestamp)
    assert isinstance(parsed, datetime.datetime)


def test_current_timestamp_is_utc() -> None:
    timestamp = _get_current_timestamp()

    parsed = datetime.datetime.fromisoformat(timestamp)
    assert parsed.tzinfo is not None
    utc_offset = parsed.utcoffset()
    assert utc_offset == datetime.timedelta(0)


def test_current_timestamp_contains_date_time_separator() -> None:
    timestamp = _get_current_timestamp()

    assert "T" in timestamp


# ---------------------------------------------------------------------------
# _serialize_findings
# ---------------------------------------------------------------------------


def test_serialize_findings_returns_valid_json_string(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert isinstance(parsed, list)


def test_serialize_findings_returns_empty_json_array_for_no_findings() -> None:
    serialized = _serialize_findings(())

    assert json.loads(serialized) == []


def test_serialize_findings_includes_value_hash(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["value_hash"] == _SAMPLE_VALUE_HASH


def test_serialize_findings_includes_entity_type(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["entity_type"] == _SAMPLE_ENTITY_TYPE


def test_serialize_findings_includes_hipaa_category(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["hipaa_category"] == PhiCategory.SSN.value


def test_serialize_findings_includes_severity(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["severity"] == SeverityLevel.HIGH.value


def test_serialize_findings_excludes_code_context(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert "code_context" not in parsed[0]


def test_serialize_findings_includes_line_number(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["line_number"] == _SAMPLE_LINE_NUMBER


def test_serialize_findings_includes_confidence(tmp_path: Path) -> None:
    finding = _build_scan_finding(tmp_path / "src" / "main.py")

    serialized = _serialize_findings((finding,))

    parsed = json.loads(serialized)
    assert parsed[0]["confidence"] == _SAMPLE_CONFIDENCE


def test_serialize_findings_serializes_multiple_findings(tmp_path: Path) -> None:
    finding_a = _build_scan_finding(tmp_path / "a.py")
    finding_b = _build_scan_finding(tmp_path / "b.py")

    serialized = _serialize_findings((finding_a, finding_b))

    parsed = json.loads(serialized)
    assert len(parsed) == 2  # noqa: PLR2004 — two findings passed above


# ---------------------------------------------------------------------------
# _get_current_branch
# ---------------------------------------------------------------------------


def test_get_current_branch_returns_branch_name_from_git() -> None:
    mock_result = _build_subprocess_result(stdout=_SAMPLE_GIT_BRANCH_OUTPUT)

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        branch = _get_current_branch()

    assert branch == _SAMPLE_GIT_BRANCH


def test_get_current_branch_strips_trailing_newline() -> None:
    mock_result = _build_subprocess_result(stdout=_SAMPLE_GIT_BRANCH_OUTPUT)

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        branch = _get_current_branch()

    assert "\n" not in branch


def test_get_current_branch_returns_unknown_on_os_error() -> None:
    with patch("phi_scan.audit.subprocess.run", side_effect=OSError("no git")):
        branch = _get_current_branch()

    assert branch == _UNKNOWN_BRANCH


def test_get_current_branch_returns_unknown_when_output_is_empty() -> None:
    mock_result = _build_subprocess_result(stdout=_EMPTY_GIT_OUTPUT)

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        branch = _get_current_branch()

    assert branch == _UNKNOWN_BRANCH


# ---------------------------------------------------------------------------
# _get_repository_path
# ---------------------------------------------------------------------------


def test_get_repository_path_returns_path_from_git() -> None:
    mock_result = _build_subprocess_result(
        stdout=_SAMPLE_GIT_REPO_OUTPUT,
        returncode=_GIT_SUCCESS_RETURN_CODE,
    )

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        repo_path = _get_repository_path()

    assert repo_path == _SAMPLE_GIT_REPO_ROOT


def test_get_repository_path_strips_trailing_newline() -> None:
    mock_result = _build_subprocess_result(
        stdout=_SAMPLE_GIT_REPO_OUTPUT,
        returncode=_GIT_SUCCESS_RETURN_CODE,
    )

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        repo_path = _get_repository_path()

    assert "\n" not in repo_path


def test_get_repository_path_returns_cwd_on_git_failure() -> None:
    mock_result = _build_subprocess_result(
        stdout=_EMPTY_GIT_OUTPUT,
        returncode=_GIT_FAILURE_RETURN_CODE,
    )

    with patch("phi_scan.audit.subprocess.run", return_value=mock_result):
        repo_path = _get_repository_path()

    # Should return something (CWD), not raise
    assert isinstance(repo_path, str)
    assert repo_path  # not empty


def test_get_repository_path_returns_cwd_on_os_error() -> None:
    with patch("phi_scan.audit.subprocess.run", side_effect=OSError("no git")):
        repo_path = _get_repository_path()

    assert isinstance(repo_path, str)
    assert repo_path  # not empty
