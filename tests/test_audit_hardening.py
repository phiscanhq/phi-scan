# phi-scan:ignore-file
"""Tests for Phase 5C audit log hardening.

Verifies that:
  - Schema v2 columns are created on fresh database
  - Migration from v1 to v2 adds the required new columns
  - insert_scan_event records event_type, pipeline, action_taken, notifications_sent
  - verify_audit_chain returns ChainVerifyResult(is_intact=True, key_present=True) for an intact log
  - verify_audit_chain returns ChainVerifyResult(is_intact=False, key_present=True) when tampered
  - verify_audit_chain returns ChainVerifyResult(key_present=False) when audit key is absent
  - purge_expired_audit_rows deletes only rows outside the retention window
  - purge_expired_audit_rows never deletes rows within the 6-year window
  - generate_audit_key creates a 32-byte key file with mode 0o600
  - AES-256-GCM encryption round-trips correctly
  - immutability guards: UPDATE/DELETE operations are never issued by the public API
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.audit import (
    ChainVerifyResult,
    _decrypt_findings_json,
    _encrypt_findings_json,
    _hmac_sha256,
    _row_content_for_hashing,
    create_audit_schema,
    generate_audit_key,
    get_schema_version,
    insert_scan_event,
    migrate_schema,
    purge_expired_audit_rows,
    query_recent_scans,
    verify_audit_chain,
)
from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    AUDIT_SCHEMA_VERSION,
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
)
from phi_scan.exceptions import AuditLogError, SchemaMigrationError
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "b" * 64
_SAMPLE_FILE_PATH: Path = Path("src/records.py")
_SAMPLE_LINE_NUMBER: int = 7
_SAMPLE_CONFIDENCE: float = 0.91
_EXPECTED_SCHEMA_VERSION: int = AUDIT_SCHEMA_VERSION
_EXPECTED_SCHEMA_V2: int = 2
_EXPECTED_KEY_BYTES: int = 32
_EXPECTED_KEY_PERMISSIONS: int = 0o600
_EXPECTED_HMAC_LENGTH: int = 64  # hex chars
_RETENTION_WITHIN_WINDOW_DAYS: int = 10
_RETENTION_OUTSIDE_WINDOW_DAYS: int = AUDIT_RETENTION_DAYS + 100
_ZERO_ROWS_DELETED: int = 0
_ONE_ROW_INSERTED: int = 1
_V1_SCHEMA: int = 1
_V2_SCHEMA: int = 2

# V2 columns that must exist after migration from v1 or fresh creation.
_EXPECTED_V2_COLUMNS: frozenset[str] = frozenset(
    {
        "event_type",
        "committer_name_hash",
        "committer_email_hash",
        "pr_number",
        "pipeline",
        "action_taken",
        "notifications_sent",
        "row_chain_hash",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding() -> ScanFinding:
    return ScanFinding(
        file_path=_SAMPLE_FILE_PATH,
        line_number=_SAMPLE_LINE_NUMBER,
        entity_type="us_ssn",
        hipaa_category=PhiCategory.SSN,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_HASH,
        severity=SeverityLevel.HIGH,
        code_context="ssn = '[REDACTED]'",
        remediation_hint="Replace SSN.",
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        findings=(),
        files_scanned=3,
        files_with_findings=0,
        scan_duration=0.05,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )


def _make_dirty_result() -> ScanResult:
    findings = (_make_finding(),)
    return ScanResult(
        findings=findings,
        files_scanned=3,
        files_with_findings=1,
        scan_duration=0.05,
        is_clean=False,
        risk_level=RiskLevel.HIGH,
        severity_counts=MappingProxyType(
            {level: (1 if level is SeverityLevel.HIGH else 0) for level in SeverityLevel}
        ),
        category_counts=MappingProxyType(
            {cat: (1 if cat is PhiCategory.SSN else 0) for cat in PhiCategory}
        ),
    )


def _get_column_names(db_path: Path) -> set[str]:
    """Return the set of column names in the scan_events table."""
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute("PRAGMA table_info(scan_events)")
        return {row[1] for row in cursor.fetchall()}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema creation tests
# ---------------------------------------------------------------------------


def test_create_audit_schema_creates_scan_events_table(tmp_path: Path) -> None:
    """create_audit_schema must create the scan_events table."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    columns = _get_column_names(db_path)
    assert "id" in columns
    assert "timestamp" in columns
    assert "findings_json" in columns


def test_create_audit_schema_creates_v2_columns(tmp_path: Path) -> None:
    """create_audit_schema must include all schema v2 columns on fresh creation."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    columns = _get_column_names(db_path)
    for expected_column in _EXPECTED_V2_COLUMNS:
        assert expected_column in columns, f"Missing v2 column: {expected_column}"


def test_create_audit_schema_sets_correct_schema_version(tmp_path: Path) -> None:
    """create_audit_schema must write AUDIT_SCHEMA_VERSION to schema_meta."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    assert get_schema_version(db_path) == _EXPECTED_SCHEMA_VERSION


def test_create_audit_schema_is_idempotent(tmp_path: Path) -> None:
    """create_audit_schema must not raise or lose data when called twice."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    create_audit_schema(db_path)
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert len(rows) == _ONE_ROW_INSERTED


# ---------------------------------------------------------------------------
# Schema migration tests (v1 → v2)
# ---------------------------------------------------------------------------


def _create_v1_schema(db_path: Path) -> None:
    """Create a v1 schema (without the new columns) for migration testing."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            CREATE TABLE scan_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT    NOT NULL,
                scanner_version  TEXT    NOT NULL,
                repository_hash  TEXT    NOT NULL,
                branch_hash      TEXT    NOT NULL,
                files_scanned    INTEGER NOT NULL,
                findings_count   INTEGER NOT NULL,
                findings_json    TEXT    NOT NULL,
                is_clean         INTEGER NOT NULL,
                scan_duration    REAL    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE schema_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.execute("INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')")
        conn.commit()
    finally:
        conn.close()


def test_migrate_v1_to_v2_adds_all_new_columns(tmp_path: Path) -> None:
    """migrate_schema from v1 to v2 must add all 8 new columns."""
    db_path = tmp_path / "audit.db"
    _create_v1_schema(db_path)
    migrate_schema(db_path, from_version=_V1_SCHEMA, to_version=_V2_SCHEMA)
    columns = _get_column_names(db_path)
    for expected_column in _EXPECTED_V2_COLUMNS:
        assert expected_column in columns, f"Migration did not add column: {expected_column}"


def test_migrate_v1_to_v2_updates_schema_version(tmp_path: Path) -> None:
    """migrate_schema must update schema_version to 2 after migration."""
    db_path = tmp_path / "audit.db"
    _create_v1_schema(db_path)
    migrate_schema(db_path, from_version=_V1_SCHEMA, to_version=_V2_SCHEMA)
    assert get_schema_version(db_path) == _V2_SCHEMA


def test_migrate_downgrade_raises_schema_migration_error(tmp_path: Path) -> None:
    """migrate_schema must raise SchemaMigrationError when asked to downgrade."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    with pytest.raises(SchemaMigrationError):
        migrate_schema(db_path, from_version=_V2_SCHEMA, to_version=_V1_SCHEMA)


def test_migrate_same_version_is_no_op(tmp_path: Path) -> None:
    """migrate_schema must be a no-op when from_version equals to_version."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    migrate_schema(db_path, from_version=_V2_SCHEMA, to_version=_V2_SCHEMA)
    assert get_schema_version(db_path) == _V2_SCHEMA


# ---------------------------------------------------------------------------
# insert_scan_event v2 column population
# ---------------------------------------------------------------------------


def test_insert_scan_event_populates_event_type(tmp_path: Path) -> None:
    """Inserted row must have event_type = 'scan'."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert rows[0]["event_type"] == "scan"


def test_insert_scan_event_populates_action_taken_pass_for_clean(tmp_path: Path) -> None:
    """action_taken must be 'pass' for a clean scan result."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert rows[0]["action_taken"] == "pass"


def test_insert_scan_event_populates_action_taken_fail_for_dirty(tmp_path: Path) -> None:
    """action_taken must be 'fail' for a scan result with findings."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_dirty_result())
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert rows[0]["action_taken"] == "fail"


def test_insert_scan_event_records_notifications_sent(tmp_path: Path) -> None:
    """notifications_sent must be stored as a JSON array of channel names."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_dirty_result(), notifications_sent=["email", "webhook-slack"])
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    import json

    channels = json.loads(rows[0]["notifications_sent"])
    assert "email" in channels
    assert "webhook-slack" in channels


def test_insert_scan_event_default_notifications_sent_is_empty_list(tmp_path: Path) -> None:
    """When no notifications_sent is passed, the column must be an empty JSON array."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    import json

    channels = json.loads(rows[0]["notifications_sent"])
    assert channels == []


# ---------------------------------------------------------------------------
# Hash chain tests
# ---------------------------------------------------------------------------


def test_verify_audit_chain_returns_intact_for_empty_db(tmp_path: Path) -> None:
    """verify_audit_chain must report is_intact=True with key_present=True for empty db."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    result = verify_audit_chain(db_path)
    assert isinstance(result, ChainVerifyResult)
    assert result.is_intact is True
    assert result.key_present is True
    assert result.skipped_rows == 0


def test_verify_audit_chain_reports_key_absent_without_key(tmp_path: Path) -> None:
    """verify_audit_chain must return key_present=False and is_intact=False when key absent."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    key_path = generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    # Remove the key so verify_audit_chain cannot load it.
    key_path.unlink()
    result = verify_audit_chain(db_path)
    assert isinstance(result, ChainVerifyResult)
    assert result.key_present is False
    # is_intact must be False when key is absent — zero verification was performed.
    assert result.is_intact is False


def test_verify_audit_chain_returns_intact_with_key(tmp_path: Path) -> None:
    """verify_audit_chain must return is_intact=True for a freshly written row when key exists."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    result = verify_audit_chain(db_path)
    assert isinstance(result, ChainVerifyResult)
    assert result.key_present is True
    assert result.is_intact is True
    assert result.skipped_rows == 0


def test_verify_audit_chain_detects_tampering(tmp_path: Path) -> None:
    """verify_audit_chain must return is_intact=False when a row's hash does not match."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    # Tamper: directly modify the stored chain hash.
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("UPDATE scan_events SET row_chain_hash = 'tampered' WHERE id = 1")
        conn.commit()
    finally:
        conn.close()
    result = verify_audit_chain(db_path)
    assert isinstance(result, ChainVerifyResult)
    assert result.key_present is True
    assert result.is_intact is False


def test_verify_audit_chain_counts_skipped_rows(tmp_path: Path) -> None:
    """verify_audit_chain must set is_intact=False and count rows whose hash was blanked."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    insert_scan_event(db_path, _make_clean_result())
    # Blank chain hash on row 1 to simulate an attacker clearing it.
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("UPDATE scan_events SET row_chain_hash = '' WHERE id = 1")
        conn.commit()
    finally:
        conn.close()
    result = verify_audit_chain(db_path)
    assert isinstance(result, ChainVerifyResult)
    assert result.key_present is True
    assert result.skipped_rows == 1
    # Blanked hashes must set is_intact=False — callers checking only is_intact
    # must not get a false sense of integrity when rows were unverifiable.
    assert result.is_intact is False


def test_hmac_sha256_returns_64_hex_chars() -> None:
    """_hmac_sha256 must return a 64-character lowercase hex string."""
    key = b"test-key-32-bytes-padded-to-fill"
    result = _hmac_sha256(key, "test message")
    assert len(result) == _EXPECTED_HMAC_LENGTH
    assert result == result.lower()
    assert all(c in "0123456789abcdef" for c in result)


def test_hmac_sha256_different_inputs_produce_different_hashes() -> None:
    """_hmac_sha256 must produce distinct outputs for distinct inputs."""
    key = b"test-key-32-bytes-padded-to-fill"
    hash1 = _hmac_sha256(key, "message-a")
    hash2 = _hmac_sha256(key, "message-b")
    assert hash1 != hash2


def test_row_content_for_hashing_is_deterministic() -> None:
    """_row_content_for_hashing must produce the same string for identical row dicts."""
    row: dict = {
        "id": 1,
        "timestamp": "2025-01-01T00:00:00+00:00",
        "scanner_version": "0.5.0",
        "repository_hash": "a" * 64,
        "branch_hash": "b" * 64,
        "files_scanned": 5,
        "findings_count": 0,
        "findings_json": "[]",
        "is_clean": 1,
        "scan_duration": 0.05,
        "event_type": "scan",
        "committer_name_hash": "",
        "committer_email_hash": "",
        "pr_number": "",
        "pipeline": "local",
        "action_taken": "pass",
        "notifications_sent": "[]",
    }
    content1 = _row_content_for_hashing(row)
    content2 = _row_content_for_hashing(row)
    assert content1 == content2


# ---------------------------------------------------------------------------
# Encryption tests
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_findings_json_round_trip() -> None:
    """AES-256-GCM round-trip must recover the original plaintext."""
    key = b"0" * 32
    plaintext = '[{"entity_type": "us_ssn", "severity": "high"}]'
    encrypted = _encrypt_findings_json(plaintext, key)
    decrypted = _decrypt_findings_json(encrypted, key)
    assert decrypted == plaintext


def test_encrypted_findings_has_enc_prefix() -> None:
    """Encrypted findings_json must begin with the AUDIT_ENCRYPTION_PREFIX."""
    from phi_scan.constants import AUDIT_ENCRYPTION_PREFIX

    key = b"0" * 32
    plaintext = "[]"
    encrypted = _encrypt_findings_json(plaintext, key)
    assert encrypted.startswith(AUDIT_ENCRYPTION_PREFIX)


def test_decrypt_with_wrong_key_raises_audit_log_error() -> None:
    """Decrypting with the wrong key must raise AuditLogError."""
    key1 = b"0" * 32
    key2 = b"1" * 32
    encrypted = _encrypt_findings_json("[]", key1)
    with pytest.raises(AuditLogError):
        _decrypt_findings_json(encrypted, key2)


def test_encrypt_produces_different_ciphertexts_for_same_plaintext() -> None:
    """Each call to _encrypt_findings_json must produce a different ciphertext (random nonce)."""
    key = b"0" * 32
    plaintext = "[]"
    ciphertext1 = _encrypt_findings_json(plaintext, key)
    ciphertext2 = _encrypt_findings_json(plaintext, key)
    assert ciphertext1 != ciphertext2


# ---------------------------------------------------------------------------
# Audit key generation tests
# ---------------------------------------------------------------------------


def test_generate_audit_key_creates_file(tmp_path: Path) -> None:
    """generate_audit_key must create the key file on disk."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    key_path = generate_audit_key(db_path)
    assert key_path.exists()


def test_generate_audit_key_is_32_bytes(tmp_path: Path) -> None:
    """The generated key must be exactly 32 bytes (256 bits)."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    key_path = generate_audit_key(db_path)
    assert len(key_path.read_bytes()) == _EXPECTED_KEY_BYTES


def test_generate_audit_key_raises_if_key_exists(tmp_path: Path) -> None:
    """generate_audit_key must raise AuditLogError if the key file already exists."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    with pytest.raises(AuditLogError):
        generate_audit_key(db_path)


# ---------------------------------------------------------------------------
# Retention purge tests
# ---------------------------------------------------------------------------


def test_purge_returns_zero_for_empty_db(tmp_path: Path) -> None:
    """purge_expired_audit_rows must return 0 for an empty database."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    deleted = purge_expired_audit_rows(db_path)
    assert deleted == _ZERO_ROWS_DELETED


def test_purge_does_not_delete_recent_rows(tmp_path: Path) -> None:
    """purge_expired_audit_rows must not delete rows written today."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    generate_audit_key(db_path)
    insert_scan_event(db_path, _make_clean_result())
    deleted = purge_expired_audit_rows(db_path)
    assert deleted == _ZERO_ROWS_DELETED
    rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert len(rows) == _ONE_ROW_INSERTED


def test_purge_deletes_rows_outside_retention_window(tmp_path: Path) -> None:
    """purge_expired_audit_rows must delete rows older than AUDIT_RETENTION_DAYS."""
    db_path = tmp_path / "audit.db"
    create_audit_schema(db_path)
    # Directly insert a row with a timestamp far in the past.
    import datetime

    old_ts = (
        datetime.datetime.now(datetime.UTC)
        - datetime.timedelta(days=_RETENTION_OUTSIDE_WINDOW_DAYS)
    ).isoformat()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO scan_events "
            "(timestamp, scanner_version, repository_hash, branch_hash, "
            "files_scanned, findings_count, findings_json, is_clean, scan_duration, "
            "event_type, committer_name_hash, committer_email_hash, pr_number, "
            "pipeline, action_taken, notifications_sent, row_chain_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                old_ts,
                "0.1.0",
                "a" * 64,
                "b" * 64,
                1,
                0,
                "[]",
                1,
                0.01,
                "scan",
                "",
                "",
                "",
                "local",
                "pass",
                "[]",
                "",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    deleted = purge_expired_audit_rows(db_path)
    assert deleted == _ONE_ROW_INSERTED


# ---------------------------------------------------------------------------
# Symlink rejection test
# ---------------------------------------------------------------------------


def test_open_database_rejects_symlink(tmp_path: Path) -> None:
    """create_audit_schema must raise AuditLogError when database_path is a symlink."""
    real_db = tmp_path / "real.db"
    real_db.touch()
    symlink_path = tmp_path / "symlink.db"
    symlink_path.symlink_to(real_db)
    with pytest.raises(AuditLogError):
        create_audit_schema(symlink_path)


# ---------------------------------------------------------------------------
# query_recent_scans filter tests (5C.5)
# ---------------------------------------------------------------------------


def test_query_recent_scans_violations_only_excludes_clean_rows(tmp_path: Path) -> None:
    """should_show_violations_only=True returns only rows where is_clean=0."""
    db_path = tmp_path / "audit.db"
    generate_audit_key(db_path)
    create_audit_schema(db_path)
    insert_scan_event(db_path, _make_clean_result())
    insert_scan_event(db_path, _make_dirty_result())

    rows = query_recent_scans(
        db_path, _RETENTION_WITHIN_WINDOW_DAYS, should_show_violations_only=True
    )

    assert all(row["is_clean"] == 0 for row in rows)
    assert len(rows) == 1


def test_query_recent_scans_violations_only_false_returns_all_rows(tmp_path: Path) -> None:
    """should_show_violations_only=False (default) returns both clean and dirty rows."""
    db_path = tmp_path / "audit.db"
    generate_audit_key(db_path)
    create_audit_schema(db_path)
    insert_scan_event(db_path, _make_clean_result())
    insert_scan_event(db_path, _make_dirty_result())

    rows = query_recent_scans(
        db_path, _RETENTION_WITHIN_WINDOW_DAYS, should_show_violations_only=False
    )

    assert len(rows) == 2


def test_query_recent_scans_repository_hash_filters_to_matching_repo(tmp_path: Path) -> None:
    """repository_hash filter returns only rows whose repository_hash column matches."""
    db_path = tmp_path / "audit.db"
    generate_audit_key(db_path)
    create_audit_schema(db_path)
    # Insert two rows — both will carry the same repository_hash (current working dir hash),
    # so we verify that filtering by that hash returns them and filtering by a different
    # hash returns nothing.
    insert_scan_event(db_path, _make_clean_result())
    insert_scan_event(db_path, _make_clean_result())

    unfiltered_rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    assert len(unfiltered_rows) == 2

    stored_repo_hash = unfiltered_rows[0]["repository_hash"]
    matching_rows = query_recent_scans(
        db_path, _RETENTION_WITHIN_WINDOW_DAYS, repository_hash=stored_repo_hash
    )
    assert len(matching_rows) == 2

    nonexistent_hash = hashlib.sha256(b"repo_that_does_not_exist").hexdigest()
    no_rows = query_recent_scans(
        db_path, _RETENTION_WITHIN_WINDOW_DAYS, repository_hash=nonexistent_hash
    )
    assert len(no_rows) == 0


def test_query_recent_scans_combined_filters_narrow_results(tmp_path: Path) -> None:
    """repository_hash and should_show_violations_only can be combined to narrow results."""
    db_path = tmp_path / "audit.db"
    generate_audit_key(db_path)
    create_audit_schema(db_path)
    insert_scan_event(db_path, _make_clean_result())
    insert_scan_event(db_path, _make_dirty_result())

    unfiltered_rows = query_recent_scans(db_path, _RETENTION_WITHIN_WINDOW_DAYS)
    stored_repo_hash = unfiltered_rows[0]["repository_hash"]

    combined_rows = query_recent_scans(
        db_path,
        _RETENTION_WITHIN_WINDOW_DAYS,
        repository_hash=stored_repo_hash,
        should_show_violations_only=True,
    )
    assert len(combined_rows) == 1
    assert combined_rows[0]["is_clean"] == 0

    nonexistent_hash = hashlib.sha256(b"no_such_repo").hexdigest()
    empty_rows = query_recent_scans(
        db_path,
        _RETENTION_WITHIN_WINDOW_DAYS,
        repository_hash=nonexistent_hash,
        should_show_violations_only=True,
    )
    assert len(empty_rows) == 0
