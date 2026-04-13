"""SQLite audit logging — HIPAA-compliant immutable scan event storage.

Audit records are INSERT-only. No UPDATE or DELETE operations are ever issued.
HIPAA (45 CFR §164.530(j)) requires audit logs to be retained for a minimum of
six years. Corrections are new INSERT rows referencing the original entry —
never modifications to existing rows.

Schema v2 additions (Phase 5):
  event_type, committer_name_hash, committer_email_hash, pr_number, pipeline,
  action_taken, notifications_sent, row_chain_hash.

Schema v3 additions (Phase 7A):
  ai_input_tokens, ai_output_tokens, ai_cost_usd.

Hash chain (5C.8):
  See ``phi_scan.audit.hash_chain`` for the HMAC-SHA256 implementation.
  Satisfies NIST SP 800-53 AU-9 and AU-10.

Encryption (5C.9):
  See ``phi_scan.audit.crypto`` for AES-256-GCM encryption of findings_json.

Retention purge (5C.4):
  ``purge_expired_audit_rows`` deletes rows older than AUDIT_RETENTION_DAYS.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import subprocess  # noqa: F401 — re-exported so tests can patch phi_scan.audit.subprocess.run
from pathlib import Path
from typing import Any

from phi_scan import __version__
from phi_scan.audit._shared import (
    _BOOLEAN_FALSE,
    _BOOLEAN_TRUE,
    _CREATED_AT_KEY,
    _DATABASE_ERROR,
    _EVENT_TYPE_SCAN,
    _GIT_COMMITTER_EMAIL_ARGS,
    _GIT_COMMITTER_NAME_ARGS,
    _LAST_SCAN_LIMIT,
    _NOTIFICATIONS_EMPTY_JSON,
    _SCAN_EVENTS_TABLE,
    _SCHEMA_META_TABLE,
    _SCHEMA_VERSION_KEY,
    _SCHEMA_VERSION_MISSING_ERROR,
    _detect_pipeline,
    _detect_pr_number,
    _get_current_timestamp,
    _hash_git_committer_field,
    _open_database,
)
from phi_scan.audit._shared import (
    _UNKNOWN_BRANCH as _UNKNOWN_BRANCH,
)
from phi_scan.audit._shared import (
    _get_current_branch as _get_current_branch,
)
from phi_scan.audit._shared import (
    _get_current_repository_path as _get_current_repository_path,
)
from phi_scan.audit._shared import (
    _reject_symlink_database_path as _reject_symlink_database_path,
)

# Crypto submodule — re-exported for public tests/callers.
from phi_scan.audit.crypto import (
    _assert_no_raw_phi_fields as _assert_no_raw_phi_fields,
)
from phi_scan.audit.crypto import (
    _audit_key_path as _audit_key_path,
)
from phi_scan.audit.crypto import (
    _decrypt_findings_json as _decrypt_findings_json,
)
from phi_scan.audit.crypto import (
    _encrypt_findings_json as _encrypt_findings_json,
)
from phi_scan.audit.crypto import (
    _load_audit_key as _load_audit_key,
)
from phi_scan.audit.crypto import (
    _redact_key_path as _redact_key_path,
)
from phi_scan.audit.crypto import (
    _serialize_and_encrypt,
)
from phi_scan.audit.crypto import (
    generate_audit_key as generate_audit_key,
)
from phi_scan.audit.hash_chain import (
    _CHAIN_HASH_PLACEHOLDER as _CHAIN_HASH_PLACEHOLDER,
)

# Hash-chain submodule — re-exported for public tests/callers.
from phi_scan.audit.hash_chain import (
    ChainVerifyResult as ChainVerifyResult,
)
from phi_scan.audit.hash_chain import (
    _attach_chain_hash,
    _compute_row_chain_hash,
)
from phi_scan.audit.hash_chain import (
    _hmac_sha256 as _hmac_sha256,
)
from phi_scan.audit.hash_chain import (
    _row_content_for_hashing as _row_content_for_hashing,
)
from phi_scan.audit.hash_chain import (
    verify_audit_chain as verify_audit_chain,
)
from phi_scan.constants import (
    ACTION_TAKEN_FAIL,
    ACTION_TAKEN_PASS,
    AUDIT_RETENTION_DAYS,
    AUDIT_SCHEMA_VERSION,
)
from phi_scan.exceptions import AuditLogError, SchemaMigrationError
from phi_scan.models import ScanFinding, ScanResult

__all__ = [
    "ChainVerifyResult",
    "create_audit_schema",
    "ensure_current_schema",
    "generate_audit_key",
    "get_last_scan",
    "get_schema_version",
    "insert_scan_event",
    "migrate_schema",
    "purge_expired_audit_rows",
    "query_recent_scans",
    "verify_audit_chain",
]


# ---------------------------------------------------------------------------
# Log and error message templates
# ---------------------------------------------------------------------------

_SCHEMA_DOWNGRADE_ERROR: str = (
    "Cannot downgrade audit schema from version {from_version} to {to_version}"
)
_UNKNOWN_MIGRATION_ERROR: str = (
    "No migration path exists from schema version {from_version} "
    "to {to_version} — add the SQL to _MIGRATIONS"
)

# ---------------------------------------------------------------------------
# Schema SQL — table names are module-level constants, not user input.
# ---------------------------------------------------------------------------

_AI_USAGE_ZERO_TOKENS: int = 0
_AI_USAGE_ZERO_COST_USD: float = 0.0

_CREATE_SCAN_EVENTS_V1_SQL: str = f"""
    CREATE TABLE IF NOT EXISTS {_SCAN_EVENTS_TABLE} (
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
"""

# v2 CREATE — includes all new columns with DEFAULT values so ALTER migration
# and fresh creation use identical column sets.
_CREATE_SCAN_EVENTS_SQL: str = f"""
    CREATE TABLE IF NOT EXISTS {_SCAN_EVENTS_TABLE} (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp             TEXT    NOT NULL,
        scanner_version       TEXT    NOT NULL,
        repository_hash       TEXT    NOT NULL,
        branch_hash           TEXT    NOT NULL,
        files_scanned         INTEGER NOT NULL,
        findings_count        INTEGER NOT NULL,
        findings_json         TEXT    NOT NULL,
        is_clean              INTEGER NOT NULL,
        scan_duration         REAL    NOT NULL,
        event_type            TEXT    NOT NULL DEFAULT 'scan',
        committer_name_hash   TEXT    NOT NULL DEFAULT '',
        committer_email_hash  TEXT    NOT NULL DEFAULT '',
        pr_number             TEXT    NOT NULL DEFAULT '',
        pipeline              TEXT    NOT NULL DEFAULT '',
        action_taken          TEXT    NOT NULL DEFAULT '',
        notifications_sent    TEXT    NOT NULL DEFAULT '[]',
        row_chain_hash        TEXT    NOT NULL DEFAULT '',
        ai_input_tokens       INTEGER NOT NULL DEFAULT 0,
        ai_output_tokens      INTEGER NOT NULL DEFAULT 0,
        ai_cost_usd           REAL    NOT NULL DEFAULT 0.0
    )
"""
_CREATE_SCHEMA_META_SQL: str = f"""
    CREATE TABLE IF NOT EXISTS {_SCHEMA_META_TABLE} (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
"""
_INSERT_META_SQL: str = f"INSERT OR IGNORE INTO {_SCHEMA_META_TABLE} (key, value) VALUES (?, ?)"
_UPSERT_SCHEMA_VERSION_SQL: str = (
    f"INSERT INTO {_SCHEMA_META_TABLE} (key, value) VALUES (?, ?)"
    f" ON CONFLICT(key) DO UPDATE SET value = excluded.value"
)
_INSERT_SCAN_EVENT_SQL: str = f"""
    INSERT INTO {_SCAN_EVENTS_TABLE}
        (timestamp, scanner_version, repository_hash, branch_hash,
         files_scanned, findings_count, findings_json, is_clean, scan_duration,
         event_type, committer_name_hash, committer_email_hash,
         pr_number, pipeline, action_taken, notifications_sent, row_chain_hash,
         ai_input_tokens, ai_output_tokens, ai_cost_usd)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_RECENT_SCANS_BASE_SQL: str = f"SELECT * FROM {_SCAN_EVENTS_TABLE} WHERE timestamp >= ?"
_FILTER_REPOSITORY_HASH_SQL: str = " AND repository_hash = ?"
_FILTER_VIOLATIONS_ONLY_SQL: str = " AND is_clean = ?"
_ORDER_BY_TIMESTAMP_DESC_SQL: str = " ORDER BY timestamp DESC"
_SELECT_LAST_SCAN_SQL: str = (
    f"SELECT * FROM {_SCAN_EVENTS_TABLE} ORDER BY id DESC LIMIT {_LAST_SCAN_LIMIT}"
)
_SELECT_SCHEMA_VERSION_SQL: str = f"SELECT value FROM {_SCHEMA_META_TABLE} WHERE key = ?"
_DELETE_EXPIRED_ROWS_SQL: str = f"DELETE FROM {_SCAN_EVENTS_TABLE} WHERE timestamp < ?"
_CREATE_SCAN_EVENTS_TIMESTAMP_INDEX_SQL: str = (
    f"CREATE INDEX IF NOT EXISTS idx_scan_events_timestamp ON {_SCAN_EVENTS_TABLE} (timestamp DESC)"
)

# Migration map: from_version → list of SQL statements to advance the schema by one version.
# Each statement is a separate string to avoid fragile semicolon-splitting.
# v1 → v2: add 8 new columns using ALTER TABLE (SQLite supports ADD COLUMN).
_MIGRATION_V1_TO_V2: list[str] = [
    f"ALTER TABLE {_SCAN_EVENTS_TABLE}"
    f" ADD COLUMN event_type TEXT NOT NULL DEFAULT '{_EVENT_TYPE_SCAN}'",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN committer_name_hash TEXT NOT NULL DEFAULT ''",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN committer_email_hash TEXT NOT NULL DEFAULT ''",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN pr_number TEXT NOT NULL DEFAULT ''",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN pipeline TEXT NOT NULL DEFAULT ''",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN action_taken TEXT NOT NULL DEFAULT ''",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE}"
    f" ADD COLUMN notifications_sent TEXT NOT NULL DEFAULT '{_NOTIFICATIONS_EMPTY_JSON}'",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE}"
    f" ADD COLUMN row_chain_hash TEXT NOT NULL DEFAULT '{_CHAIN_HASH_PLACEHOLDER}'",
]

_MIGRATION_V2_TO_V3: list[str] = [
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN ai_input_tokens INTEGER NOT NULL DEFAULT 0",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN ai_output_tokens INTEGER NOT NULL DEFAULT 0",
    f"ALTER TABLE {_SCAN_EVENTS_TABLE} ADD COLUMN ai_cost_usd REAL NOT NULL DEFAULT 0.0",
]

_MIGRATIONS: dict[int, list[str]] = {
    1: _MIGRATION_V1_TO_V2,
    2: _MIGRATION_V2_TO_V3,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_audit_schema(database_path: Path) -> None:
    """Create the audit schema if it does not already exist.

    Idempotent — safe to call on every startup.
    """
    timestamp = _get_current_timestamp()
    connection = _open_database(database_path)
    try:
        connection.execute(_CREATE_SCAN_EVENTS_SQL)
        connection.execute(_CREATE_SCAN_EVENTS_TIMESTAMP_INDEX_SQL)
        connection.execute(_CREATE_SCHEMA_META_SQL)
        connection.execute(_INSERT_META_SQL, (_SCHEMA_VERSION_KEY, str(AUDIT_SCHEMA_VERSION)))
        connection.execute(_INSERT_META_SQL, (_CREATED_AT_KEY, timestamp))
        connection.commit()
    except sqlite3.Error as db_error:
        connection.rollback()
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def ensure_current_schema(database_path: Path) -> None:
    """Create the audit schema and migrate it to the current version if needed."""
    create_audit_schema(database_path)
    current_version = get_schema_version(database_path)
    if current_version < AUDIT_SCHEMA_VERSION:
        migrate_schema(database_path, current_version, AUDIT_SCHEMA_VERSION)


def insert_scan_event(
    database_path: Path,
    scan_result: ScanResult,
    notifications_sent: list[str] | None = None,
) -> None:
    """Record a completed scan as an immutable audit entry.

    findings_json stores only value_hash and metadata fields — raw detected
    values and code_context (which may contain raw PHI) are never persisted.
    """
    delivered_channels: list[str] = notifications_sent or []
    # PHI safety: _serialize_findings() strips raw values and returns a JSON string
    # containing only hashes and metadata. That string is passed to _serialize_and_encrypt.
    encrypted_findings = _serialize_and_encrypt(
        _serialize_findings(scan_result.findings), database_path.parent
    )
    scan_event_row = _build_scan_event_row(scan_result, delivered_channels, encrypted_findings)
    connection = _open_database(database_path)
    try:
        insert_cursor = connection.execute(_INSERT_SCAN_EVENT_SQL, scan_event_row)
        new_row_id = insert_cursor.lastrowid
        chain_hash = _compute_row_chain_hash(database_path, connection, new_row_id, scan_event_row)
        _attach_chain_hash(connection, new_row_id, chain_hash)
        connection.commit()
    except sqlite3.Error as db_error:
        connection.rollback()
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def query_recent_scans(
    database_path: Path,
    lookback_days: int,
    repository_hash: str | None = None,
    should_show_violations_only: bool = False,
) -> list[dict[str, Any]]:
    """Return scan events recorded within the last ``lookback_days`` days."""
    cutoff = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=lookback_days)
    ).isoformat()
    scan_query_sql = _SELECT_RECENT_SCANS_BASE_SQL
    params: list[Any] = [cutoff]
    if repository_hash is not None:
        scan_query_sql += _FILTER_REPOSITORY_HASH_SQL
        params.append(repository_hash)
    if should_show_violations_only:
        scan_query_sql += _FILTER_VIOLATIONS_ONLY_SQL
        params.append(_BOOLEAN_FALSE)
    scan_query_sql += _ORDER_BY_TIMESTAMP_DESC_SQL
    connection = _open_database(database_path)
    try:
        cursor = connection.execute(scan_query_sql, params)
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as db_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def get_last_scan(database_path: Path) -> dict[str, Any] | None:
    """Return the most recent scan event, or None if no scans exist."""
    connection = _open_database(database_path)
    try:
        cursor = connection.execute(_SELECT_LAST_SCAN_SQL)
        row = cursor.fetchone()
        return dict(row) if row is not None else None
    except sqlite3.Error as db_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def get_schema_version(database_path: Path) -> int:
    """Return the schema version stored in the database."""
    connection = _open_database(database_path)
    try:
        cursor = connection.execute(_SELECT_SCHEMA_VERSION_SQL, (_SCHEMA_VERSION_KEY,))
        row = cursor.fetchone()
        if row is None:
            raise AuditLogError(_SCHEMA_VERSION_MISSING_ERROR)
        return int(row[0])
    except sqlite3.Error as db_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def migrate_schema(database_path: Path, from_version: int, to_version: int) -> None:
    """Advance the database schema from from_version to to_version."""
    if from_version == to_version:
        return
    if from_version > to_version:
        raise SchemaMigrationError(
            _SCHEMA_DOWNGRADE_ERROR.format(from_version=from_version, to_version=to_version)
        )
    connection = _open_database(database_path)
    try:
        _apply_migration_steps(connection, from_version, to_version)
        connection.commit()
    except sqlite3.Error as db_error:
        connection.rollback()
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def purge_expired_audit_rows(database_path: Path) -> int:
    """Delete audit rows older than AUDIT_RETENTION_DAYS (HIPAA 6-year window)."""
    cutoff = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=AUDIT_RETENTION_DAYS)
    ).isoformat()
    connection = _open_database(database_path)
    try:
        cursor = connection.execute(_DELETE_EXPIRED_ROWS_SQL, (cutoff,))
        deleted_count = cursor.rowcount
        connection.commit()
        return deleted_count
    except sqlite3.Error as db_error:
        connection.rollback()
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _apply_migration_steps(
    connection: sqlite3.Connection, from_version: int, to_version: int
) -> None:
    """Execute sequential migration SQL steps from from_version up to to_version."""
    current_version = from_version
    while current_version < to_version:
        if current_version not in _MIGRATIONS:
            raise SchemaMigrationError(
                _UNKNOWN_MIGRATION_ERROR.format(
                    from_version=current_version,
                    to_version=current_version + 1,
                )
            )
        migration_statements = _MIGRATIONS[current_version]
        for statement in migration_statements:
            connection.execute(statement)
        next_version = str(current_version + 1)
        connection.execute(_UPSERT_SCHEMA_VERSION_SQL, (_SCHEMA_VERSION_KEY, next_version))
        current_version += 1


def _serialize_findings(findings: tuple[ScanFinding, ...]) -> str:
    """Serialise findings to a JSON string for audit storage.

    Only non-PHI fields are included. code_context and remediation_hint are
    excluded; file_path is stored as a SHA-256 hash.
    """
    serialized_findings = [
        {
            "file_path_hash": hashlib.sha256(str(finding.file_path).encode()).hexdigest(),
            "line_number": finding.line_number,
            "entity_type": finding.entity_type,
            "hipaa_category": finding.hipaa_category.value,
            "confidence": finding.confidence,
            "detection_layer": finding.detection_layer,
            "value_hash": finding.value_hash,
            "severity": finding.severity.value,
        }
        for finding in findings
    ]
    return json.dumps(serialized_findings)


def _collect_repository_identity() -> tuple[str, str]:
    """Return (repository_hash, branch_hash) as SHA-256 hex digests."""
    repository_hash = hashlib.sha256(_get_current_repository_path().encode()).hexdigest()
    branch_hash = hashlib.sha256(_get_current_branch().encode()).hexdigest()
    return repository_hash, branch_hash


def _collect_committer_identity() -> tuple[str, str]:
    """Return (committer_name_hash, committer_email_hash) as SHA-256 hex digests."""
    return (
        _hash_git_committer_field(_GIT_COMMITTER_NAME_ARGS),
        _hash_git_committer_field(_GIT_COMMITTER_EMAIL_ARGS),
    )


def _build_scan_event_row(
    scan_result: ScanResult,
    notifications_sent: list[str],
    encrypted_findings_json: str,
) -> tuple[str | int | float, ...]:
    """Build the 20-tuple for INSERT into scan_events from already-encrypted findings."""
    repository_hash, branch_hash = _collect_repository_identity()
    committer_name_hash, committer_email_hash = _collect_committer_identity()
    action_taken = ACTION_TAKEN_PASS if scan_result.is_clean else ACTION_TAKEN_FAIL
    ai_usage = scan_result.ai_usage
    ai_input_tokens = ai_usage.input_tokens if ai_usage else _AI_USAGE_ZERO_TOKENS
    ai_output_tokens = ai_usage.output_tokens if ai_usage else _AI_USAGE_ZERO_TOKENS
    ai_cost_usd = ai_usage.estimated_cost_usd if ai_usage else _AI_USAGE_ZERO_COST_USD
    return (
        _get_current_timestamp(),
        __version__,
        repository_hash,
        branch_hash,
        scan_result.files_scanned,
        len(scan_result.findings),
        encrypted_findings_json,
        _BOOLEAN_TRUE if scan_result.is_clean else _BOOLEAN_FALSE,
        scan_result.scan_duration,
        _EVENT_TYPE_SCAN,
        committer_name_hash,
        committer_email_hash,
        _detect_pr_number(),
        _detect_pipeline(),
        action_taken,
        json.dumps(notifications_sent),
        _CHAIN_HASH_PLACEHOLDER,  # replaced by HMAC in subsequent UPDATE
        ai_input_tokens,
        ai_output_tokens,
        ai_cost_usd,
    )
