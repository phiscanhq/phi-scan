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
  Each row carries ``row_chain_hash = HMAC-SHA256(key=audit_secret,
  msg=prev_chain_hash || row_content)``. The first row uses
  AUDIT_GENESIS_CHAIN_HASH as the previous hash. ``verify_audit_chain``
  recomputes the chain in insertion order and raises AuditLogError if any
  row diverges. Satisfies NIST SP 800-53 AU-9 and AU-10.

Encryption (5C.9):
  ``findings_json`` is encrypted at rest with AES-256-GCM using a key stored
  at ``~/.phi-scanner/audit.key``. If the key file is absent,
  ``insert_scan_event`` raises ``AuditKeyMissingError`` — plaintext fallback
  is explicitly prohibited. The ``enc:`` prefix on stored values distinguishes
  ciphertext from any legacy plaintext rows that predate Phase 5. Requires the
  ``cryptography`` package (Phase 5 dependency).

Retention purge (5C.4):
  ``purge_expired_audit_rows`` deletes rows older than AUDIT_RETENTION_DAYS.
  Exported for scheduled or CLI-triggered invocation — not called automatically
  to avoid surprising callers.
"""

from __future__ import annotations

import datetime
import errno
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, NamedTuple

from phi_scan import __version__
from phi_scan.constants import (
    ACTION_TAKEN_FAIL,
    ACTION_TAKEN_PASS,
    AUDIT_ENCRYPTION_PREFIX,
    AUDIT_GENESIS_CHAIN_HASH,
    AUDIT_KEY_FILENAME,
    AUDIT_RETENTION_DAYS,
    AUDIT_SCHEMA_VERSION,
)
from phi_scan.exceptions import (
    AuditKeyMissingError,
    AuditLogError,
    PhiDetectionError,
    SchemaMigrationError,
)
from phi_scan.logging_config import get_logger
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


class ChainVerifyResult(NamedTuple):
    """Result of verify_audit_chain.

    Attributes:
        is_intact: True only when all rows were verified and every hash matched.
            False if: any row failed hash verification, any row had an empty
            row_chain_hash, OR the audit key was absent (no verification done).
            A False result always means the chain cannot be considered clean.
        key_present: True if the audit key was found and verification was attempted.
            False means the key was absent; is_intact will also be False.
        skipped_rows: Count of rows with empty row_chain_hash that could not be
            verified. When non-zero, is_intact is always False.
    """

    is_intact: bool
    key_present: bool
    skipped_rows: int = 0


_logger: logging.Logger = get_logger("audit")

# ---------------------------------------------------------------------------
# Log and error message templates
# ---------------------------------------------------------------------------

_SYMLINK_DATABASE_PATH_ERROR: str = (
    "Audit database path {path!r} is a symlink — symlinks are prohibited "
    "to prevent log-redirection attacks"
)
_SCHEMA_DOWNGRADE_ERROR: str = (
    "Cannot downgrade audit schema from version {from_version} to {to_version}"
)
_UNKNOWN_MIGRATION_ERROR: str = (
    "No migration path exists from schema version {from_version} "
    "to {to_version} — add the SQL to _MIGRATIONS"
)
_SCHEMA_VERSION_MISSING_ERROR: str = "schema_meta table exists but the schema_version key is absent"
_DATABASE_ERROR: str = "Audit database operation failed: {detail}"
_CHAIN_TAMPER_ERROR: str = (
    "Audit chain verification failed at row id={row_id}: "
    "stored hash does not match recomputed hash — the audit log may have been tampered with"
)
_CHAIN_KEY_MISSING_WARNING: str = (
    "Audit chain key not found at %s — hash chain verification skipped. "
    "Run 'phi-scan setup' to generate the audit key."
)
_ENCRYPTION_KEY_MISSING_ERROR: str = (
    "Audit encryption key not found at {redacted_key_path} — refusing to store findings_json "
    "as plaintext. Run 'phi-scan setup' to generate the audit key."
)
_CHAIN_ROW_SKIPPED_WARNING: str = (
    "Audit chain: row id={row_id} has an empty row_chain_hash and was skipped. "
    "This may indicate the row predates hash-chain support, or that the hash was "
    "cleared by an attacker. Treat skipped_rows > 0 as unverified."
)
_INSERT_WITHOUT_CHAIN_HASH_WARNING: str = (
    "Audit row id={row_id} committed without a chain hash — audit key is absent. "
    "Run 'phi-scan setup' to enable hash-chain integrity protection."
)
_KEY_FILE_EXISTS_ERROR: str = (
    "Audit key already exists at {redacted_key_path} — "
    "refusing to overwrite. Delete the file manually to regenerate."
)
_KEY_WRITE_ERROR: str = "Cannot write audit key to {redacted_key_path}: {io_strerror}"
_KEY_READ_ERROR: str = "Cannot read audit key from {redacted_key_path}: {io_strerror}"

# ---------------------------------------------------------------------------
# Implementation constants
# ---------------------------------------------------------------------------

_SCAN_EVENTS_TABLE: str = "scan_events"
_SCHEMA_META_TABLE: str = "schema_meta"
_SCHEMA_VERSION_KEY: str = "schema_version"
_CREATED_AT_KEY: str = "created_at"
_UNKNOWN_REPOSITORY: str = "unknown"
_UNKNOWN_BRANCH: str = "unknown"
_BOOLEAN_TRUE: int = 1
_BOOLEAN_FALSE: int = 0
_EVENT_TYPE_SCAN: str = "scan"
_CHAIN_HASH_PLACEHOLDER: str = ""
_NOTIFICATIONS_EMPTY_JSON: str = "[]"
# O_NOFOLLOW is POSIX-only (Linux/macOS). On Windows it does not exist;
# _reject_symlink_database_path falls back to Path.is_symlink() there.
_O_NOFOLLOW: int | None = getattr(os, "O_NOFOLLOW", None)
# O_BINARY is Windows-only. On POSIX it is 0 (no-op). Without it, os.open on
# Windows opens in text mode and translates \n → \r\n, corrupting binary key data.
_O_BINARY: int = getattr(os, "O_BINARY", 0)
_PRAGMA_WAL_MODE: str = "PRAGMA journal_mode=WAL"
_LAST_SCAN_LIMIT: int = 1
_GIT_SUBPROCESS_TIMEOUT_SECONDS: int = 5
_GIT_BRANCH_ARGS: tuple[str, ...] = ("git", "branch", "--show-current")
_GIT_TOPLEVEL_ARGS: tuple[str, ...] = ("git", "rev-parse", "--show-toplevel")
# git log pretty-format specifiers used for committer identity.
# %cn = committer name (the person who applied the commit, not the author)
# %ce = committer email
# These are hashed before storage — raw values are never persisted.
_GIT_FORMAT_COMMITTER_NAME: str = "--format=%cn"
_GIT_FORMAT_COMMITTER_EMAIL: str = "--format=%ce"
_GIT_COMMITTER_NAME_ARGS: tuple[str, ...] = ("git", "log", "-1", _GIT_FORMAT_COMMITTER_NAME)
_GIT_COMMITTER_EMAIL_ARGS: tuple[str, ...] = ("git", "log", "-1", _GIT_FORMAT_COMMITTER_EMAIL)

# CI/CD environment variable names for PR number and pipeline detection.
_ENV_PR_NUMBER_GITHUB: str = "GITHUB_PR_NUMBER"
_ENV_PR_NUMBER_GITLAB: str = "CI_MERGE_REQUEST_IID"
_ENV_PR_NUMBER_BITBUCKET: str = "BITBUCKET_PR_ID"
_ENV_PIPELINE_GITHUB: str = "GITHUB_ACTIONS"
_ENV_PIPELINE_GITLAB: str = "GITLAB_CI"
_ENV_PIPELINE_JENKINS: str = "JENKINS_URL"
_ENV_PIPELINE_CIRCLECI: str = "CIRCLECI"
_ENV_PIPELINE_BITBUCKET: str = "BITBUCKET_PIPELINE_UUID"
_PIPELINE_GITHUB_NAME: str = "github-actions"
_PIPELINE_GITLAB_NAME: str = "gitlab-ci"
_PIPELINE_JENKINS_NAME: str = "jenkins"
_PIPELINE_CIRCLECI_NAME: str = "circleci"
_PIPELINE_BITBUCKET_NAME: str = "bitbucket-pipelines"
_PIPELINE_LOCAL: str = "local"

# ScanFinding field names that carry raw or PHI-adjacent values and must NEVER
# appear as JSON keys in a serialised findings record stored to the audit DB.
# _assert_no_raw_phi_fields() checks the output of _serialize_findings() against
# this set before encryption as a defence-in-depth guard.
#   "file_path"        — raw path; must be stored only as file_path_hash
#   "code_context"     — source line (even though [REDACTED] replaces the match,
#                        the surrounding tokens may still be PHI-adjacent)
#   "remediation_hint" — free-text hint that may embed partial PHI
_FORBIDDEN_AUDIT_FIELD_NAMES: frozenset[str] = frozenset(
    {"file_path", "code_context", "remediation_hint"}
)

# AES-256-GCM constants.
_AES_GCM_KEY_BYTES: int = 32  # 256-bit key
_AES_GCM_NONCE_BYTES: int = 12  # 96-bit nonce (GCM standard)
_AES_GCM_TAG_BYTES: int = 16  # 128-bit authentication tag
# Ciphertext layout: nonce(12) || ciphertext || tag(16), base64-encoded,
# prefixed with AUDIT_ENCRYPTION_PREFIX.
_AES_GCM_NONCE_END: int = _AES_GCM_NONCE_BYTES
_AES_GCM_TAG_START: int = -_AES_GCM_TAG_BYTES  # slice from end

# SQL DDL — table names are module-level constants, not user input; f-strings are safe.
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
# Row tuple positional indices for the three AI usage columns added in schema v3.
# Index 16 (row_chain_hash) is intentionally excluded from the chain-hash content
# dict in _compute_row_chain_hash — the chain hash cannot include itself.
_ROW_TUPLE_AI_INPUT_TOKENS_INDEX: int = 17
_ROW_TUPLE_AI_OUTPUT_TOKENS_INDEX: int = 18
_ROW_TUPLE_AI_COST_USD_INDEX: int = 19

_SELECT_RECENT_SCANS_BASE_SQL: str = f"SELECT * FROM {_SCAN_EVENTS_TABLE} WHERE timestamp >= ?"
_FILTER_REPOSITORY_HASH_SQL: str = " AND repository_hash = ?"
_FILTER_VIOLATIONS_ONLY_SQL: str = " AND is_clean = ?"
_ORDER_BY_TIMESTAMP_DESC_SQL: str = " ORDER BY timestamp DESC"
_SELECT_LAST_SCAN_SQL: str = (
    f"SELECT * FROM {_SCAN_EVENTS_TABLE} ORDER BY id DESC LIMIT {_LAST_SCAN_LIMIT}"
)
_SELECT_SCHEMA_VERSION_SQL: str = f"SELECT value FROM {_SCHEMA_META_TABLE} WHERE key = ?"
_SELECT_ALL_ROWS_ORDERED_SQL: str = (
    f"SELECT id, timestamp, scanner_version, repository_hash, branch_hash, "
    f"files_scanned, findings_count, findings_json, is_clean, scan_duration, "
    f"event_type, committer_name_hash, committer_email_hash, pr_number, "
    f"pipeline, action_taken, notifications_sent, row_chain_hash "
    f"FROM {_SCAN_EVENTS_TABLE} ORDER BY id ASC"
)
_SELECT_LAST_ROW_CHAIN_HASH_SQL: str = (
    f"SELECT row_chain_hash FROM {_SCAN_EVENTS_TABLE} ORDER BY id DESC LIMIT 1"
)
_UPDATE_ROW_CHAIN_HASH_SQL: str = f"UPDATE {_SCAN_EVENTS_TABLE} SET row_chain_hash = ? WHERE id = ?"
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

    Idempotent — safe to call on every startup. Initialises both the
    ``scan_events`` table and the ``schema_meta`` table, then seeds
    ``schema_version`` and ``created_at`` metadata keys.

    Args:
        database_path: Path to the SQLite audit database file. The parent
            directory is created automatically if it does not exist.

    Raises:
        AuditLogError: If database_path is a symlink, or if the database
            cannot be opened or written to.
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
    """Create the audit schema and migrate it to the current version if needed.

    This is the preferred entry point for callers that need a ready-to-use
    database. It calls ``create_audit_schema`` to initialise the tables, then
    runs any pending migrations so an older on-disk database is brought up to
    ``AUDIT_SCHEMA_VERSION`` transparently.

    ``create_audit_schema`` has a single responsibility (create), so callers
    that need only creation (tests, tooling) can call it directly. This
    function handles the combined create-and-migrate use case.

    Args:
        database_path: Path to the SQLite audit database file.

    Raises:
        AuditLogError: If the database cannot be opened or written to.
        SchemaMigrationError: If a migration step is missing or cannot run.
    """
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
    repository_hash, branch_hash, and file_path_hash store SHA-256 digests
    — paths and branch names can be PHI-revealing (e.g. a branch named
    feature/patient-john-doe-ssn-fix or a repo at /home/patient_records).

    The row_chain_hash is computed as:
        HMAC-SHA256(key=audit_key, msg=prev_chain_hash || row_content)
    If the audit key file is absent, row_chain_hash is left as empty string
    and a one-time warning is emitted.

    Args:
        database_path: Path to the SQLite audit database file.
        scan_result: The completed scan result to record.
        notifications_sent: List of notification channel names delivered
            (e.g. ["email", "webhook-slack"]). None is treated as empty list.

    Raises:
        AuditLogError: If the database cannot be written to.
    """
    delivered_channels: list[str] = notifications_sent or []
    # PHI safety: _serialize_findings() strips raw values (code_context, file paths)
    # and returns a JSON string containing only hashes and metadata. That string —
    # never the ScanFinding objects themselves — is passed to _serialize_and_encrypt.
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
    """Return scan events recorded within the last ``lookback_days`` days.

    Args:
        database_path: Path to the SQLite audit database file.
        lookback_days: Number of days back to include in the results.
        repository_hash: Optional SHA-256 hex digest to filter by repository.
            When provided, only rows whose ``repository_hash`` column matches
            exactly are returned. Callers must hash the raw path before passing.
        should_show_violations_only: When True, only rows where ``is_clean = 0``
            are returned.

    Returns:
        List of scan event rows as dicts, ordered by timestamp descending.

    Raises:
        AuditLogError: If the database cannot be read.
    """
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
    """Return the most recent scan event, or None if no scans exist.

    Args:
        database_path: Path to the SQLite audit database file.

    Returns:
        The most recent scan event row as a dict, or None.

    Raises:
        AuditLogError: If the database cannot be read.
    """
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
    """Return the schema version stored in the database.

    Args:
        database_path: Path to the SQLite audit database file.

    Returns:
        The integer schema version read from schema_meta.

    Raises:
        AuditLogError: If the database cannot be read or the key is absent.
    """
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
    """Advance the database schema from from_version to to_version.

    Applies sequential migrations from _MIGRATIONS. Each migration step
    advances the version by one. Downgrading is not supported.

    Args:
        database_path: Path to the SQLite audit database file.
        from_version: The current schema version in the database.
        to_version: The target schema version to migrate to.

    Raises:
        SchemaMigrationError: If from_version > to_version, or if no
            migration SQL exists for a required step.
        AuditLogError: If the database cannot be written to.
    """
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


def _verify_chain_rows(audit_rows: list[Any], audit_key: bytearray) -> ChainVerifyResult:
    """Walk audit_rows in insertion order and verify each HMAC chain hash.

    Called by verify_audit_chain after the key and rows have been loaded.
    Extracted to keep verify_audit_chain under the 30-line function limit.

    Args:
        audit_rows: Rows from _SELECT_ALL_ROWS_ORDERED_SQL, ordered by id ASC.
        audit_key: The 32-byte AES-256 audit key used as the HMAC key.

    Returns:
        ChainVerifyResult with key_present=True (the caller already confirmed
        the key is present). is_intact is False if any hash mismatches or any
        row was skipped.
    """
    prev_hash = AUDIT_GENESIS_CHAIN_HASH
    skipped_rows = 0
    is_chain_intact = True
    for audit_row in audit_rows:
        row_fields = dict(audit_row)
        row_id = row_fields["id"]
        stored_hash: str = row_fields.get("row_chain_hash", "")
        if not stored_hash:
            # Row has no chain hash — either pre-dates hash-chain support or was
            # cleared by an attacker. Log at WARNING and mark chain as not fully intact.
            _logger.warning(_CHAIN_ROW_SKIPPED_WARNING.format(row_id=row_id))
            skipped_rows += 1
            is_chain_intact = False
            continue
        row_content_string = _row_content_for_hashing(row_fields)
        recomputed_chain_hash = _hmac_sha256(audit_key, prev_hash + row_content_string)
        if not hmac.compare_digest(stored_hash, recomputed_chain_hash):
            _logger.error(_CHAIN_TAMPER_ERROR.format(row_id=row_id))
            return ChainVerifyResult(is_intact=False, key_present=True, skipped_rows=skipped_rows)
        prev_hash = recomputed_chain_hash
    return ChainVerifyResult(is_intact=is_chain_intact, key_present=True, skipped_rows=skipped_rows)


def verify_audit_chain(database_path: Path) -> ChainVerifyResult:
    """Recompute the HMAC-SHA256 hash chain and return a ChainVerifyResult.

    Reads all rows in insertion order and recomputes each row's chain hash
    from the previous hash and the row's content fields.

    When the audit key is absent the chain cannot be verified — the result
    has ``key_present=False`` so callers can distinguish this from a verified-
    clean result. Callers should treat ``key_present=False`` as unverified, not
    as a passing audit.

    Args:
        database_path: Path to the SQLite audit database file.

    Returns:
        ChainVerifyResult with is_intact and key_present fields.
        key_present=False means the audit key was absent and no verification
        was performed; is_intact is False in that case so callers checking
        only is_intact cannot conclude the chain is clean.

    Raises:
        AuditLogError: If the database cannot be read or the key exists but
            cannot be loaded.
    """
    audit_key = _load_audit_key(database_path.parent)
    if audit_key is None:
        # Key absent means zero verification was performed — is_intact must be
        # False so callers checking only that field cannot conclude the chain is
        # clean when it was never checked.
        return ChainVerifyResult(is_intact=False, key_present=False)
    try:
        connection = _open_database(database_path)
        try:
            cursor = connection.execute(_SELECT_ALL_ROWS_ORDERED_SQL)
            audit_rows = cursor.fetchall()
        except sqlite3.Error as db_error:
            raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
        finally:
            connection.close()
        return _verify_chain_rows(audit_rows, audit_key)
    finally:
        audit_key[:] = bytes(len(audit_key))


def purge_expired_audit_rows(database_path: Path) -> int:
    """Delete audit rows older than AUDIT_RETENTION_DAYS (HIPAA 6-year window).

    HIPAA §164.530(j) requires retention for 6 years minimum; rows beyond
    that window may be purged. This function deletes rows whose timestamp
    predates the retention cutoff and returns the number of rows deleted.

    Args:
        database_path: Path to the SQLite audit database file.

    Returns:
        Number of rows deleted.

    Raises:
        AuditLogError: If the database cannot be written to.
    """
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


def generate_audit_key(database_path: Path) -> Path:
    """Generate a new AES-256-GCM audit key and write it to the key file.

    The key file is created in the same directory as database_path with mode
    0o600 (owner read/write only). Raises AuditLogError if the file already
    exists — never silently overwrites an existing key.

    Args:
        database_path: Path to the SQLite audit database — the key is stored
            in the same directory.

    Returns:
        Path to the generated key file.

    Raises:
        AuditLogError: If the key file already exists or cannot be written.
    """
    key_path = _audit_key_path(database_path.parent)
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_bytes = os.urandom(_AES_GCM_KEY_BYTES)
        # O_CREAT | O_EXCL atomically creates key_path only if it does not already
        # exist — raises EEXIST if present, eliminating the TOCTOU window that
        # key_path.exists() + open() would create. Mode 0o600 sets owner-only
        # permissions at file creation, not in a separate chmod call.
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        try:
            os.write(fd, key_bytes)
        finally:
            os.close(fd)
    except OSError as io_error:
        if io_error.errno == errno.EEXIST:
            raise AuditLogError(
                _KEY_FILE_EXISTS_ERROR.format(redacted_key_path=_redact_key_path(key_path))
            ) from io_error
        raise AuditLogError(
            _KEY_WRITE_ERROR.format(
                redacted_key_path=_redact_key_path(key_path),
                io_strerror=io_error.strerror or f"errno {io_error.errno}",
            )
        ) from io_error
    return key_path


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _apply_migration_steps(
    connection: sqlite3.Connection, from_version: int, to_version: int
) -> None:
    """Execute sequential migration SQL steps from from_version up to to_version.

    SQLite does not support executing multiple semicolon-separated statements
    in a single execute() call — each ALTER TABLE statement must be issued
    separately.

    Args:
        connection: Open database connection to execute migrations on.
        from_version: The starting schema version.
        to_version: The target schema version.

    Raises:
        SchemaMigrationError: If no migration SQL exists for a required step.
    """
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


def _reject_symlink_database_path(database_path: Path) -> None:
    """Raise AuditLogError if database_path is a symbolic link.

    Symlinks are rejected to prevent log-redirection attacks: an attacker
    who can create a symlink at the expected database path could redirect
    all audit writes to an arbitrary file (e.g. /dev/null or a file they
    control), silently discarding the audit trail or poisoning a different
    file. Rejecting symlinks forces the path to resolve to a real file.

    On POSIX (Linux/macOS), uses ``os.open`` with ``O_NOFOLLOW`` to detect
    symlinks atomically. ``Path.is_symlink()`` + ``sqlite3.connect()`` has a
    TOCTOU race window; ``O_NOFOLLOW`` closes it because the kernel rejects
    the symlink in a single syscall (``errno.ELOOP``). ``ENOENT`` is not an
    error — new databases are created by ``sqlite3.connect``.

    On Windows, ``O_NOFOLLOW`` is not available; the function falls back to
    ``Path.is_symlink()``. The TOCTOU window remains on Windows but symlink
    attacks are mitigated by the OS security model.

    Args:
        database_path: Resolved path to validate.

    Raises:
        AuditLogError: If database_path is a symbolic link.
    """
    if _O_NOFOLLOW is not None:
        # POSIX: O_NOFOLLOW atomically rejects symlinks in a single syscall.
        try:
            fd = os.open(str(database_path), os.O_RDONLY | _O_NOFOLLOW)
            os.close(fd)
        except OSError as os_error:
            if os_error.errno == errno.ELOOP:
                raise AuditLogError(
                    _SYMLINK_DATABASE_PATH_ERROR.format(path=database_path)
                ) from os_error
            if os_error.errno != errno.ENOENT:
                # Unexpected OS error (e.g. EACCES, EPERM) — surface as AuditLogError.
                raise AuditLogError(_DATABASE_ERROR.format(detail=os_error)) from os_error
            # ENOENT is intentionally ignored — new databases created by sqlite3.connect.
    else:
        # Windows fallback: O_NOFOLLOW unavailable; is_symlink() has a small TOCTOU
        # window but is the best available check on this platform.
        if database_path.is_symlink():
            raise AuditLogError(_SYMLINK_DATABASE_PATH_ERROR.format(path=database_path))


def _ensure_database_parent_exists(database_path: Path) -> None:
    """Create the parent directory of database_path if it does not exist.

    Args:
        database_path: Path to the SQLite file whose parent must exist.

    Raises:
        AuditLogError: If the directory cannot be created (e.g. permission
            denied or a file already occupies the expected directory path).
    """
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as io_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=io_error)) from io_error


def _open_database(database_path: Path) -> sqlite3.Connection:
    """Open and configure a SQLite connection to the audit database.

    Symlink detection uses O_NOFOLLOW (see _reject_symlink_database_path),
    which closes the TOCTOU race that existed between is_symlink() and
    sqlite3.connect() in earlier versions.

    Args:
        database_path: Path to the SQLite file to open or create.

    Returns:
        An open sqlite3.Connection with row_factory and WAL mode configured.

    Raises:
        AuditLogError: If the path is a symlink, the parent directory cannot
            be created, or the database cannot be opened or configured.
    """
    _reject_symlink_database_path(database_path)
    _ensure_database_parent_exists(database_path)
    try:
        connection = sqlite3.connect(str(database_path))
    except sqlite3.Error as db_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    try:
        connection.row_factory = sqlite3.Row
        connection.execute(_PRAGMA_WAL_MODE)
    except sqlite3.Error as config_error:
        connection.close()
        raise AuditLogError(_DATABASE_ERROR.format(detail=config_error)) from config_error
    return connection


def _get_current_timestamp() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.datetime.now(datetime.UTC).isoformat()


def _serialize_findings(findings: tuple[ScanFinding, ...]) -> str:
    """Serialise findings to a JSON string for audit storage.

    Only non-PHI fields are included. code_context and remediation_hint are
    excluded; file_path is stored as a SHA-256 hash.

    Args:
        findings: The findings tuple from a completed ScanResult.

    Returns:
        A JSON array string safe for storage in the audit database.
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


def _get_current_branch() -> str:
    """Return the current git branch name, or 'unknown' if unavailable.

    Security note: the raw branch name is never stored or logged. Callers
    hash it with SHA-256 before persisting to the audit database because
    branch names can be PHI-revealing (e.g. feature/patient-john-doe-ssn-fix).
    Only the type of the subprocess exception is logged on failure — not any
    path or argument value — to avoid leaking filesystem layout.

    Returns:
        The branch name string for hashing, or 'unknown' when git is
        unavailable, returns a non-zero exit code, or times out.
    """
    try:
        completed_process = subprocess.run(
            _GIT_BRANCH_ARGS,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            branch = completed_process.stdout.strip()
            return branch if branch else _UNKNOWN_BRANCH
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not determine git branch: %s", type(git_error).__name__)
    return _UNKNOWN_BRANCH


def _get_current_repository_path() -> str:
    """Return the git repository root path, or the current directory if unavailable.

    Security note: the raw path is never stored or logged. Callers hash it
    with SHA-256 before persisting because repository paths can be PHI-
    revealing (e.g. /home/nurse_jones/patient_records). The exception type
    only is logged on failure — not the path — to avoid leaking filesystem
    layout in log files.

    Returns:
        The absolute repository root path string for hashing, or the
        current working directory when git is unavailable or times out.
    """
    try:
        completed_process = subprocess.run(
            _GIT_TOPLEVEL_ARGS,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            return completed_process.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not determine git repository path: %s", type(git_error).__name__)
    return str(Path.cwd())


def _fetch_git_command_stdout(args: tuple[str, ...]) -> str:
    """Run a git log format command and return its stdout, or empty string on failure."""
    try:
        completed_process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_GIT_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if completed_process.returncode == 0:
            return completed_process.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as git_error:
        _logger.warning("Could not run git format command: %s", type(git_error).__name__)
    return ""


def _hash_git_committer_field(args: tuple[str, ...]) -> str:
    """Return SHA-256 hash of a git log committer field, or empty string if unavailable.

    Args:
        args: Full argument tuple for the git log command (e.g. _GIT_COMMITTER_NAME_ARGS).

    Returns:
        64-char hex digest, or empty string when git is unavailable or returns no output.
    """
    field_value = _fetch_git_command_stdout(args)
    return hashlib.sha256(field_value.encode()).hexdigest() if field_value else ""


def _detect_pr_number() -> str:
    """Return the PR/MR number from CI environment variables, or empty string."""
    for env_var in (
        _ENV_PR_NUMBER_GITHUB,
        _ENV_PR_NUMBER_GITLAB,
        _ENV_PR_NUMBER_BITBUCKET,
    ):
        pr_number_string = os.environ.get(env_var, "")
        if pr_number_string:
            return pr_number_string
    return ""


def _detect_pipeline() -> str:
    """Return the CI/CD pipeline name from environment variables, or 'local'."""
    if os.environ.get(_ENV_PIPELINE_GITHUB):
        return _PIPELINE_GITHUB_NAME
    if os.environ.get(_ENV_PIPELINE_GITLAB):
        return _PIPELINE_GITLAB_NAME
    if os.environ.get(_ENV_PIPELINE_JENKINS):
        return _PIPELINE_JENKINS_NAME
    if os.environ.get(_ENV_PIPELINE_CIRCLECI):
        return _PIPELINE_CIRCLECI_NAME
    if os.environ.get(_ENV_PIPELINE_BITBUCKET):
        return _PIPELINE_BITBUCKET_NAME
    return _PIPELINE_LOCAL


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
    """Build the 20-tuple for INSERT into scan_events from already-encrypted findings.

    Delegates identity collection to focused helpers. Encryption is the
    caller's responsibility so this function has a single concern: assembling
    scan metadata into the INSERT tuple. The row_chain_hash column is seeded
    with _CHAIN_HASH_PLACEHOLDER and replaced by the actual HMAC in a
    subsequent UPDATE.

    Args:
        scan_result: Completed scan result.
        notifications_sent: Notification channels that were delivered.
        encrypted_findings_json: AES-256-GCM encrypted findings JSON string,
            already produced by _serialize_and_encrypt.

    Returns:
        20-tuple matching the INSERT column order (id is auto-assigned;
        row_chain_hash is updated after INSERT).
    """
    repository_hash, branch_hash = _collect_repository_identity()
    committer_name_hash, committer_email_hash = _collect_committer_identity()
    action_taken = ACTION_TAKEN_PASS if scan_result.is_clean else ACTION_TAKEN_FAIL
    ai_input_tokens = scan_result.ai_usage.input_tokens if scan_result.ai_usage else 0
    ai_output_tokens = scan_result.ai_usage.output_tokens if scan_result.ai_usage else 0
    ai_cost_usd = scan_result.ai_usage.estimated_cost_usd if scan_result.ai_usage else 0.0
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


# ---------------------------------------------------------------------------
# Audit key + encryption helpers
# ---------------------------------------------------------------------------


def _audit_key_path(key_dir: Path) -> Path:
    """Return the Path to the audit key file within key_dir.

    key_dir is always database_path.parent — the key lives beside the database,
    not at a hardcoded global path. For the default database (~/.phi-scanner/audit.db)
    this resolves to ~/.phi-scanner/audit.key.
    """
    return key_dir / AUDIT_KEY_FILENAME


def _redact_key_path(key_path: Path) -> str:
    """Return a safe representation of key_path that omits the directory.

    The directory component is PHI-revealing when the database is placed in a
    patient-data path (e.g. /home/patient_records/). Only the filename is
    included — it is the constant AUDIT_KEY_FILENAME and carries no PHI.
    Callers use this in exception messages and log strings to stay consistent
    with the path-hashing policy applied to repository_hash and branch_hash.

    Returns:
        String of the form ``<redacted>/audit.key`` (filename only).
    """
    return f"<redacted>/{key_path.name}"


def _assert_no_raw_phi_fields(findings_json: str) -> None:
    """Raise PhiDetectionError if findings_json contains a known PHI field name.

    Defence-in-depth guard applied in _serialize_and_encrypt before encryption.
    If _serialize_findings ever develops a regression that includes a raw-value
    field (e.g. ``file_path``, ``code_context``, ``remediation_hint``), this
    guard catches the violation at the encryption boundary rather than silently
    persisting a PHI-adjacent field name in the audit database.

    Args:
        findings_json: The JSON string produced by _serialize_findings().

    Raises:
        PhiDetectionError: If any key in _FORBIDDEN_AUDIT_FIELD_NAMES appears
            as a JSON key (``"field_name"``) in findings_json. This is a
            serialisation bug, not a user error — callers should re-raise.
    """
    for field_name in _FORBIDDEN_AUDIT_FIELD_NAMES:
        if f'"{field_name}"' in findings_json:
            raise PhiDetectionError(
                f"_serialize_findings produced findings_json containing the raw PHI "
                f"field '{field_name}' — refusing to encrypt. This is a serialisation "
                f"bug; file a security issue."
            )


def _load_audit_key(key_dir: Path) -> bytearray | None:
    """Load the AES-256-GCM audit key from the key file.

    Returns None if the key file does not exist (encryption not configured).
    Raises AuditLogError if the file exists but cannot be read — silent
    degradation to plaintext after key setup would be a security failure.

    Security note: TOCTOU race between exists() and read_bytes() mirrors the
    symlink race in _open_database. A future fix would use O_NOFOLLOW.

    Args:
        key_dir: Directory that contains the audit.key file.

    Returns:
        32-byte key as a ``bytearray`` (mutable so callers can zero it after
        use), or None if the key file is absent.

        Known limitation: Python's garbage collector may retain copies of the
        bytearray's backing memory even after ``key[:] = bytes(len(key))``
        zeroes the live object. This is a language-level constraint shared by
        all Python cryptographic code. Callers must still zero promptly to
        minimise the window during which the key is accessible.

    Raises:
        AuditLogError: If the key file exists but cannot be read.
    """
    key_path = _audit_key_path(key_dir)
    if not key_path.exists():
        return None
    try:
        return bytearray(key_path.read_bytes())
    except OSError as io_error:
        raise AuditLogError(
            _KEY_READ_ERROR.format(
                redacted_key_path=_redact_key_path(key_path),
                io_strerror=io_error.strerror or f"errno {io_error.errno}",
            )
        ) from io_error


def _encrypt_findings_json(plaintext: str, key: bytearray) -> str:
    """Encrypt a findings JSON string with AES-256-GCM.

    The output is: AUDIT_ENCRYPTION_PREFIX + base64(nonce + ciphertext + tag).

    Requires the ``cryptography`` package. Raises ImportError if absent —
    callers should gate on the package being installed.

    Args:
        plaintext: JSON string to encrypt.
        key: 32-byte AES-256 key.

    Returns:
        Encrypted string with AUDIT_ENCRYPTION_PREFIX.
    """
    import base64

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_AES_GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return AUDIT_ENCRYPTION_PREFIX + base64.b64encode(nonce + ciphertext_with_tag).decode()


def _decrypt_findings_json(encrypted: str, key: bytes) -> str:
    """Decrypt an encrypted findings JSON string produced by _encrypt_findings_json.

    Args:
        encrypted: String beginning with AUDIT_ENCRYPTION_PREFIX.
        key: 32-byte AES-256 key.

    Returns:
        Decrypted plaintext JSON string.

    Raises:
        AuditLogError: If decryption fails (wrong key or tampered ciphertext).
    """
    import base64

    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(encrypted[len(AUDIT_ENCRYPTION_PREFIX) :])
    nonce = raw[:_AES_GCM_NONCE_END]
    ciphertext_with_tag = raw[_AES_GCM_NONCE_END:]
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None).decode()
    except (InvalidTag, ValueError) as crypto_error:
        raise AuditLogError(
            f"Audit findings_json decryption failed — the key may be wrong "
            f"or the ciphertext has been tampered with: {crypto_error}"
        ) from crypto_error


def _serialize_and_encrypt(findings_json: str, key_dir: Path) -> str:
    """Encrypt findings_json with AES-256-GCM using the audit key in key_dir.

    PHI safety: the ``findings_json`` parameter must be the output of
    ``_serialize_findings()`` — a JSON string containing only hashes and
    metadata (file_path_hash, value_hash, hipaa_category, etc.). Raw
    ``ScanFinding`` objects, ``code_context``, or plaintext file paths must
    never be passed here. The type annotation ``str`` enforces this at the
    API boundary; callers must not bypass ``_serialize_findings``.

    Hard-fails if the key is absent — plaintext fallback is not permitted because
    findings_json contains structured audit data (hipaa_category, file_path_hash,
    rule_id, value_hash) that must be protected at rest.

    Args:
        findings_json: Plaintext JSON string of serialised findings produced
            by _serialize_findings() — not raw ScanFinding objects.
        key_dir: Directory where the audit key file is stored.

    Returns:
        Encrypted string with AUDIT_ENCRYPTION_PREFIX.

    Raises:
        AuditKeyMissingError: If the audit key file does not exist.
        AuditLogError: If the key exists but cannot be read.
        PhiDetectionError: If findings_json contains a forbidden raw PHI field
            name — indicates a serialisation bug in _serialize_findings.
    """
    _assert_no_raw_phi_fields(findings_json)
    key = _load_audit_key(key_dir)
    if key is None:
        raise AuditKeyMissingError(
            _ENCRYPTION_KEY_MISSING_ERROR.format(
                redacted_key_path=_redact_key_path(_audit_key_path(key_dir))
            )
        )
    try:
        return _encrypt_findings_json(findings_json, key)
    finally:
        key[:] = bytes(len(key))


# ---------------------------------------------------------------------------
# Hash chain helpers
# ---------------------------------------------------------------------------


def _hmac_sha256(key: bytearray, message: str) -> str:
    """Return HMAC-SHA256(key, message) as a lowercase hex string.

    Args:
        key: The HMAC key bytes.
        message: The message string (encoded as UTF-8 before hashing).

    Returns:
        64-character lowercase hex digest.
    """
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def _row_content_for_hashing(row_fields: dict[str, Any]) -> str:
    """Produce a canonical string representation of a row for hash chain computation.

    All fields except row_chain_hash itself are included, in a stable order,
    to detect any modification to any column value.

    PHI safety: the ``findings_json`` field included here is always the
    AES-256-GCM ciphertext string written by ``_serialize_and_encrypt`` —
    never plaintext findings or raw ScanFinding content. The ``enc:`` prefix
    on all stored findings_json values confirms this at a glance.

    Args:
        row_fields: Row dict from the database (all columns except row_chain_hash).

    Returns:
        Canonical pipe-delimited string for HMAC input.
    """
    return (
        f"{row_fields.get('id', '')}"
        f"|{row_fields.get('timestamp', '')}"
        f"|{row_fields.get('scanner_version', '')}"
        f"|{row_fields.get('repository_hash', '')}"
        f"|{row_fields.get('branch_hash', '')}"
        f"|{row_fields.get('files_scanned', '')}"
        f"|{row_fields.get('findings_count', '')}"
        f"|{row_fields.get('findings_json', '')}"
        f"|{row_fields.get('is_clean', '')}"
        f"|{row_fields.get('scan_duration', '')}"
        f"|{row_fields.get('event_type', '')}"
        f"|{row_fields.get('committer_name_hash', '')}"
        f"|{row_fields.get('committer_email_hash', '')}"
        f"|{row_fields.get('pr_number', '')}"
        f"|{row_fields.get('pipeline', '')}"
        f"|{row_fields.get('action_taken', '')}"
        f"|{row_fields.get('notifications_sent', '')}"
    )


def _get_previous_chain_hash(connection: sqlite3.Connection, new_row_id: int | None) -> str:
    """Return the chain hash of the row preceding new_row_id.

    Uses the genesis hash for the first row.

    Args:
        connection: Open database connection.
        new_row_id: The id of the row just inserted.

    Returns:
        The prev_chain_hash to use when computing the new row's hash.
    """
    try:
        cursor = connection.execute(
            f"SELECT row_chain_hash FROM {_SCAN_EVENTS_TABLE} "
            f"WHERE id < ? ORDER BY id DESC LIMIT 1",
            (new_row_id,),
        )
        row = cursor.fetchone()
        if row is not None and row[0]:
            return str(row[0])
    except sqlite3.Error:
        pass
    return AUDIT_GENESIS_CHAIN_HASH


def _attach_chain_hash(connection: sqlite3.Connection, row_id: int | None, chain_hash: str) -> None:
    """Write chain_hash into the row_chain_hash column for row_id, or log if absent.

    If chain_hash is empty (audit key absent), logs at DEBUG level. The key-absent
    state is already warned about inside _compute_row_chain_hash; this function
    avoids emitting an additional WARNING that would appear in every scan output
    when the key is not configured.

    Args:
        connection: Open database connection.
        row_id: The autoincrement id of the just-inserted row.
        chain_hash: The computed chain hash, or empty string if key was absent.
    """
    if chain_hash:
        connection.execute(_UPDATE_ROW_CHAIN_HASH_SQL, (chain_hash, row_id))
    else:
        _logger.debug(_INSERT_WITHOUT_CHAIN_HASH_WARNING.format(row_id=row_id))


def _compute_row_chain_hash(
    database_path: Path,
    connection: sqlite3.Connection,
    new_row_id: int | None,
    row_tuple: tuple[str | int | float, ...],
) -> str:
    """Compute the HMAC-SHA256 chain hash for a newly inserted row.

    Returns empty string if the audit key is absent (chain disabled).

    Args:
        database_path: Used to locate the audit key directory.
        connection: Open database connection for prev-hash lookup.
        new_row_id: The autoincrement id of the just-inserted row.
        row_tuple: The 20-tuple passed to INSERT (same column order).

    Returns:
        64-hex-char chain hash, or empty string if key is absent.
    """
    key = _load_audit_key(database_path.parent)
    if key is None:
        _logger.debug(
            _CHAIN_KEY_MISSING_WARNING, _redact_key_path(_audit_key_path(database_path.parent))
        )
        return ""
    try:
        prev_hash = _get_previous_chain_hash(connection, new_row_id)
        # Reconstruct a row dict from the tuple for _row_content_for_hashing.
        # Column order must match _INSERT_SCAN_EVENT_SQL (excluding id which is auto).
        row_fields: dict[str, Any] = {
            "id": new_row_id,
            "timestamp": row_tuple[0],
            "scanner_version": row_tuple[1],
            "repository_hash": row_tuple[2],
            "branch_hash": row_tuple[3],
            "files_scanned": row_tuple[4],
            "findings_count": row_tuple[5],
            "findings_json": row_tuple[6],
            "is_clean": row_tuple[7],
            "scan_duration": row_tuple[8],
            "event_type": row_tuple[9],
            "committer_name_hash": row_tuple[10],
            "committer_email_hash": row_tuple[11],
            "pr_number": row_tuple[12],
            "pipeline": row_tuple[13],
            "action_taken": row_tuple[14],
            "notifications_sent": row_tuple[15],
            "ai_input_tokens": row_tuple[_ROW_TUPLE_AI_INPUT_TOKENS_INDEX],
            "ai_output_tokens": row_tuple[_ROW_TUPLE_AI_OUTPUT_TOKENS_INDEX],
            "ai_cost_usd": row_tuple[_ROW_TUPLE_AI_COST_USD_INDEX],
        }
        row_content_string = _row_content_for_hashing(row_fields)
        return _hmac_sha256(key, prev_hash + row_content_string)
    finally:
        key[:] = bytes(len(key))
