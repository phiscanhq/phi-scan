"""SQLite audit logging — HIPAA-compliant immutable scan event storage.

Audit records are INSERT-only. No UPDATE or DELETE operations are ever issued.
HIPAA (45 CFR §164.530(j)) requires audit logs to be retained for a minimum of
six years. Corrections are new INSERT rows referencing the original entry —
never modifications to existing rows.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from phi_scan import __version__
from phi_scan.constants import AUDIT_SCHEMA_VERSION
from phi_scan.exceptions import AuditLogError, SchemaMigrationError
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanFinding, ScanResult

__all__ = [
    "create_audit_schema",
    "get_last_scan",
    "get_schema_version",
    "insert_scan_event",
    "migrate_schema",
    "query_recent_scans",
]

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
_PRAGMA_WAL_MODE: str = "PRAGMA journal_mode=WAL"
_LAST_SCAN_LIMIT: int = 1
_GIT_SUBPROCESS_TIMEOUT_SECONDS: int = 5
# Git args are fully hardcoded tuples — shell=False is implicit (list form),
# no user input is interpolated, so subprocess injection is not possible.
_GIT_BRANCH_ARGS: tuple[str, ...] = ("git", "branch", "--show-current")
_GIT_TOPLEVEL_ARGS: tuple[str, ...] = ("git", "rev-parse", "--show-toplevel")

# SQL DDL — table names are module-level constants, not user input; f-strings are safe.
_CREATE_SCAN_EVENTS_SQL: str = f"""
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
         files_scanned, findings_count, findings_json, is_clean, scan_duration)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_SELECT_RECENT_SCANS_SQL: str = (
    f"SELECT * FROM {_SCAN_EVENTS_TABLE} WHERE timestamp >= ? ORDER BY timestamp DESC"
)
_SELECT_LAST_SCAN_SQL: str = (
    f"SELECT * FROM {_SCAN_EVENTS_TABLE} ORDER BY id DESC LIMIT {_LAST_SCAN_LIMIT}"
)
_SELECT_SCHEMA_VERSION_SQL: str = f"SELECT value FROM {_SCHEMA_META_TABLE} WHERE key = ?"
_CREATE_SCAN_EVENTS_TIMESTAMP_INDEX_SQL: str = (
    f"CREATE INDEX IF NOT EXISTS idx_scan_events_timestamp ON {_SCAN_EVENTS_TABLE} (timestamp DESC)"
)

# Migration map: from_version → SQL to advance the schema by one version.
# Add entries here when AUDIT_SCHEMA_VERSION is incremented. Never remove entries
# — they must remain to support upgrading older databases.
_MIGRATIONS: dict[int, str] = {}


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


def _assemble_scan_event_row(scan_result: ScanResult) -> tuple[str | int | float, ...]:
    repository_hash = hashlib.sha256(_get_current_repository_path().encode()).hexdigest()
    branch_hash = hashlib.sha256(_get_current_branch().encode()).hexdigest()
    return (
        _get_current_timestamp(),
        __version__,
        repository_hash,
        branch_hash,
        scan_result.files_scanned,
        len(scan_result.findings),
        _serialize_findings(scan_result.findings),
        _BOOLEAN_TRUE if scan_result.is_clean else _BOOLEAN_FALSE,
        scan_result.scan_duration,
    )


def insert_scan_event(database_path: Path, scan_result: ScanResult) -> None:
    """Record a completed scan as an immutable audit entry.

    findings_json stores only value_hash and metadata fields — raw detected
    values and code_context (which may contain raw PHI) are never persisted.
    repository_hash, branch_hash, and file_path_hash store SHA-256 digests
    — paths and branch names can be PHI-revealing (e.g. a branch named
    feature/patient-john-doe-ssn-fix or a repo at /home/patient_records).

    Args:
        database_path: Path to the SQLite audit database file.
        scan_result: The completed scan result to record.

    Raises:
        AuditLogError: If the database cannot be written to.
    """
    scan_event_row = _assemble_scan_event_row(scan_result)
    connection = _open_database(database_path)
    try:
        connection.execute(_INSERT_SCAN_EVENT_SQL, scan_event_row)
        connection.commit()
    except sqlite3.Error as db_error:
        connection.rollback()
        raise AuditLogError(_DATABASE_ERROR.format(detail=db_error)) from db_error
    finally:
        connection.close()


def query_recent_scans(database_path: Path, lookback_days: int) -> list[dict[str, Any]]:
    """Return scan events recorded within the last ``lookback_days`` days.

    Args:
        database_path: Path to the SQLite audit database file.
        lookback_days: Number of days back to include in the results.

    Returns:
        List of scan event rows as dicts, ordered by timestamp descending.

    Raises:
        AuditLogError: If the database cannot be read.
    """
    cutoff = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=lookback_days)
    ).isoformat()
    connection = _open_database(database_path)
    try:
        cursor = connection.execute(_SELECT_RECENT_SCANS_SQL, (cutoff,))
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


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _apply_migration_steps(
    connection: sqlite3.Connection, from_version: int, to_version: int
) -> None:
    """Execute sequential migration SQL steps from from_version up to to_version.

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
        connection.execute(_MIGRATIONS[current_version])
        next_version = str(current_version + 1)
        connection.execute(_UPSERT_SCHEMA_VERSION_SQL, (_SCHEMA_VERSION_KEY, next_version))
        current_version += 1


def _reject_symlink_database_path(database_path: Path) -> None:
    """Raise AuditLogError if database_path is a symlink.

    A symlinked database path could allow an attacker to redirect audit log
    writes to an arbitrary location, destroying HIPAA immutability guarantees.

    Args:
        database_path: The path to validate.

    Raises:
        AuditLogError: If database_path is a symlink.
    """
    if database_path.is_symlink():
        raise AuditLogError(_SYMLINK_DATABASE_PATH_ERROR.format(path=database_path))


def _ensure_database_parent_exists(database_path: Path) -> None:
    """Create the parent directory of database_path if it does not exist.

    Args:
        database_path: Path to the SQLite file whose parent must exist.

    Raises:
        AuditLogError: If the parent directory cannot be created.
    """
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as io_error:
        raise AuditLogError(_DATABASE_ERROR.format(detail=io_error)) from io_error


def _open_database(database_path: Path) -> sqlite3.Connection:
    """Open and configure a SQLite connection to the audit database.

    Args:
        database_path: Path to the SQLite file to open or create.

    Returns:
        An open sqlite3.Connection with row_factory and WAL mode configured.

    Raises:
        AuditLogError: If the path is a symlink, the parent directory cannot
            be created, or the database cannot be opened or configured.
    """
    # TODO(security, phase-5): TOCTOU race between is_symlink() and sqlite3.connect —
    # full fix requires os.open with O_NOFOLLOW (not portable on Windows). Deferred to Phase 5.
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
    """Return the current UTC time as an ISO 8601 string.

    Returns:
        ISO 8601 formatted timestamp with timezone offset.
    """
    return datetime.datetime.now(datetime.UTC).isoformat()


def _serialize_findings(findings: tuple[ScanFinding, ...]) -> str:
    """Serialise findings to a JSON string for audit storage.

    Only fields that cannot contain raw PHI are included. ``code_context``
    is deliberately excluded — it stores surrounding source lines that may
    contain the detected value in plaintext. ``file_path`` is stored as a
    SHA-256 hash (``file_path_hash``) — paths can be PHI-revealing (e.g.
    patient_ssn_export.csv) and must not be persisted in plaintext.

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
            "remediation_hint": finding.remediation_hint,
        }
        for finding in findings
    ]
    return json.dumps(serialized_findings)


def _get_current_branch() -> str:
    """Return the current git branch name, or 'unknown' if unavailable.

    Returns:
        The branch name string, or _UNKNOWN_BRANCH on any failure.
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
        # Log only the error type — branch names can embed PHI (e.g. feature/patient-john-doe).
        _logger.warning("Could not determine git branch: %s", type(git_error).__name__)
    return _UNKNOWN_BRANCH


def _get_current_repository_path() -> str:
    """Return the git repository root path, or the current directory if unavailable.

    Returns:
        Absolute path string of the repository root or CWD.
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
        # Log only the error type — repository paths can embed PHI (e.g. /home/patient_records/).
        _logger.warning("Could not determine git repository path: %s", type(git_error).__name__)
    # Path.cwd() follows symlinks on most platforms. The returned path is
    # SHA-256 hashed before storage, so no plaintext PHI is persisted even
    # if a symlinked CWD returns an attacker-influenced path.
    return str(Path.cwd())
