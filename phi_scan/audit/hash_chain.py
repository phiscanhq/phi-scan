"""HMAC-SHA256 hash chain for audit log tamper detection.

Each audit row carries ``row_chain_hash = HMAC-SHA256(key=audit_secret,
msg=prev_chain_hash || row_content)``. The first row uses
``AUDIT_GENESIS_CHAIN_HASH`` as the previous hash. ``verify_audit_chain``
recomputes the chain in insertion order and returns a ``ChainVerifyResult``
indicating whether the stored hashes still match.

This module owns chain-hash computation, persistence of the chain hash on a
newly inserted row, and full-chain verification. It does not perform
encryption (see ``phi_scan.audit.crypto``) or general schema writes (see
``phi_scan.audit.__init__``).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from phi_scan.audit._shared import _DATABASE_ERROR, _SCAN_EVENTS_TABLE, _open_database
from phi_scan.audit.crypto import _audit_key_path, _load_audit_key, _redact_key_path
from phi_scan.constants import AUDIT_GENESIS_CHAIN_HASH
from phi_scan.exceptions import AuditLogError
from phi_scan.logging_config import get_logger

if TYPE_CHECKING:
    pass

_logger: logging.Logger = get_logger("audit")

# ---------------------------------------------------------------------------
# Log / error message templates
# ---------------------------------------------------------------------------

_CHAIN_TAMPER_ERROR: str = (
    "Audit chain verification failed at row id={row_id}: "
    "stored hash does not match recomputed hash — the audit log may have been tampered with"
)
_CHAIN_KEY_MISSING_WARNING: str = (
    "Audit chain key not found at %s — hash chain verification skipped. "
    "Run 'phi-scan setup' to generate the audit key."
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

# ---------------------------------------------------------------------------
# Implementation constants
# ---------------------------------------------------------------------------

_CHAIN_HASH_PLACEHOLDER: str = ""

# Row tuple positional indices for the three AI usage columns added in schema v3.
# Index 16 (row_chain_hash) is intentionally excluded from the chain-hash content
# dict in _compute_row_chain_hash — the chain hash cannot include itself.
_ROW_TUPLE_AI_INPUT_TOKENS_INDEX: int = 17
_ROW_TUPLE_AI_OUTPUT_TOKENS_INDEX: int = 18
_ROW_TUPLE_AI_COST_USD_INDEX: int = 19

_SELECT_ALL_ROWS_ORDERED_SQL: str = (
    f"SELECT id, timestamp, scanner_version, repository_hash, branch_hash, "
    f"files_scanned, findings_count, findings_json, is_clean, scan_duration, "
    f"event_type, committer_name_hash, committer_email_hash, pr_number, "
    f"pipeline, action_taken, notifications_sent, row_chain_hash "
    f"FROM {_SCAN_EVENTS_TABLE} ORDER BY id ASC"
)
_UPDATE_ROW_CHAIN_HASH_SQL: str = f"UPDATE {_SCAN_EVENTS_TABLE} SET row_chain_hash = ? WHERE id = ?"


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


# ---------------------------------------------------------------------------
# Hash chain primitives
# ---------------------------------------------------------------------------


def _hmac_sha256(key: bytearray, message: str) -> str:
    """Return HMAC-SHA256(key, message) as a lowercase hex string."""
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def _row_content_for_hashing(row_fields: dict[str, Any]) -> str:
    """Produce a canonical string representation of a row for hash chain computation.

    All fields except row_chain_hash itself are included, in a stable order,
    to detect any modification to any column value.

    PHI safety: the ``findings_json`` field included here is always the
    AES-256-GCM ciphertext string — never plaintext findings or raw ScanFinding
    content.
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
    """Write chain_hash into the row_chain_hash column for row_id, or log if absent."""
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
    """
    key = _load_audit_key(database_path.parent)
    if key is None:
        _logger.debug(
            _CHAIN_KEY_MISSING_WARNING, _redact_key_path(_audit_key_path(database_path.parent))
        )
        return ""
    try:
        prev_hash = _get_previous_chain_hash(connection, new_row_id)
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


# ---------------------------------------------------------------------------
# Full-chain verification
# ---------------------------------------------------------------------------


def _verify_chain_rows(audit_rows: list[Any], audit_key: bytearray) -> ChainVerifyResult:
    """Walk audit_rows in insertion order and verify each HMAC chain hash."""
    prev_hash = AUDIT_GENESIS_CHAIN_HASH
    skipped_rows = 0
    is_chain_intact = True
    for audit_row in audit_rows:
        row_fields = dict(audit_row)
        row_id = row_fields["id"]
        stored_hash: str = row_fields.get("row_chain_hash", "")
        if not stored_hash:
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
    clean result.
    """
    audit_key = _load_audit_key(database_path.parent)
    if audit_key is None:
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
