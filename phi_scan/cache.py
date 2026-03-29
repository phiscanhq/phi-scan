"""Content-hash scan cache for incremental scanning (Phase 2).

Stores per-file scan results keyed by the SHA-256 hash of file content. An
unchanged file (same hash) returns its cached findings without re-scanning.
The cache is invalidated automatically when the scanner version or config hash
changes, and on explicit request via ``invalidate_cache()``.

Cache database: ~/.phi-scanner/cache.db (SQLite)
Schema version tracked in ``schema_meta`` table; increment CACHE_SCHEMA_VERSION
in constants.py to trigger automatic migration on next run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phi_scan import __version__
from phi_scan.constants import (
    CACHE_SCHEMA_VERSION,
    DEFAULT_TEXT_ENCODING,
    SHA256_HEX_DIGEST_LENGTH,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import PhiScanError
from phi_scan.models import ScanFinding

__all__ = [
    "CacheStats",
    "FileCacheKey",
    "compute_file_hash",
    "get_cache_stats",
    "get_cached_result",
    "invalidate_cache",
    "store_cached_result",
]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CACHE_PATH: str = "~/.phi-scanner/cache.db"
_HASH_ALGORITHM: str = "sha256"
_READ_CHUNK_SIZE_BYTES: int = 65536  # 64 KiB — balance memory and syscall count

# SQL table and column names
_TABLE_FILE_CACHE: str = "file_cache"
_TABLE_SCHEMA_META: str = "schema_meta"

_COL_FILE_PATH_HASH: str = "file_path_hash"
_COL_CONTENT_HASH: str = "content_hash_sha256"
_COL_LAST_SCAN_TS: str = "last_scan_timestamp"
_COL_FINDINGS_JSON: str = "findings_json"
_COL_SCANNER_VERSION: str = "scanner_version"
_COL_CONFIG_HASH: str = "config_hash"
_COL_KEY: str = "key"
_COL_VALUE: str = "value"

_META_KEY_SCHEMA_VERSION: str = "schema_version"
_META_KEY_SCANNER_VERSION: str = "scanner_version"

_CREATE_SCHEMA_META_SQL: str = f"""
CREATE TABLE IF NOT EXISTS {_TABLE_SCHEMA_META} (
    {_COL_KEY}   TEXT PRIMARY KEY NOT NULL,
    {_COL_VALUE} TEXT NOT NULL
)
"""

_CREATE_FILE_CACHE_SQL: str = f"""
CREATE TABLE IF NOT EXISTS {_TABLE_FILE_CACHE} (
    {_COL_FILE_PATH_HASH}  TEXT PRIMARY KEY NOT NULL,
    {_COL_CONTENT_HASH}    TEXT NOT NULL,
    {_COL_LAST_SCAN_TS}    TEXT NOT NULL,
    {_COL_FINDINGS_JSON}   TEXT NOT NULL,
    {_COL_SCANNER_VERSION} TEXT NOT NULL,
    {_COL_CONFIG_HASH}     TEXT NOT NULL
)
"""

_UPSERT_FILE_CACHE_SQL: str = f"""
INSERT INTO {_TABLE_FILE_CACHE}
    ({_COL_FILE_PATH_HASH}, {_COL_CONTENT_HASH}, {_COL_LAST_SCAN_TS},
     {_COL_FINDINGS_JSON}, {_COL_SCANNER_VERSION}, {_COL_CONFIG_HASH})
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT({_COL_FILE_PATH_HASH}) DO UPDATE SET
    {_COL_CONTENT_HASH}    = excluded.{_COL_CONTENT_HASH},
    {_COL_LAST_SCAN_TS}    = excluded.{_COL_LAST_SCAN_TS},
    {_COL_FINDINGS_JSON}   = excluded.{_COL_FINDINGS_JSON},
    {_COL_SCANNER_VERSION} = excluded.{_COL_SCANNER_VERSION},
    {_COL_CONFIG_HASH}     = excluded.{_COL_CONFIG_HASH}
"""

_SELECT_FILE_CACHE_SQL: str = f"""
SELECT {_COL_CONTENT_HASH}, {_COL_FINDINGS_JSON}, {_COL_SCANNER_VERSION}, {_COL_CONFIG_HASH}
FROM {_TABLE_FILE_CACHE}
WHERE {_COL_FILE_PATH_HASH} = ?
"""

_DELETE_ALL_CACHE_SQL: str = f"DELETE FROM {_TABLE_FILE_CACHE}"

_COUNT_CACHE_ENTRIES_SQL: str = f"SELECT COUNT(*) FROM {_TABLE_FILE_CACHE}"

_UPSERT_META_SQL: str = f"""
INSERT INTO {_TABLE_SCHEMA_META} ({_COL_KEY}, {_COL_VALUE})
VALUES (?, ?)
ON CONFLICT({_COL_KEY}) DO UPDATE SET {_COL_VALUE} = excluded.{_COL_VALUE}
"""

_SELECT_META_SQL: str = f"SELECT {_COL_VALUE} FROM {_TABLE_SCHEMA_META} WHERE {_COL_KEY} = ?"

# JSON keys used when serialising ScanFinding objects into the cache.
_FINDING_KEY_FILE_PATH: str = "file_path"
_FINDING_KEY_LINE_NUMBER: str = "line_number"
_FINDING_KEY_ENTITY_TYPE: str = "entity_type"
_FINDING_KEY_HIPAA_CATEGORY: str = "hipaa_category"
_FINDING_KEY_CONFIDENCE: str = "confidence"
_FINDING_KEY_DETECTION_LAYER: str = "detection_layer"
_FINDING_KEY_VALUE_HASH: str = "value_hash"
_FINDING_KEY_SEVERITY: str = "severity"
_FINDING_KEY_CODE_CONTEXT: str = "code_context"
_FINDING_KEY_REMEDIATION_HINT: str = "remediation_hint"

_DEFAULT_CONFIG_HASH: str = "0" * SHA256_HEX_DIGEST_LENGTH


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheStats:
    """Statistics returned by get_cache_stats().

    Args:
        total_entries: Number of files currently in the cache.
        cache_size_bytes: Approximate size of the cache database file on disk.
        database_path: Resolved path to the SQLite cache file.
    """

    total_entries: int
    cache_size_bytes: int
    database_path: Path


@dataclass(frozen=True)
class FileCacheKey:
    """Immutable key identifying a cached scan result.

    Bundles the three values that together uniquely identify a valid cache
    entry: which file, what its content was, and what config was active.

    Args:
        file_path: Path to the source file being cached.
        content_hash: SHA-256 hex digest of the file's current content.
        config_hash: SHA-256 hex digest of the active scan configuration.
            Defaults to the zero-hash sentinel for callers that do not track
            configuration changes.
    """

    file_path: Path
    content_hash: str
    config_hash: str = _DEFAULT_CONFIG_HASH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_file_hash(file_path: Path) -> str:
    """Return the SHA-256 hex digest of a file's content.

    Reads the file in 64 KiB chunks to avoid loading large files into memory.

    Args:
        file_path: Path to the file to hash.

    Returns:
        64-character lowercase hex string.

    Raises:
        PhiScanError: If the file cannot be read.
    """
    digest = hashlib.new(_HASH_ALGORITHM)
    try:
        with file_path.open("rb") as file_handle:
            while chunk := file_handle.read(_READ_CHUNK_SIZE_BYTES):
                digest.update(chunk)
    except OSError as exc:
        raise PhiScanError(f"Cannot compute hash for {file_path}: {exc}") from exc
    return digest.hexdigest()


def get_cached_result(
    cache_key: FileCacheKey,
    cache_path: Path | None = None,
) -> list[ScanFinding] | None:
    """Return cached findings for a file if the content and config are unchanged.

    Returns None (cache miss) when:
    - The file has never been scanned.
    - The content hash differs from the cached value (file was modified).
    - The scanner version differs (detector logic changed).
    - The config hash differs (scan configuration changed).

    Args:
        cache_key: FileCacheKey bundling the file path, content hash, and config
            hash that together identify a valid cache entry.
        cache_path: Override the default cache database location. Defaults to
            ``~/.phi-scanner/cache.db``.

    Returns:
        List of ScanFinding objects, or None on cache miss.
    """
    resolved_cache_path = _resolve_cache_path(cache_path)
    _initialise_cache_schema(resolved_cache_path)

    file_path_hash = _compute_string_hash(str(cache_key.file_path))
    try:
        with sqlite3.connect(resolved_cache_path) as connection:
            cursor = connection.execute(_SELECT_FILE_CACHE_SQL, (file_path_hash,))
            row = cursor.fetchone()
    except sqlite3.Error as exc:
        _logger.warning("Cache read failed for %s: %s", cache_key.file_path, exc)
        return None

    if row is None:
        return None

    cached_content_hash, findings_json, cached_scanner_version, cached_config_hash = row

    if cached_content_hash != cache_key.content_hash:
        return None
    if cached_scanner_version != __version__:
        return None
    if cached_config_hash != cache_key.config_hash:
        return None

    return _deserialise_findings(findings_json)


def store_cached_result(
    cache_key: FileCacheKey,
    findings: list[ScanFinding],
    cache_path: Path | None = None,
) -> None:
    """Persist scan findings for a file into the cache.

    Performs an upsert — existing entries for the same file path are replaced.

    Args:
        cache_key: FileCacheKey bundling the file path, content hash, and config
            hash that together identify this cache entry.
        findings: Findings produced by the scan. May be empty (clean file).
        cache_path: Override the default cache database location.
    """
    resolved_cache_path = _resolve_cache_path(cache_path)
    _initialise_cache_schema(resolved_cache_path)

    file_path_hash = _compute_string_hash(str(cache_key.file_path))
    findings_json = _serialise_findings(findings)
    scanned_at = datetime.now(tz=UTC).isoformat()

    try:
        with sqlite3.connect(resolved_cache_path) as connection:
            connection.execute(
                _UPSERT_FILE_CACHE_SQL,
                (
                    file_path_hash,
                    cache_key.content_hash,
                    scanned_at,
                    findings_json,
                    __version__,
                    cache_key.config_hash,
                ),
            )
    except sqlite3.Error as exc:
        _logger.warning("Cache write failed for %s: %s", cache_key.file_path, exc)


def invalidate_cache(cache_path: Path | None = None) -> None:
    """Delete all entries from the scan cache.

    Used when the scanner version changes, the configuration changes, or the
    user passes ``--no-cache``.

    Args:
        cache_path: Override the default cache database location.
    """
    resolved_cache_path = _resolve_cache_path(cache_path)
    _initialise_cache_schema(resolved_cache_path)
    try:
        with sqlite3.connect(resolved_cache_path) as connection:
            connection.execute(_DELETE_ALL_CACHE_SQL)
        _logger.info("Scan cache invalidated.")
    except sqlite3.Error as exc:
        _logger.warning("Cache invalidation failed: %s", exc)


def get_cache_stats(cache_path: Path | None = None) -> CacheStats:
    """Return statistics about the current cache state.

    Args:
        cache_path: Override the default cache database location.

    Returns:
        CacheStats with total_entries, cache_size_bytes, and database_path.
    """
    resolved_cache_path = _resolve_cache_path(cache_path)
    _initialise_cache_schema(resolved_cache_path)

    total_entries = 0
    try:
        with sqlite3.connect(resolved_cache_path) as connection:
            cursor = connection.execute(_COUNT_CACHE_ENTRIES_SQL)
            row = cursor.fetchone()
            if row is not None:
                total_entries = row[0]
    except sqlite3.Error as exc:
        _logger.warning("Cache stats query failed: %s", exc)

    # Use is_file() rather than exists() so a dangling symlink or directory at
    # the cache path doesn't cause a misleading non-zero size to be returned.
    cache_size_bytes = resolved_cache_path.stat().st_size if resolved_cache_path.is_file() else 0
    return CacheStats(
        total_entries=total_entries,
        cache_size_bytes=cache_size_bytes,
        database_path=resolved_cache_path,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _resolve_cache_path(cache_path: Path | None) -> Path:
    """Return the resolved cache database path, expanding ~ only.

    Pure function — no filesystem side effects. Directory creation is handled
    by _ensure_cache_schema so that setup is co-located with the DB open call.
    """
    return (cache_path or Path(_DEFAULT_CACHE_PATH)).expanduser()


# Tracks which database paths have been initialised in this process. Avoids
# re-running four DDL/upsert statements on every public function call.
# Thread safety: CPython's GIL ensures that set membership tests and adds are
# atomic for built-in types, so no explicit lock is needed here. The worst case
# under concurrent first access is redundant (idempotent) DDL execution.
_initialised_cache_paths: set[Path] = set()


def _initialise_cache_schema(cache_path: Path) -> None:
    """Create the cache directory, tables, and schema_meta if not yet done.

    Runs exactly once per (cache_path, process lifetime) pair — subsequent
    calls for the same path return immediately via the module-level guard.
    """
    if cache_path in _initialised_cache_paths:
        return
    # Directory must exist before sqlite3.connect opens or creates the file.
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(cache_path) as connection:
            connection.execute(_CREATE_SCHEMA_META_SQL)
            connection.execute(_CREATE_FILE_CACHE_SQL)
            connection.execute(
                _UPSERT_META_SQL,
                (_META_KEY_SCHEMA_VERSION, str(CACHE_SCHEMA_VERSION)),
            )
            connection.execute(
                _UPSERT_META_SQL,
                (_META_KEY_SCANNER_VERSION, __version__),
            )
    except sqlite3.Error as exc:
        raise PhiScanError(f"Cache schema initialisation failed: {exc}") from exc
    _initialised_cache_paths.add(cache_path)


def _compute_string_hash(text: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.new(_HASH_ALGORITHM, text.encode(DEFAULT_TEXT_ENCODING)).hexdigest()


def _serialise_findings(findings: list[ScanFinding]) -> str:
    """Convert a list of ScanFinding objects to a compact JSON string."""
    return json.dumps([_finding_to_dict(finding) for finding in findings], separators=(",", ":"))


def _deserialise_findings(findings_json: str) -> list[ScanFinding] | None:
    """Reconstruct ScanFinding objects from a JSON string.

    Returns None (cache miss) if deserialisation fails — malformed cache
    entries should not crash the scanner.
    """
    try:
        records: list[dict[str, Any]] = json.loads(findings_json)
        return [_dict_to_finding(record) for record in records]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        _logger.warning("Cache deserialisation failed: %s", exc)
        return None


def _finding_to_dict(finding: ScanFinding) -> dict[str, Any]:
    """Serialise a ScanFinding to a JSON-safe dict.

    file_path is stored as the original path string so that _dict_to_finding
    can reconstruct a usable ScanFinding. The DB primary key (file_path_hash
    column) is a separate SHA-256 hash used only for lookup — it is never stored
    in the JSON payload.
    """
    return {
        _FINDING_KEY_FILE_PATH: str(finding.file_path),
        _FINDING_KEY_LINE_NUMBER: finding.line_number,
        _FINDING_KEY_ENTITY_TYPE: finding.entity_type,
        _FINDING_KEY_HIPAA_CATEGORY: finding.hipaa_category.value,
        _FINDING_KEY_CONFIDENCE: finding.confidence,
        _FINDING_KEY_DETECTION_LAYER: finding.detection_layer.value,
        _FINDING_KEY_VALUE_HASH: finding.value_hash,
        _FINDING_KEY_SEVERITY: finding.severity.value,
        _FINDING_KEY_CODE_CONTEXT: finding.code_context,
        _FINDING_KEY_REMEDIATION_HINT: finding.remediation_hint,
    }


def _dict_to_finding(record: dict[str, Any]) -> ScanFinding:
    """Reconstruct a ScanFinding from a cached JSON record.

    No explicit value_hash format check is needed here — ScanFinding.__post_init__
    calls _reject_invalid_value_hash, which enforces the SHA-256 hex pattern.
    A corrupted cache entry will raise ValueError, which _deserialise_findings
    catches and converts to a cache miss.
    """
    return ScanFinding(
        file_path=Path(record[_FINDING_KEY_FILE_PATH]),
        line_number=record[_FINDING_KEY_LINE_NUMBER],
        entity_type=record[_FINDING_KEY_ENTITY_TYPE],
        hipaa_category=PhiCategory(record[_FINDING_KEY_HIPAA_CATEGORY]),
        confidence=record[_FINDING_KEY_CONFIDENCE],
        detection_layer=DetectionLayer(record[_FINDING_KEY_DETECTION_LAYER]),
        value_hash=record[_FINDING_KEY_VALUE_HASH],
        severity=SeverityLevel(record[_FINDING_KEY_SEVERITY]),
        code_context=record[_FINDING_KEY_CODE_CONTEXT],
        remediation_hint=record[_FINDING_KEY_REMEDIATION_HINT],
    )
