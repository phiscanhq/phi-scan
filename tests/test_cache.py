"""Tests for phi_scan.cache — content-hash scan cache."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from phi_scan.cache import (
    CacheStats,
    FileCacheKey,
    compute_file_hash,
    get_cache_stats,
    get_cached_result,
    invalidate_cache,
    store_cached_result,
)
from phi_scan.constants import (
    DEFAULT_TEXT_ENCODING,
    SHA256_HEX_DIGEST_LENGTH,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_VALUE_HASH: str = hashlib.sha256(b"test-value").hexdigest()
_FAKE_REMEDIATION_HINT: str = "Remove this value."
_FAKE_CODE_CONTEXT: str = 'ssn = "[REDACTED]"'
_FAKE_ENTITY_TYPE: str = "SSN"

_CLEAN_CONTENT: str = "greeting = 'hello world'\n"
_MODIFIED_CONTENT: str = "greeting = 'goodbye world'\n"

_DEFAULT_CONFIG_HASH: str = "0" * SHA256_HEX_DIGEST_LENGTH
_ALTERNATE_CONFIG_HASH: str = "a" * SHA256_HEX_DIGEST_LENGTH
# ScanFinding requires a relative path — the absolute source_file used for I/O
# must not be passed directly to _make_finding.
_FAKE_FINDING_FILE_PATH: Path = Path("app.py")


def _make_finding(file_path: Path, line_number: int = 1) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=_FAKE_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_FAKE_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_FAKE_CODE_CONTEXT,
        remediation_hint=_FAKE_REMEDIATION_HINT,
    )


# ---------------------------------------------------------------------------
# compute_file_hash
# ---------------------------------------------------------------------------


class TestComputeFileHash:
    def test_returns_64_character_hex_string(self, tmp_path: Path) -> None:
        source_file = tmp_path / "sample.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

        file_hash = compute_file_hash(source_file)

        assert len(file_hash) == SHA256_HEX_DIGEST_LENGTH
        assert all(character in "0123456789abcdef" for character in file_hash)

    def test_same_content_produces_same_hash(self, tmp_path: Path) -> None:
        first_file = tmp_path / "first.py"
        second_file = tmp_path / "second.py"
        first_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        second_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

        assert compute_file_hash(first_file) == compute_file_hash(second_file)

    def test_different_content_produces_different_hash(self, tmp_path: Path) -> None:
        source_file = tmp_path / "sample.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        original_hash = compute_file_hash(source_file)

        source_file.write_text(_MODIFIED_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        modified_hash = compute_file_hash(source_file)

        assert original_hash != modified_hash

    def test_raises_phi_scan_error_on_missing_file(self, tmp_path: Path) -> None:
        from phi_scan.exceptions import PhiScanError

        missing_file = tmp_path / "nonexistent.py"

        with pytest.raises(PhiScanError):
            compute_file_hash(missing_file)


# ---------------------------------------------------------------------------
# Symlink guard
# ---------------------------------------------------------------------------


class TestSymlinkCachePathRejected:
    def test_raises_phi_scan_error_when_cache_path_is_symlink(self, tmp_path: Path) -> None:
        from phi_scan.exceptions import PhiScanError

        real_db = tmp_path / "real.db"
        real_db.touch()
        symlink_db = tmp_path / "cache.db"
        symlink_db.symlink_to(real_db)
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)

        with pytest.raises(PhiScanError, match="symlink"):
            get_cached_result(FileCacheKey(source_file, content_hash), cache_path=symlink_db)


# ---------------------------------------------------------------------------
# get_cached_result / store_cached_result
# ---------------------------------------------------------------------------


class TestCacheMissOnFirstScan:
    def test_returns_none_for_unscanned_file(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)

        cached_findings = get_cached_result(
            FileCacheKey(source_file, content_hash), cache_path=cache_db
        )

        assert cached_findings is None


class TestCacheHitOnUnchangedFile:
    def test_returns_findings_after_store(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        stored_findings = [_make_finding(_FAKE_FINDING_FILE_PATH)]
        cache_key = FileCacheKey(source_file, content_hash)

        store_cached_result(cache_key, stored_findings, cache_path=cache_db)
        cached_findings = get_cached_result(cache_key, cache_path=cache_db)

        assert cached_findings is not None
        assert len(cached_findings) == len(stored_findings)

    def test_reconstructed_finding_preserves_file_path(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        stored_finding = _make_finding(_FAKE_FINDING_FILE_PATH)
        cache_key = FileCacheKey(source_file, content_hash)

        store_cached_result(cache_key, [stored_finding], cache_path=cache_db)
        cached_findings = get_cached_result(cache_key, cache_path=cache_db)

        assert cached_findings is not None
        assert cached_findings[0].file_path == stored_finding.file_path

    def test_returns_empty_list_for_clean_cached_file(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "clean.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        cache_key = FileCacheKey(source_file, content_hash)

        store_cached_result(cache_key, [], cache_path=cache_db)
        cached_findings = get_cached_result(cache_key, cache_path=cache_db)

        assert cached_findings == []


class TestCacheInvalidation:
    def test_cache_miss_when_content_changes(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        original_hash = compute_file_hash(source_file)
        store_cached_result(FileCacheKey(source_file, original_hash), [], cache_path=cache_db)

        source_file.write_text(_MODIFIED_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        new_hash = compute_file_hash(source_file)

        cached_findings = get_cached_result(
            FileCacheKey(source_file, new_hash), cache_path=cache_db
        )

        assert cached_findings is None

    def test_cache_miss_when_config_hash_changes(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)

        store_cached_result(
            FileCacheKey(source_file, content_hash, _DEFAULT_CONFIG_HASH),
            [],
            cache_path=cache_db,
        )
        cached_findings = get_cached_result(
            FileCacheKey(source_file, content_hash, _ALTERNATE_CONFIG_HASH),
            cache_path=cache_db,
        )

        assert cached_findings is None

    def test_invalidate_cache_clears_all_entries(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        store_cached_result(FileCacheKey(source_file, content_hash), [], cache_path=cache_db)

        invalidate_cache(cache_path=cache_db)

        cached_findings = get_cached_result(
            FileCacheKey(source_file, content_hash), cache_path=cache_db
        )
        assert cached_findings is None

    def test_cache_miss_when_scanner_version_changes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        cache_key = FileCacheKey(source_file, content_hash)

        # Store a cache entry attributed to the current version.
        store_cached_result(cache_key, [], cache_path=cache_db)

        # Simulate a scanner version bump.
        monkeypatch.setattr("phi_scan.cache.__version__", "999.0.0")
        cached_findings = get_cached_result(cache_key, cache_path=cache_db)

        assert cached_findings is None


# ---------------------------------------------------------------------------
# get_cache_stats
# ---------------------------------------------------------------------------


class TestGetCacheStats:
    def test_total_entries_is_zero_on_empty_cache(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"

        cache_statistics = get_cache_stats(cache_path=cache_db)

        assert cache_statistics.total_entries == 0

    def test_total_entries_increments_after_store(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        store_cached_result(FileCacheKey(source_file, content_hash), [], cache_path=cache_db)

        cache_statistics = get_cache_stats(cache_path=cache_db)

        assert cache_statistics.total_entries == 1

    def test_total_entries_is_zero_after_invalidate(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"
        source_file = tmp_path / "app.py"
        source_file.write_text(_CLEAN_CONTENT, encoding=DEFAULT_TEXT_ENCODING)
        content_hash = compute_file_hash(source_file)
        store_cached_result(FileCacheKey(source_file, content_hash), [], cache_path=cache_db)
        invalidate_cache(cache_path=cache_db)

        cache_statistics = get_cache_stats(cache_path=cache_db)

        assert cache_statistics.total_entries == 0

    def test_returns_cache_stats_dataclass(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"

        cache_statistics = get_cache_stats(cache_path=cache_db)

        assert isinstance(cache_statistics, CacheStats)

    def test_database_path_matches_requested_path(self, tmp_path: Path) -> None:
        cache_db = tmp_path / "cache.db"

        cache_statistics = get_cache_stats(cache_path=cache_db)

        assert cache_statistics.database_path == cache_db
