"""Structural validation tests for the PHI detection fixture corpus.

These tests verify that the fixture files and manifest are well-formed and
consistent. Detection assertions (did the scanner find the right entity types?)
are deferred to per-detector tests in Phase 2, once the detection engine exists.
"""

import json
from pathlib import Path
from typing import Any

import pytest

_FIXTURES_ROOT = Path(__file__).parent / "fixtures"
_MANIFEST_PATH = _FIXTURES_ROOT / "manifest.json"
_PHI_FIXTURE_DIR = _FIXTURES_ROOT / "phi"
_CLEAN_FIXTURE_DIR = _FIXTURES_ROOT / "clean"

_MANIFEST_VERSION = "1.0.0"
_MANIFEST_FIXTURES_KEY = "fixtures"
_MANIFEST_PATH_KEY = "path"
_MANIFEST_CATEGORY_KEY = "category"
_MANIFEST_MIN_FINDINGS_KEY = "expected_min_findings"
_MANIFEST_MAX_FINDINGS_KEY = "expected_max_findings"
_MANIFEST_ENTITY_TYPES_KEY = "primary_entity_types"
_MANIFEST_VERSION_KEY = "version"

_CATEGORY_PHI = "phi"
_CATEGORY_CLEAN = "clean"

_REQUIRED_MANIFEST_KEYS = {
    _MANIFEST_PATH_KEY,
    _MANIFEST_CATEGORY_KEY,
    _MANIFEST_MIN_FINDINGS_KEY,
    _MANIFEST_ENTITY_TYPES_KEY,
}

_MINIMUM_PHI_FIXTURE_COUNT = 13
_MINIMUM_CLEAN_FIXTURE_COUNT = 3


def _read_manifest_file() -> dict[str, Any]:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _extract_phi_fixture_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        fixture_entry
        for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]
        if fixture_entry[_MANIFEST_CATEGORY_KEY] == _CATEGORY_PHI
    ]


def _extract_clean_fixture_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        fixture_entry
        for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]
        if fixture_entry[_MANIFEST_CATEGORY_KEY] == _CATEGORY_CLEAN
    ]


class TestManifestStructure:
    def test_manifest_file_exists(self) -> None:
        assert _MANIFEST_PATH.exists(), f"manifest.json not found at {_MANIFEST_PATH}"

    def test_manifest_is_valid_json(self) -> None:
        manifest = _read_manifest_file()
        assert isinstance(manifest, dict)

    def test_manifest_has_version(self) -> None:
        manifest = _read_manifest_file()
        assert manifest.get(_MANIFEST_VERSION_KEY) == _MANIFEST_VERSION

    def test_manifest_has_fixtures_list(self) -> None:
        manifest = _read_manifest_file()
        assert _MANIFEST_FIXTURES_KEY in manifest
        assert isinstance(manifest[_MANIFEST_FIXTURES_KEY], list)
        assert len(manifest[_MANIFEST_FIXTURES_KEY]) > 0

    def test_every_fixture_entry_has_required_keys(self) -> None:
        manifest = _read_manifest_file()
        for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]:
            missing = _REQUIRED_MANIFEST_KEYS - fixture_entry.keys()
            assert not missing, (
                f"Fixture {fixture_entry.get(_MANIFEST_PATH_KEY)!r} "
                f"is missing required keys: {missing}"
            )

    def test_phi_fixture_count_meets_minimum(self) -> None:
        manifest = _read_manifest_file()
        phi_entries = _extract_phi_fixture_entries(manifest)
        assert len(phi_entries) >= _MINIMUM_PHI_FIXTURE_COUNT

    def test_clean_fixture_count_meets_minimum(self) -> None:
        manifest = _read_manifest_file()
        clean_entries = _extract_clean_fixture_entries(manifest)
        assert len(clean_entries) >= _MINIMUM_CLEAN_FIXTURE_COUNT

    def test_phi_fixtures_have_positive_min_findings(self) -> None:
        manifest = _read_manifest_file()
        for fixture_entry in _extract_phi_fixture_entries(manifest):
            assert fixture_entry[_MANIFEST_MIN_FINDINGS_KEY] >= 1, (
                f"PHI fixture {fixture_entry[_MANIFEST_PATH_KEY]!r} must expect "
                f"at least 1 finding (got {fixture_entry[_MANIFEST_MIN_FINDINGS_KEY]})"
            )

    def test_clean_fixtures_have_zero_max_findings(self) -> None:
        manifest = _read_manifest_file()
        for fixture_entry in _extract_clean_fixture_entries(manifest):
            assert fixture_entry.get(_MANIFEST_MAX_FINDINGS_KEY) == 0, (
                f"Clean fixture {fixture_entry[_MANIFEST_PATH_KEY]!r} must declare "
                f"expected_max_findings: 0"
            )

    def test_manifest_paths_are_unique(self) -> None:
        manifest = _read_manifest_file()
        paths = [
            fixture_entry[_MANIFEST_PATH_KEY] for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]
        ]
        assert len(paths) == len(set(paths)), "Duplicate fixture paths found in manifest"


class TestFixtureFilesExist:
    def test_all_manifest_fixture_files_exist_on_disk(self) -> None:
        manifest = _read_manifest_file()
        missing_files: list[str] = []
        for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]:
            fixture_path = _FIXTURES_ROOT / fixture_entry[_MANIFEST_PATH_KEY]
            if not fixture_path.is_file() or fixture_path.is_symlink():
                missing_files.append(fixture_entry[_MANIFEST_PATH_KEY])
        assert not missing_files, (
            f"Fixture files declared in manifest but not found: {missing_files}"
        )

    def test_phi_directory_exists(self) -> None:
        assert _PHI_FIXTURE_DIR.is_dir()

    def test_clean_directory_exists(self) -> None:
        assert _CLEAN_FIXTURE_DIR.is_dir()

    def test_no_undeclared_phi_fixtures(self) -> None:
        manifest = _read_manifest_file()
        declared_paths = {
            fixture_entry[_MANIFEST_PATH_KEY]
            for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]
            if fixture_entry[_MANIFEST_CATEGORY_KEY] == _CATEGORY_PHI
        }
        actual_files = {
            f"{_CATEGORY_PHI}/{p.name}" for p in _PHI_FIXTURE_DIR.glob("*.py") if not p.is_symlink()
        }
        undeclared = actual_files - declared_paths
        assert not undeclared, (
            f"PHI fixture files exist on disk but are missing from manifest.json: {undeclared}"
        )

    def test_no_undeclared_clean_fixtures(self) -> None:
        manifest = _read_manifest_file()
        declared_paths = {
            fixture_entry[_MANIFEST_PATH_KEY]
            for fixture_entry in manifest[_MANIFEST_FIXTURES_KEY]
            if fixture_entry[_MANIFEST_CATEGORY_KEY] == _CATEGORY_CLEAN
        }
        actual_files = {
            f"{_CATEGORY_CLEAN}/{p.name}"
            for p in _CLEAN_FIXTURE_DIR.glob("*.py")
            if not p.is_symlink()
        }
        undeclared = actual_files - declared_paths
        assert not undeclared, (
            f"Clean fixture files exist on disk but are missing from manifest.json: {undeclared}"
        )


class TestFixtureFileContent:
    @pytest.mark.parametrize(
        "fixture_path",
        [
            pytest.param(f"{_CATEGORY_PHI}/{p.name}", id=p.name)
            for p in sorted(_PHI_FIXTURE_DIR.glob("*.py"))
            if not p.is_symlink()
        ],
    )
    def test_phi_fixture_is_non_empty(self, fixture_path: str) -> None:
        full_path = _FIXTURES_ROOT / fixture_path
        assert full_path.stat().st_size > 0, f"{fixture_path} is an empty file"

    @pytest.mark.parametrize(
        "fixture_path",
        [
            pytest.param(f"{_CATEGORY_CLEAN}/{p.name}", id=p.name)
            for p in sorted(_CLEAN_FIXTURE_DIR.glob("*.py"))
            if not p.is_symlink()
        ],
    )
    def test_clean_fixture_is_non_empty(self, fixture_path: str) -> None:
        full_path = _FIXTURES_ROOT / fixture_path
        assert full_path.stat().st_size > 0, f"{fixture_path} is an empty file"

    def test_phi_fixtures_have_expected_findings_comment(self) -> None:
        """Every PHI fixture must declare its expected finding count in a comment."""
        missing_comment: list[str] = []
        for phi_file in _PHI_FIXTURE_DIR.glob("*.py"):
            if phi_file.is_symlink():
                continue
            file_text = phi_file.read_text(encoding="utf-8")
            if "Expected findings:" not in file_text:
                missing_comment.append(phi_file.name)
        assert not missing_comment, (
            f"PHI fixtures missing 'Expected findings:' comment: {missing_comment}"
        )

    def test_clean_fixtures_have_expected_findings_comment(self) -> None:
        """Every clean fixture must declare zero expected findings in a comment."""
        missing_comment: list[str] = []
        for clean_file in _CLEAN_FIXTURE_DIR.glob("*.py"):
            if clean_file.is_symlink():
                continue
            file_text = clean_file.read_text(encoding="utf-8")
            if "Expected findings: 0" not in file_text:
                missing_comment.append(clean_file.name)
        assert not missing_comment, (
            f"Clean fixtures missing 'Expected findings: 0' comment: {missing_comment}"
        )
