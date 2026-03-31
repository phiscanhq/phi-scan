# phi-scan:ignore-file
"""Tests for package metadata correctness and entry point availability.

Verifies that the installed package's metadata (via importlib.metadata) is
consistent with the values declared in pyproject.toml and phi_scan/__init__.py:

  - Installed package name is "phi-scan".
  - Installed version matches phi_scan.__version__.
  - License is MIT.
  - The phi-scan entry point is registered and maps to phi_scan.cli:app.
  - The package is importable and exports __version__ and __app_name__.
  - pyproject.toml version field matches phi_scan.__version__ (prevents drift
    between the declared version and the installed module version).

No build-tool invocation (uv build / pip wheel) is performed here — those are
CI responsibilities. What these tests verify is that the *installed* package
metadata is correct and internally consistent.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest

import phi_scan
from phi_scan import __app_name__, __version__

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_EXPECTED_PACKAGE_NAME: str = "phi-scan"
_EXPECTED_APP_NAME: str = "phi-scan"
_EXPECTED_LICENSE: str = "MIT"
_EXPECTED_ENTRY_POINT_GROUP: str = "console_scripts"
_EXPECTED_ENTRY_POINT_VALUE: str = "phi_scan.cli:app"
_PYPROJECT_TOML_PATH: Path = Path(__file__).parent.parent / "pyproject.toml"

# Normalise package names per PEP 503 (dashes → underscores, lowercase)
# importlib.metadata returns the canonical name; "phi-scan" and "phi_scan" are
# equivalent per the packaging spec.
_PYPROJECT_VERSION_KEY: str = "version"
_PYPROJECT_PROJECT_SECTION: str = "[project]"


# ---------------------------------------------------------------------------
# importlib.metadata
# ---------------------------------------------------------------------------


class TestInstalledPackageMetadata:
    @pytest.fixture(scope="class")
    def metadata(self) -> importlib.metadata.PackageMetadata:
        return importlib.metadata.metadata(_EXPECTED_PACKAGE_NAME)

    def test_package_is_installed_and_has_metadata(
        self, metadata: importlib.metadata.PackageMetadata
    ) -> None:
        assert metadata is not None

    def test_installed_version_matches_module_version(
        self, metadata: importlib.metadata.PackageMetadata
    ) -> None:
        assert metadata["Version"] == __version__

    def test_installed_name_is_phi_scan(self, metadata: importlib.metadata.PackageMetadata) -> None:
        installed_name: str = metadata["Name"]
        # Normalise per PEP 503 before comparing
        assert installed_name.lower().replace("_", "-") == _EXPECTED_PACKAGE_NAME

    def test_installed_license_is_mit(self, metadata: importlib.metadata.PackageMetadata) -> None:
        # License field may be "MIT" or "MIT License" depending on the metadata format
        license_value: str = metadata.get("License", "")
        assert _EXPECTED_LICENSE in license_value


# ---------------------------------------------------------------------------
# Entry point registration
# ---------------------------------------------------------------------------


class TestEntryPointRegistration:
    def test_phi_scan_console_script_entry_point_is_registered(self) -> None:
        entry_points = importlib.metadata.entry_points(group=_EXPECTED_ENTRY_POINT_GROUP)
        phi_scan_eps = [ep for ep in entry_points if ep.name == _EXPECTED_APP_NAME]

        assert phi_scan_eps, (
            f"No console_scripts entry point named {_EXPECTED_APP_NAME!r} found. "
            "Check the [project.scripts] section of pyproject.toml."
        )

    def test_phi_scan_entry_point_maps_to_cli_app(self) -> None:
        entry_points = importlib.metadata.entry_points(group=_EXPECTED_ENTRY_POINT_GROUP)
        phi_scan_eps = [ep for ep in entry_points if ep.name == _EXPECTED_APP_NAME]
        assert phi_scan_eps
        ep = phi_scan_eps[0]

        assert ep.value == _EXPECTED_ENTRY_POINT_VALUE

    def test_phi_scan_entry_point_is_loadable(self) -> None:
        """The entry point must be importable — catches module path renames."""
        entry_points = importlib.metadata.entry_points(group=_EXPECTED_ENTRY_POINT_GROUP)
        phi_scan_eps = [ep for ep in entry_points if ep.name == _EXPECTED_APP_NAME]
        assert phi_scan_eps
        ep = phi_scan_eps[0]

        loaded = ep.load()

        assert loaded is not None


# ---------------------------------------------------------------------------
# phi_scan module exports
# ---------------------------------------------------------------------------


class TestPhiScanModuleExports:
    def test_phi_scan_is_importable(self) -> None:
        assert phi_scan is not None

    def test_version_attribute_is_a_string(self) -> None:
        assert isinstance(__version__, str)

    def test_version_attribute_is_non_empty(self) -> None:
        assert __version__ != ""

    def test_version_follows_semver_structure(self) -> None:
        """Version must have at least two dots (MAJOR.MINOR.PATCH)."""
        parts = __version__.split(".")
        assert len(parts) >= 3, (
            f"Version {__version__!r} does not follow MAJOR.MINOR.PATCH structure"
        )

    def test_app_name_attribute_is_phi_scan(self) -> None:
        assert __app_name__ == _EXPECTED_APP_NAME

    def test_app_name_attribute_is_a_string(self) -> None:
        assert isinstance(__app_name__, str)


# ---------------------------------------------------------------------------
# pyproject.toml version consistency
# ---------------------------------------------------------------------------


class TestPyprojectVersionConsistency:
    def test_pyproject_toml_exists(self) -> None:
        assert _PYPROJECT_TOML_PATH.exists(), f"pyproject.toml not found at {_PYPROJECT_TOML_PATH}"

    def test_pyproject_toml_version_matches_module_version(self) -> None:
        """Prevents drift between pyproject.toml [project] version and __version__."""
        content = _PYPROJECT_TOML_PATH.read_text(encoding="utf-8")
        # Extract version = "x.y.z" from [project] section.
        # We parse naively (no TOML library needed) because the version line
        # appears in a predictable position with no ambiguity.
        in_project_section = False
        pyproject_version: str | None = None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == _PYPROJECT_PROJECT_SECTION:
                in_project_section = True
                continue
            is_new_section = stripped.startswith("[") and stripped != _PYPROJECT_PROJECT_SECTION
            if in_project_section and is_new_section:
                # Entered a new section — stop looking
                break
            if in_project_section and stripped.startswith(_PYPROJECT_VERSION_KEY + " ="):
                # version = "x.y.z"
                pyproject_version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                break

        assert pyproject_version is not None, (
            "Could not find 'version' in [project] section of pyproject.toml"
        )
        assert pyproject_version == __version__, (
            f"pyproject.toml version {pyproject_version!r} != "
            f"phi_scan.__version__ {__version__!r}. "
            "Update one to match the other."
        )
