"""Tests verifying all phi_scan module files are importable.

Also pins the structural-safety invariant for threat-model row A-2
(zip-slip, P1): no module in the ``phi_scan`` package may call
``ZipFile.extract`` or ``ZipFile.extractall``. Archive members are read
into memory via ``ZipFile.read`` — a write-to-disk primitive must not
sneak back in silently. See ``docs/threat-model.md`` section 3.2.
"""

import ast
import importlib
from importlib.metadata import metadata, version
from pathlib import Path

import pytest
import typer

import phi_scan
from phi_scan.cli import app

PACKAGE_DISTRIBUTION_NAME = "phi-scan"
METADATA_NAME_KEY = "Name"

# Archive write-to-disk method names banned across the entire phi_scan
# package for threat-model row A-2 (zip-slip, P1). Both are unambiguous
# archive-object methods — stdlib has no other `.extract`/`.extractall`
# method on commonly used types, so the AST attribute-name check below
# has no known false positives.
_BANNED_ARCHIVE_METHOD_NAMES: frozenset[str] = frozenset({"extract", "extractall"})
_PHI_SCAN_PACKAGE_ROOT: Path = Path(phi_scan.__file__).parent
_PYTHON_SOURCE_GLOB: str = "**/*.py"
_SOURCE_FILE_ENCODING: str = "utf-8"

PHASE_ONE_MODULES = [
    "phi_scan.constants",
    "phi_scan.exceptions",
    "phi_scan.models",
    "phi_scan.logging_config",
    "phi_scan.config",
    "phi_scan.scanner",
    "phi_scan.diff",
    "phi_scan.output",
    "phi_scan.audit",
    "phi_scan.cli",
]

FUTURE_PHASE_MODULES = [
    "phi_scan.suppression",
    "phi_scan.cache",
    "phi_scan.help_text",
    "phi_scan.fhir_recognizer",
    "phi_scan.fixer",
    "phi_scan.baseline",
    "phi_scan.notifier",
    "phi_scan.compliance",
    "phi_scan.report",
    "phi_scan.plugin_api",
]


@pytest.mark.parametrize("module_name", PHASE_ONE_MODULES)
def test_phase_one_module_is_importable(module_name: str) -> None:
    """Each Phase 1 module must import without error and have a docstring."""
    imported_module = importlib.import_module(module_name)

    assert imported_module.__doc__ is not None, f"{module_name} is missing a module-level docstring"


@pytest.mark.parametrize("module_name", FUTURE_PHASE_MODULES)
def test_future_phase_module_is_importable(module_name: str) -> None:
    """Each future-phase stub module must import without error and have a docstring."""
    imported_module = importlib.import_module(module_name)

    assert imported_module.__doc__ is not None, f"{module_name} is missing a module-level docstring"


def test_cli_app_is_typer_instance() -> None:
    """The CLI entry point must be a Typer app instance."""
    assert isinstance(app, typer.Typer)


def test_package_version_matches_pyproject() -> None:
    """Package version must stay consistent with pyproject.toml."""
    expected_version = version(PACKAGE_DISTRIBUTION_NAME)

    assert phi_scan.__version__ == expected_version


def test_package_app_name_matches_distribution() -> None:
    """Package app name must match the PyPI distribution name."""
    expected_distribution_name = metadata(PACKAGE_DISTRIBUTION_NAME)[METADATA_NAME_KEY]

    assert phi_scan.__app_name__ == expected_distribution_name


# ---------------------------------------------------------------------------
# Structural safety — threat-model A-2 (P1)
# ---------------------------------------------------------------------------


def _find_banned_archive_extract_calls(source_path: Path) -> list[tuple[int, str]]:
    """Return ``(line_number, attr_name)`` for every banned archive call.

    Parses ``source_path`` with ``ast`` and walks every ``Call`` node.
    A hit is any ``Call`` whose ``func`` is an ``Attribute`` with
    ``attr in _BANNED_ARCHIVE_METHOD_NAMES``. The receiver is not
    constrained because ``extract`` and ``extractall`` are not used as
    method names on any other stdlib type we depend on.
    """
    module_source = source_path.read_text(encoding=_SOURCE_FILE_ENCODING)
    tree = ast.parse(module_source)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr in _BANNED_ARCHIVE_METHOD_NAMES:
            hits.append((node.lineno, func.attr))
    return hits


def test_phi_scan_package_contains_no_archive_extract_calls() -> None:
    """Structural regression gate for threat-model row A-2 (P1).

    PhiScan must never write archive members to disk — zip-slip is
    mitigated structurally by using ``ZipFile.read`` (memory-only)
    instead of ``ZipFile.extract`` / ``ZipFile.extractall``. This test
    walks every Python source file under ``phi_scan/`` and fails on
    any ``.extract(...)`` or ``.extractall(...)`` method call. A future
    change that reintroduces either primitive must update
    ``docs/threat-model.md`` row A-2 explicitly.
    """
    violations: list[str] = []
    for source_path in sorted(_PHI_SCAN_PACKAGE_ROOT.glob(_PYTHON_SOURCE_GLOB)):
        hits = _find_banned_archive_extract_calls(source_path)
        for line_number, attr_name in hits:
            relative_path = source_path.relative_to(_PHI_SCAN_PACKAGE_ROOT.parent)
            violations.append(f"{relative_path}:{line_number} calls .{attr_name}(...)")
    assert not violations, (
        "phi_scan package introduced archive extract primitives banned by "
        "threat-model row A-2 (P1). Violations: "
        f"{violations}. Members must be read via ZipFile.read into memory, "
        "never extracted to disk. Update docs/threat-model.md before merge."
    )
