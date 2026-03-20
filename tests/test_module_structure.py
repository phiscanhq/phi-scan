"""Tests verifying all phi_scan module files are importable."""

import importlib
from importlib.metadata import metadata, version

import pytest
import typer

import phi_scan
from phi_scan.cli import app

EXPECTED_VERSION = version("phi-scan")
EXPECTED_APP_NAME = metadata("phi-scan")["Name"]

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
    assert phi_scan.__version__ == EXPECTED_VERSION


def test_package_app_name_is_defined() -> None:
    """Package app name must be the CLI command name."""
    assert phi_scan.__app_name__ == EXPECTED_APP_NAME
