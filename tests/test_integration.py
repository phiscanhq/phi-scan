"""End-to-end integration tests for PhiScan — task 1F.9.

Covers the full pipeline from CLI invocation through scanner → audit → output.
Each test invokes the CLI via CliRunner and verifies exactly one observable
behaviour at the integration boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phi_scan.audit import create_audit_schema, get_last_scan
from phi_scan.cli import app
from phi_scan.constants import EXIT_CODE_CLEAN

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_ENCODING: str = "utf-8"

# Configuration YAML template — version key required; audit.database_path redirected.
_CONFIGURATION_YAML_TEMPLATE: str = "version: 1\naudit:\n  database_path: {database_path}\n"

# Directory and file names used to build the two-file exclude fixture.
_SOURCE_DIR_NAME: str = "src"
_SCAN_TARGET_DIR_NAME: str = "scan_root"
_SOURCE_FILE_NAME: str = "app.py"
_EXCLUDED_DIR_NAME: str = "node_modules"
_EXCLUDED_FILE_NAME: str = "secret.py"
_SOURCE_FILE_CONTENT: str = "# placeholder source file\n"
_EXCLUDED_FILE_CONTENT: str = "# excluded source file\n"

# JSON output keys asserted across multiple tests.
_JSON_KEY_IS_CLEAN: str = "is_clean"
_JSON_KEY_FILES_SCANNED: str = "files_scanned"

# Observable message fragments from the report command.
_NO_SCAN_RECORD_MESSAGE_FRAGMENT: str = "No scan record found"

# Expected files_scanned count when the excluded directory is filtered out.
_EXPECTED_FILES_SCANNED_WITH_EXCLUDE: int = 1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    """Return a fresh CliRunner instance isolated per test."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_test_configuration(tmp_path: Path, database_path: Path) -> Path:
    """Write a versioned .phi-scanner.yml that redirects audit writes to database_path.

    The configuration file is written to tmp_path so it sits outside the scan
    root and is never picked up as a scan target.

    Args:
        tmp_path: pytest tmp_path fixture directory.
        database_path: Path where the audit database should be written.

    Returns:
        Path to the written configuration file.
    """
    configuration_path = tmp_path / ".phi-scanner.yml"
    configuration_path.write_text(
        _CONFIGURATION_YAML_TEMPLATE.format(database_path=str(database_path)),
        encoding=_TEST_FILE_ENCODING,
    )
    return configuration_path


def _create_scan_root_directory(tmp_path: Path) -> Path:
    """Create an empty subdirectory to use as the scan root.

    Placing scan targets in a subdirectory keeps the configuration file
    (written to tmp_path) outside the scan root, preventing it from being
    picked up as a scan target.

    Args:
        tmp_path: pytest tmp_path fixture directory.

    Returns:
        Path to the empty scan root subdirectory.
    """
    scan_root = tmp_path / _SCAN_TARGET_DIR_NAME
    scan_root.mkdir()
    return scan_root


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scan_empty_directory_exits_clean(tmp_path: Path, runner: CliRunner) -> None:
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root = _create_scan_root_directory(tmp_path)

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    assert cli_invocation.exit_code == EXIT_CODE_CLEAN


def test_scan_empty_directory_writes_audit_record(tmp_path: Path, runner: CliRunner) -> None:
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root = _create_scan_root_directory(tmp_path)

    runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    create_audit_schema(database_path)
    last_scan = get_last_scan(database_path)
    assert last_scan is not None


def test_scan_directory_with_exclude_does_not_scan_excluded_file(
    tmp_path: Path, runner: CliRunner
) -> None:
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root = _create_scan_root_directory(tmp_path)
    source_dir = scan_root / _SOURCE_DIR_NAME
    source_dir.mkdir()
    (source_dir / _SOURCE_FILE_NAME).write_text(_SOURCE_FILE_CONTENT, encoding=_TEST_FILE_ENCODING)
    excluded_dir = scan_root / _EXCLUDED_DIR_NAME
    excluded_dir.mkdir()
    (excluded_dir / _EXCLUDED_FILE_NAME).write_text(
        _EXCLUDED_FILE_CONTENT, encoding=_TEST_FILE_ENCODING
    )

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    json_output = json.loads(cli_invocation.stdout)
    assert json_output[_JSON_KEY_FILES_SCANNED] == _EXPECTED_FILES_SCANNED_WITH_EXCLUDE


def test_scan_directory_produces_clean_result_json(tmp_path: Path, runner: CliRunner) -> None:
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root = _create_scan_root_directory(tmp_path)

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    json_output = json.loads(cli_invocation.stdout)
    assert json_output[_JSON_KEY_IS_CLEAN] is True


def test_scan_report_command_returns_no_record_when_no_scan_performed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    fresh_database_path = str(tmp_path / "audit.db")
    # Patch the name bound in cli.py's namespace — that is the binding used at
    # call time by the report command (imported via `from phi_scan.constants import`).
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", fresh_database_path)

    cli_invocation = runner.invoke(app, ["report"])

    assert _NO_SCAN_RECORD_MESSAGE_FRAGMENT in cli_invocation.output


def test_full_pipeline_scan_then_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    shared_database_path = tmp_path / "audit.db"
    # Both scan (via configuration) and report (via monkeypatched constant) must
    # point at the same database so that report can read the record scan wrote.
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", str(shared_database_path))
    configuration_path = _write_test_configuration(tmp_path, shared_database_path)
    scan_root = _create_scan_root_directory(tmp_path)

    scan_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )
    report_invocation = runner.invoke(app, ["report"])

    assert scan_invocation.exit_code == EXIT_CODE_CLEAN
    assert report_invocation.exit_code == EXIT_CODE_CLEAN
