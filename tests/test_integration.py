# phi-scan:ignore-file
"""End-to-end integration tests for PhiScan — tasks 1F.9 and 2G.14.

Covers the full pipeline from CLI invocation through scanner → audit → output.
Each test invokes the CLI via CliRunner and verifies exactly one observable
behaviour at the integration boundary.

Task 2G.14 tests added at the end of this file: scan → detect → cache → re-scan
(cache hit) → output verification → audit log verification.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from phi_scan.audit import generate_audit_key, get_last_scan
from phi_scan.cli import app
from phi_scan.config import create_default_config
from phi_scan.constants import EXIT_CODE_CLEAN, EXIT_CODE_VIOLATION

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_TEST_FILE_ENCODING: str = "utf-8"

# Directory and file names used to build the two-file exclude fixture.
_SOURCE_DIR_NAME: str = "src"
_SCAN_TARGET_DIR_NAME: str = "scan_root"
_SOURCE_FILE_NAME: str = "app.py"
_EXCLUDED_DIR_NAME: str = "node_modules"
_EXCLUDED_DIR_PATTERN: str = f"{_EXCLUDED_DIR_NAME}/"
_EXCLUDED_FILE_NAME: str = "secret.py"
_SOURCE_FILE_CONTENT: str = "# placeholder source file\n"
_EXCLUDED_FILE_CONTENT: str = "# excluded source file\n"

# JSON output keys asserted across multiple tests.
_JSON_KEY_IS_CLEAN: str = "is_clean"
_JSON_KEY_FILES_SCANNED: str = "files_scanned"

# YAML config document keys patched in _write_test_configuration.
_CONFIG_AUDIT_KEY: str = "audit"
_CONFIG_DATABASE_PATH_KEY: str = "database_path"
_CONFIG_SCAN_KEY: str = "scan"
_CONFIG_EXCLUDE_PATHS_KEY: str = "exclude_paths"

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


def _write_test_configuration(
    tmp_path: Path,
    database_path: Path,
    exclude_patterns: list[str] | None = None,
) -> Path:
    """Write a schema-valid .phi-scanner.yml that redirects audit writes to database_path.

    Calls create_default_config to produce a validated base configuration, then
    patches audit.database_path to an isolated test location. If exclude_patterns
    is provided, sets scan.exclude_paths to that list.

    The configuration file is written to tmp_path so it sits outside the scan
    root and is never picked up as a scan target.

    Args:
        tmp_path: pytest tmp_path fixture directory.
        database_path: Path where the audit database should be written.
        exclude_patterns: Optional gitignore-style patterns to set on scan.exclude_paths.

    Returns:
        Path to the written configuration file.
    """
    configuration_path = tmp_path / ".phi-scanner.yml"
    create_default_config(configuration_path)
    configuration_document = yaml.safe_load(
        configuration_path.read_text(encoding=_TEST_FILE_ENCODING)
    )
    # DEFAULT_DATABASE_PATH is typed as str in constants.py; write str here.
    configuration_document[_CONFIG_AUDIT_KEY][_CONFIG_DATABASE_PATH_KEY] = str(database_path)
    if exclude_patterns is not None:
        configuration_document[_CONFIG_SCAN_KEY][_CONFIG_EXCLUDE_PATHS_KEY] = exclude_patterns
    configuration_path.write_text(
        yaml.dump(configuration_document, default_flow_style=False, sort_keys=False),
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
    generate_audit_key(database_path)
    scan_root = _create_scan_root_directory(tmp_path)

    runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    most_recent_scan_record = get_last_scan(database_path)
    assert most_recent_scan_record is not None


def test_scan_directory_with_exclude_does_not_scan_excluded_file(
    tmp_path: Path, runner: CliRunner
) -> None:
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(
        tmp_path, database_path, exclude_patterns=[_EXCLUDED_DIR_PATTERN]
    )
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
    fresh_database_path = tmp_path / "audit.db"
    # Patch the name bound in cli.py's namespace — that is the binding used at
    # call time by the report command (imported via `from phi_scan.constants import`).
    # DEFAULT_DATABASE_PATH is a str constant, so convert Path to str at call site.
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", str(fresh_database_path))

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


# ---------------------------------------------------------------------------
# 2G.14 — End-to-end: scan → detect → cache → re-scan → output → audit
# ---------------------------------------------------------------------------

# File name and PHI content for the planted-PHI scan target.
_PHI_FILE_NAME: str = "patient.py"
# SSN value outside all reserved ranges — triggers the regex layer.
_PLANTED_SSN_LINE: str = 'patient_ssn = "321-54-9870"\n'

# JSON output keys specific to 2G.14 assertions.
_JSON_KEY_FINDINGS: str = "findings"
_JSON_KEY_IS_CLEAN_2G: str = "is_clean"
_JSON_KEY_FILES_WITH_FINDINGS: str = "files_with_findings"

# Minimum number of findings expected when a file with one SSN is scanned.
_MINIMUM_FINDINGS_FOR_PLANTED_SSN: int = 1

# Fragment verified in audit record to confirm findings were written.
_AUDIT_KEY_FINDINGS_COUNT: str = "findings_count"


def _create_phi_scan_root(tmp_path: Path) -> tuple[Path, Path]:
    """Create a scan root with one PHI file and return (scan_root, phi_file_path).

    Keeping the config file in tmp_path (not scan_root) prevents it from being
    picked up as a scan target.

    Args:
        tmp_path: pytest tmp_path fixture directory.

    Returns:
        Tuple of (scan_root Path, planted PHI file Path).
    """
    scan_root = tmp_path / _SCAN_TARGET_DIR_NAME
    scan_root.mkdir()
    phi_file = scan_root / _PHI_FILE_NAME
    phi_file.write_text(_PLANTED_SSN_LINE, encoding=_TEST_FILE_ENCODING)
    return scan_root, phi_file


def test_scan_file_with_phi_exits_with_violation_code(tmp_path: Path, runner: CliRunner) -> None:
    """Scanning a file containing a planted SSN returns EXIT_CODE_VIOLATION."""
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    assert cli_invocation.exit_code == EXIT_CODE_VIOLATION


def test_scan_file_with_phi_reports_not_clean_in_json_output(
    tmp_path: Path, runner: CliRunner
) -> None:
    """JSON output has is_clean=false when a file containing PHI is scanned."""
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    json_output = json.loads(cli_invocation.stdout)
    assert json_output[_JSON_KEY_IS_CLEAN_2G] is False


def test_scan_file_with_phi_reports_findings_in_json_output(
    tmp_path: Path, runner: CliRunner
) -> None:
    """JSON output contains at least one finding when a file containing PHI is scanned."""
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    cli_invocation = runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    json_output = json.loads(cli_invocation.stdout)
    assert json_output[_JSON_KEY_FILES_WITH_FINDINGS] >= _MINIMUM_FINDINGS_FOR_PLANTED_SSN


def test_scan_file_with_phi_writes_audit_record_with_findings(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Scanning a file with PHI writes an audit record with a non-zero findings count."""
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    generate_audit_key(database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    runner.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)],
    )

    audit_record = get_last_scan(database_path)
    assert audit_record is not None
    assert audit_record[_AUDIT_KEY_FINDINGS_COUNT] >= _MINIMUM_FINDINGS_FOR_PLANTED_SSN


def test_rescan_unchanged_phi_file_produces_same_exit_code(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Re-scanning an unchanged PHI file produces EXIT_CODE_VIOLATION on both runs.

    The second run exercises the cache path — the content hash is unchanged so
    findings are served from the scan cache rather than re-detected. The exit
    code must be consistent regardless of whether the result came from cache.
    """
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    scan_args = ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)]
    first_invocation = runner.invoke(app, scan_args)
    second_invocation = runner.invoke(app, scan_args)

    assert first_invocation.exit_code == EXIT_CODE_VIOLATION
    assert second_invocation.exit_code == first_invocation.exit_code


def test_rescan_unchanged_phi_file_produces_consistent_findings_count(
    tmp_path: Path, runner: CliRunner
) -> None:
    """Re-scanning an unchanged PHI file returns the same files_with_findings count.

    Verifies that the cache path returns results consistent with the cold-scan path.
    """
    database_path = tmp_path / "audit.db"
    configuration_path = _write_test_configuration(tmp_path, database_path)
    scan_root, _ = _create_phi_scan_root(tmp_path)

    scan_args = ["scan", str(scan_root), "--output", "json", "--config", str(configuration_path)]
    first_output = json.loads(runner.invoke(app, scan_args).stdout)
    second_output = json.loads(runner.invoke(app, scan_args).stdout)

    first_count = first_output[_JSON_KEY_FILES_WITH_FINDINGS]
    second_count = second_output[_JSON_KEY_FILES_WITH_FINDINGS]
    assert second_count == first_count
