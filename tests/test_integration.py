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

_RUNNER: CliRunner = CliRunner()

# Config YAML template — version key required; audit.database_path redirected.
_CONFIG_YAML_TEMPLATE: str = "version: 1\naudit:\n  database_path: {db_path}\n"

# Directory and file names used to build the two-file exclude fixture.
_SRC_DIR_NAME: str = "src"
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
# Helpers
# ---------------------------------------------------------------------------


def _make_config(tmp_path: Path) -> tuple[Path, Path]:
    """Write a versioned .phi-scanner.yml that redirects audit writes to tmp_path.

    The config file is written outside the scan root so it is never picked
    up as a scan target.

    Args:
        tmp_path: pytest tmp_path fixture directory.

    Returns:
        Tuple of (config_path, db_path).
    """
    db_path = tmp_path / "audit.db"
    config_path = tmp_path / ".phi-scanner.yml"
    config_path.write_text(
        _CONFIG_YAML_TEMPLATE.format(db_path=str(db_path)),
        encoding="utf-8",
    )
    return config_path, db_path


def _make_scan_root(tmp_path: Path) -> Path:
    """Create an empty subdirectory to use as the scan root.

    Placing scan targets in a subdirectory keeps the config file (written to
    tmp_path) outside the scan root, preventing it from being picked up as a
    scan target.

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


def test_scan_empty_directory_exits_clean(tmp_path: Path) -> None:
    config_path, _ = _make_config(tmp_path)
    scan_root = _make_scan_root(tmp_path)

    result = _RUNNER.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(config_path)],
    )

    assert result.exit_code == EXIT_CODE_CLEAN


def test_scan_empty_directory_writes_audit_record(tmp_path: Path) -> None:
    config_path, db_path = _make_config(tmp_path)
    scan_root = _make_scan_root(tmp_path)

    _RUNNER.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(config_path)],
    )

    create_audit_schema(db_path)
    last_scan = get_last_scan(db_path)
    assert last_scan is not None


def test_scan_directory_with_exclude_does_not_scan_excluded_file(tmp_path: Path) -> None:
    config_path, _ = _make_config(tmp_path)
    scan_root = _make_scan_root(tmp_path)
    src_dir = scan_root / _SRC_DIR_NAME
    src_dir.mkdir()
    (src_dir / _SOURCE_FILE_NAME).write_text(_SOURCE_FILE_CONTENT, encoding="utf-8")
    excluded_dir = scan_root / _EXCLUDED_DIR_NAME
    excluded_dir.mkdir()
    (excluded_dir / _EXCLUDED_FILE_NAME).write_text(_EXCLUDED_FILE_CONTENT, encoding="utf-8")

    result = _RUNNER.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(config_path)],
    )

    parsed = json.loads(result.stdout)
    assert parsed[_JSON_KEY_FILES_SCANNED] == _EXPECTED_FILES_SCANNED_WITH_EXCLUDE


def test_scan_directory_produces_clean_result_json(tmp_path: Path) -> None:
    config_path, _ = _make_config(tmp_path)
    scan_root = _make_scan_root(tmp_path)

    result = _RUNNER.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(config_path)],
    )

    parsed = json.loads(result.stdout)
    assert parsed[_JSON_KEY_IS_CLEAN] is True


def test_scan_report_command_returns_no_record_when_no_scan_performed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh_db_path = str(tmp_path / "audit.db")
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", fresh_db_path)

    result = _RUNNER.invoke(app, ["report"])

    assert _NO_SCAN_RECORD_MESSAGE_FRAGMENT in result.output


def test_full_pipeline_scan_then_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shared_db_path = str(tmp_path / "audit.db")
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", shared_db_path)
    config_path, _ = _make_config(tmp_path)
    # Override db path in config to match the monkeypatched report path.
    config_path.write_text(
        _CONFIG_YAML_TEMPLATE.format(db_path=shared_db_path),
        encoding="utf-8",
    )
    scan_root = _make_scan_root(tmp_path)

    scan_result = _RUNNER.invoke(
        app,
        ["scan", str(scan_root), "--output", "json", "--config", str(config_path)],
    )
    report_result = _RUNNER.invoke(app, ["report"])

    assert scan_result.exit_code == EXIT_CODE_CLEAN
    assert report_result.exit_code == EXIT_CODE_CLEAN
