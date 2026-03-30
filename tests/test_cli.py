"""Tests for phi_scan.cli — Typer command smoke tests and behaviour checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phi_scan import __version__
from phi_scan.cli import _GIT_DIR_NOT_FOUND_MESSAGE, _truncate_filename_for_progress, app
from phi_scan.constants import (
    DEFAULT_CONFIG_FILENAME,
    EXIT_CODE_CLEAN,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

# Version output: "phi-scan <version>" — tests verify __version__ appears in output.
_EXPECTED_VERSION_FRAGMENT: str = __version__
_EXIT_CODE_SUCCESS: int = 0
_EXIT_CODE_ERROR: int = 2
_UNSUPPORTED_FORMAT_NAME: str = "pdf"
_INVALID_SEVERITY_VALUE: str = "extreme"
_VALID_PERIOD_30_DAYS: str = "30d"
_INVALID_PERIOD_NO_SUFFIX: str = "30"
_INVALID_PERIOD_NON_NUMERIC: str = "xd"
_JSON_FINDINGS_KEY: str = "findings"
_CSV_HEADER_FRAGMENT: str = "file_path"
_SARIF_VERSION_KEY: str = "version"
_SARIF_EXPECTED_VERSION: str = "2.1.0"
_HOOK_PATH_RELATIVE: str = ".git/hooks/pre-commit"
_FOREIGN_HOOK_CONTENT: str = "#!/bin/sh\necho hello\n"
# Observable hook marker — the string phi-scan writes into every hook it installs.
_EXPECTED_HOOK_MARKER: str = "phi-scan scan"
# Full hook script content — must match what install_hook writes verbatim so
# that uninstall_hook tests can simulate our hook being present.
_EXPECTED_HOOK_SCRIPT: str = (
    "#!/bin/sh\n"
    "# phi-scan pre-commit hook — installed by phi-scan install-hook\n"
    "phi-scan scan --diff HEAD --quiet\n"
    "if [ $? -ne 0 ]; then\n"
    "  echo 'phi-scan: PHI/PII detected — commit blocked'\n"
    "  exit 1\n"
    "fi\n"
)
# Observable fragments of stub command output — stable identifiers from each message.
_EXPECTED_INIT_MESSAGE_FRAGMENT: str = "phi-scan init"
_EXPECTED_SETUP_MESSAGE_FRAGMENT: str = "phi-scan setup"
_EXPECTED_DASHBOARD_MESSAGE_FRAGMENT: str = "phi-scan dashboard"
# Observable messages from report / history commands.
_EXPECTED_NO_LAST_SCAN_MESSAGE: str = "No scan record found. Run `phi-scan scan` first."
_EXPECTED_NO_SCAN_HISTORY_MESSAGE: str = "No scan history found."
_SHORT_FILE_PATH: str = "src/phi_scan/cli.py"
_LONG_FILE_PATH: str = "a/very/deep/nested/path/that/exceeds/the/column/width/limit/some_module.py"
_LONG_FILE_ELLIPSIS_PREFIX: str = "…"
_PROGRESS_FILENAME_MAX_CHARS: int = 38
_WATCH_FINDING_FILE_PATH: Path = Path("f.py")
_WATCH_FINDING_ENTITY_TYPE: str = "ssn"
_WATCH_FINDING_CONFIDENCE: float = 0.9
_WATCH_FINDING_CODE_CONTEXT: str = ""
_WATCH_FINDING_REMEDIATION_HINT: str = ""


def _make_watch_scan_finding(
    file_path: Path,
    *,
    line_number: int,
    value_hash_seed: bytes,
) -> ScanFinding:
    """Build a minimal ScanFinding for watch-mode unit tests.

    Args:
        file_path: Path to the file containing the finding.
        line_number: Line number of the finding within the file.
        value_hash_seed: Raw bytes used to derive the SHA-256 value_hash.

    Returns:
        A ScanFinding populated with stable test defaults.
    """
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=_WATCH_FINDING_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=_WATCH_FINDING_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=hashlib.sha256(value_hash_seed).hexdigest(),
        severity=SeverityLevel.HIGH,
        code_context=_WATCH_FINDING_CODE_CONTEXT,
        remediation_hint=_WATCH_FINDING_REMEDIATION_HINT,
    )


# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------

_runner = CliRunner()


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


def test_version_flag_prints_version() -> None:
    result = _runner.invoke(app, ["--version"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_VERSION_FRAGMENT in result.output


def test_version_short_flag_prints_version() -> None:
    result = _runner.invoke(app, ["-V"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_VERSION_FRAGMENT in result.output


# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------


def test_help_flag_exits_cleanly() -> None:
    result = _runner.invoke(app, ["--help"])

    assert result.exit_code == _EXIT_CODE_SUCCESS


def test_scan_help_exits_cleanly() -> None:
    result = _runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == _EXIT_CODE_SUCCESS


def test_watch_help_exits_cleanly() -> None:
    result = _runner.invoke(app, ["watch", "--help"])

    assert result.exit_code == _EXIT_CODE_SUCCESS


def test_history_help_exits_cleanly() -> None:
    result = _runner.invoke(app, ["history", "--help"])

    assert result.exit_code == _EXIT_CODE_SUCCESS


def test_report_help_exits_cleanly() -> None:
    result = _runner.invoke(app, ["report", "--help"])

    assert result.exit_code == _EXIT_CODE_SUCCESS


# ---------------------------------------------------------------------------
# scan — output formats
# ---------------------------------------------------------------------------


def test_scan_quiet_on_clean_directory_exits_zero(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == EXIT_CODE_CLEAN


def test_scan_quiet_flag_produces_no_table_output(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.output.strip() == ""


def test_scan_quiet_with_json_format_still_emits_json(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--output", "json"])

    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)


def test_scan_json_output_is_valid_json(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", "json"])

    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)


def test_scan_json_output_contains_findings_key(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", "json"])

    parsed = json.loads(result.output)
    assert _JSON_FINDINGS_KEY in parsed


def test_scan_csv_output_contains_header_row(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", "csv"])

    assert _CSV_HEADER_FRAGMENT in result.output


def test_scan_sarif_output_is_valid_json(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", "sarif"])

    parsed = json.loads(result.output)
    assert parsed[_SARIF_VERSION_KEY] == _SARIF_EXPECTED_VERSION


def test_scan_unsupported_output_format_exits_with_error(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", _UNSUPPORTED_FORMAT_NAME])

    assert result.exit_code == _EXIT_CODE_ERROR


def test_scan_unsupported_output_format_prints_error_message(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--output", _UNSUPPORTED_FORMAT_NAME])

    assert _UNSUPPORTED_FORMAT_NAME in result.output


# ---------------------------------------------------------------------------
# scan — severity threshold override
# ---------------------------------------------------------------------------


def test_scan_invalid_severity_threshold_exits_with_error(tmp_path: Path) -> None:
    result = _runner.invoke(
        app, ["scan", str(tmp_path), "--severity-threshold", _INVALID_SEVERITY_VALUE]
    )

    assert result.exit_code == _EXIT_CODE_ERROR


def test_scan_valid_severity_threshold_exits_cleanly(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--severity-threshold", "high"])

    assert result.exit_code == EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def test_report_prints_no_scan_message_when_no_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", str(tmp_path / "audit.db"))

    result = _runner.invoke(app, ["report"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_NO_LAST_SCAN_MESSAGE in result.output


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


def test_history_with_valid_period_exits_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", str(tmp_path / "audit.db"))

    result = _runner.invoke(app, ["history", "--last", _VALID_PERIOD_30_DAYS])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_NO_SCAN_HISTORY_MESSAGE in result.output


def test_history_invalid_period_no_suffix_raises_bad_parameter(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["history", "--last", _INVALID_PERIOD_NO_SUFFIX])

    assert result.exit_code != _EXIT_CODE_SUCCESS


def test_history_invalid_period_non_numeric_raises_bad_parameter(tmp_path: Path) -> None:
    result = _runner.invoke(app, ["history", "--last", _INVALID_PERIOD_NON_NUMERIC])

    assert result.exit_code != _EXIT_CODE_SUCCESS


# ---------------------------------------------------------------------------
# install-hook / uninstall-hook
# ---------------------------------------------------------------------------


def test_install_hook_creates_hook_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["install-hook"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert hook_path.exists()
    assert _EXPECTED_HOOK_MARKER in hook_path.read_text(encoding="utf-8")


def test_install_hook_prints_installed_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["install-hook"])

    assert str(hook_path) in result.output


def test_install_hook_does_not_overwrite_existing_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_FOREIGN_HOOK_CONTENT)
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["install-hook"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert hook_path.read_text() == _FOREIGN_HOOK_CONTENT


def test_uninstall_hook_removes_our_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_EXPECTED_HOOK_SCRIPT, encoding="utf-8")
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["uninstall-hook"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert not hook_path.exists()


def test_uninstall_hook_prints_removed_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_EXPECTED_HOOK_SCRIPT, encoding="utf-8")
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["uninstall-hook"])

    assert str(hook_path) in result.output


def test_uninstall_hook_prints_not_found_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["uninstall-hook"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert str(hook_path) in result.output


def test_uninstall_hook_does_not_remove_foreign_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    (tmp_path / ".git").mkdir()
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(_FOREIGN_HOOK_CONTENT)
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["uninstall-hook"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert hook_path.exists()


def test_install_hook_exits_with_error_when_not_in_git_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["install-hook"])

    assert result.exit_code == _EXIT_CODE_ERROR
    # Click 8.2+ always splits stderr from stdout; result.stderr is populated
    # with the default CliRunner. Asserting here (not result.output) ensures
    # the message is genuinely emitted with err=True — a regression where
    # err=True is removed would cause this assertion to fail.
    assert _GIT_DIR_NOT_FOUND_MESSAGE in result.stderr


def test_uninstall_hook_exits_with_error_when_not_in_git_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    monkeypatch.setattr("phi_scan.cli._GIT_DIR_PATH", tmp_path / ".git")
    monkeypatch.setattr("phi_scan.cli._PRE_COMMIT_HOOK_PATH", str(hook_path))

    result = _runner.invoke(app, ["uninstall-hook"])

    assert result.exit_code == _EXIT_CODE_ERROR
    # Click 8.2+ always splits stderr from stdout; result.stderr is populated
    # with the default CliRunner. Asserting here (not result.output) ensures
    # the message is genuinely emitted with err=True — a regression where
    # err=True is removed would cause this assertion to fail.
    assert _GIT_DIR_NOT_FOUND_MESSAGE in result.stderr


# ---------------------------------------------------------------------------
# config init
# ---------------------------------------------------------------------------


def test_config_init_creates_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = _runner.invoke(app, ["config", "init"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert (tmp_path / DEFAULT_CONFIG_FILENAME).exists()


def test_config_init_prints_created_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = _runner.invoke(app, ["config", "init"])

    assert DEFAULT_CONFIG_FILENAME in result.output


def test_config_init_does_not_overwrite_existing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / DEFAULT_CONFIG_FILENAME
    original_content = "original: true\n"
    config_path.write_text(original_content)

    _runner.invoke(app, ["config", "init"])

    assert config_path.read_text() == original_content


# ---------------------------------------------------------------------------
# Stub commands — verify they exit cleanly with expected messages
# ---------------------------------------------------------------------------


def test_init_command_prints_stub_message() -> None:
    result = _runner.invoke(app, ["init"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_INIT_MESSAGE_FRAGMENT in result.output


def test_setup_command_prints_stub_message() -> None:
    result = _runner.invoke(app, ["setup"])

    assert result.exit_code == _EXIT_CODE_SUCCESS
    assert _EXPECTED_SETUP_MESSAGE_FRAGMENT in result.output


def test_dashboard_command_exits_cleanly_on_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("phi_scan.cli.DEFAULT_DATABASE_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setattr("phi_scan.cli.query_recent_scans", lambda *_: [])
    monkeypatch.setattr("phi_scan.cli.get_last_scan", lambda *_: None)

    def _raise_keyboard_interrupt(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("phi_scan.cli.time.sleep", _raise_keyboard_interrupt)

    result = _runner.invoke(app, ["dashboard"])

    assert result.exit_code == EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# _truncate_filename_for_progress
# ---------------------------------------------------------------------------


def test_truncate_filename_for_progress_returns_path_unchanged_when_short_enough() -> None:
    result = _truncate_filename_for_progress(Path(_SHORT_FILE_PATH))

    assert result == _SHORT_FILE_PATH


def test_truncate_filename_for_progress_truncates_long_path_with_ellipsis() -> None:
    result = _truncate_filename_for_progress(Path(_LONG_FILE_PATH))

    assert result.startswith(_LONG_FILE_ELLIPSIS_PREFIX)
    assert len(result) <= _PROGRESS_FILENAME_MAX_CHARS + len(_LONG_FILE_ELLIPSIS_PREFIX)


def test_truncate_filename_for_progress_truncated_result_ends_with_original_suffix() -> None:
    result = _truncate_filename_for_progress(Path(_LONG_FILE_PATH))

    assert result.endswith(_LONG_FILE_PATH[-_PROGRESS_FILENAME_MAX_CHARS:])


# ---------------------------------------------------------------------------
# _aggregate_category_totals (1C.5)
# ---------------------------------------------------------------------------

_AGGREGATE_EMPTY_SCANS: list[dict[str, object]] = []
_AGGREGATE_CATEGORY_SSN: str = "SSN"
_AGGREGATE_CATEGORY_EMAIL: str = "EMAIL"
_AGGREGATE_SINGLE_SCAN_ROW: list[dict[str, object]] = [
    {
        "findings_json": (
            '[{"hipaa_category": "SSN"}, {"hipaa_category": "SSN"}, {"hipaa_category": "EMAIL"}]'
        )
    }
]
_AGGREGATE_TWO_SCAN_ROWS: list[dict[str, object]] = [
    {"findings_json": '[{"hipaa_category": "SSN"}]'},
    {"findings_json": '[{"hipaa_category": "SSN"}, {"hipaa_category": "EMAIL"}]'},
]


def test_aggregate_category_totals_empty_scans_returns_empty_dict() -> None:
    from phi_scan.cli import _aggregate_category_totals

    totals = _aggregate_category_totals(_AGGREGATE_EMPTY_SCANS)

    assert totals == {}


def test_aggregate_category_totals_single_scan_sums_correctly() -> None:
    from phi_scan.cli import _aggregate_category_totals

    totals = _aggregate_category_totals(_AGGREGATE_SINGLE_SCAN_ROW)

    assert totals[_AGGREGATE_CATEGORY_SSN] == 2
    assert totals[_AGGREGATE_CATEGORY_EMAIL] == 1


def test_aggregate_category_totals_multiple_scans_combines_counts() -> None:
    from phi_scan.cli import _aggregate_category_totals

    totals = _aggregate_category_totals(_AGGREGATE_TWO_SCAN_ROWS)

    assert totals[_AGGREGATE_CATEGORY_SSN] == 2
    assert totals[_AGGREGATE_CATEGORY_EMAIL] == 1


def test_aggregate_category_totals_missing_findings_json_skips_row() -> None:
    from phi_scan.cli import _aggregate_category_totals

    scans: list[dict[str, object]] = [{"timestamp": "2026-03-27"}]
    totals = _aggregate_category_totals(scans)

    assert totals == {}


# ---------------------------------------------------------------------------
# _build_watch_result (1C.6b–1C.6c)
# ---------------------------------------------------------------------------


def test_build_watch_result_returns_clean_text_for_no_findings() -> None:
    from phi_scan.cli import _build_watch_result
    from phi_scan.output import WATCH_RESULT_CLEAN_TEXT

    scan_outcome = _build_watch_result([])

    assert scan_outcome.result_text == WATCH_RESULT_CLEAN_TEXT
    assert scan_outcome.is_clean is True


def test_build_watch_result_returns_violation_text_for_findings(
    tmp_path: Path,
) -> None:
    from phi_scan.cli import _build_watch_result

    finding = _make_watch_scan_finding(
        _WATCH_FINDING_FILE_PATH, line_number=1, value_hash_seed=b"x"
    )

    scan_outcome = _build_watch_result([finding])

    assert "1" in scan_outcome.result_text
    assert scan_outcome.is_clean is False


def test_build_watch_result_violation_count_matches_findings_length(
    tmp_path: Path,
) -> None:
    from phi_scan.cli import _build_watch_result

    finding_one = _make_watch_scan_finding(
        _WATCH_FINDING_FILE_PATH, line_number=1, value_hash_seed=b"x"
    )
    finding_two = _make_watch_scan_finding(
        _WATCH_FINDING_FILE_PATH, line_number=2, value_hash_seed=b"y"
    )

    scan_outcome = _build_watch_result([finding_one, finding_two])

    assert "2" in scan_outcome.result_text
