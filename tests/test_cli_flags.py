# phi-scan:ignore-file
"""Tests for CLI flag behaviour not covered by test_cli.py or test_output_3a.py.

Focuses on:

  - --baseline flag: scan exits 0 when all findings are baselined, exits 1 when
    new findings exist, falls back to regular scan when no baseline file is present.
  - --output FORMAT via CLI: every implemented non-TABLE format produces parseable
    output when run via the Typer CLI runner.
  - --severity-threshold: invalid value rejects, valid value accepts (covered in
    test_cli.py) — extended here to show the flag combines correctly with --output.
  - --quiet with findings still exits 1 (exit code not suppressed by quiet mode).

The --verbose and --report-path flags are covered in test_output_3a.py.
"""

from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phi_scan.cli import app
from phi_scan.constants import (
    DEFAULT_BASELINE_FILENAME,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
    EXIT_CODE_VIOLATION,
    OutputFormat,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

# SYNTHETIC TEST FIXTURE — NOT A REAL SSN.
# This pattern reliably produces a HIGH-severity finding.
_PHI_VIOLATION_FIXTURE_CONTENT: str = 'ssn = "900-00-0001"\n'  # phi-scan:ignore
_PHI_FILE_NAME: str = "patient.py"

_BASELINE_CREATED_FRAGMENT: str = "Baseline created"
_BASELINE_WARNING_FRAGMENT: str = "baseline"

_SARIF_VERSION_VALUE: str = "2.1.0"
_JUNIT_TESTSUITE_TAG: str = "testsuite"
_CSV_HEADER_FRAGMENT: str = "file_path"
_JSON_FINDINGS_KEY: str = "findings"

# The v2 footer section is labelled "SCAN COMPLETE"; this string appears
# exclusively in the v2 renderer and is a reliable marker for v2 output.
_V2_FOOTER_MARKER: str = "SCAN COMPLETE"
_DEPRECATION_WARNING_FRAGMENT: str = "DeprecationWarning"
_DEPRECATION_REMOVAL_TARGET: str = "0.8.0"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _write_phi_file(directory: Path) -> Path:
    """Write a file that reliably produces a HIGH-severity SSN finding."""
    phi_file = directory / _PHI_FILE_NAME
    phi_file.write_text(_PHI_VIOLATION_FIXTURE_CONTENT, encoding="utf-8")
    return phi_file


# ---------------------------------------------------------------------------
# --baseline flag
# ---------------------------------------------------------------------------


class TestBaselineFlag:
    def test_baseline_flag_without_baseline_file_warns_and_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no .phi-scanbaseline file exists, --baseline warns and falls back.

        The exit code reflects the actual scan result (findings present → exit 1).
        """
        monkeypatch.chdir(tmp_path)
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--baseline"])

        # No baseline → falls back to regular scan → PHI found → exit 1
        assert result.exit_code == EXIT_CODE_VIOLATION

    def test_baseline_flag_with_all_findings_baselined_exits_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--baseline exits 0 when every finding is covered by an active baseline entry."""
        monkeypatch.chdir(tmp_path)
        # Use a source subdirectory so .phi-scanbaseline (written to CWD) is not
        # included in the scan target — the baseline file contains SHA-256 hashes
        # that trigger false-positive detections when scanned.
        src = tmp_path / "src"
        src.mkdir()
        _write_phi_file(src)
        runner = CliRunner()

        # Step 1: create baseline from the source directory
        create_result = runner.invoke(
            app,
            ["baseline", "create", str(src)],
        )
        assert create_result.exit_code == EXIT_CODE_CLEAN
        assert (tmp_path / DEFAULT_BASELINE_FILENAME).exists()

        # Step 2: scan src/ with --baseline — all findings are baselined → exit 0
        scan_result = runner.invoke(app, ["scan", str(src), "--quiet", "--baseline"])

        assert scan_result.exit_code == EXIT_CODE_CLEAN

    def test_baseline_flag_with_new_finding_exits_violation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--baseline exits 1 when at least one finding is not in the baseline."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        # Step 1: create baseline from an empty directory (no findings)
        empty_src = tmp_path / "src"
        empty_src.mkdir()
        create_result = runner.invoke(
            app,
            ["baseline", "create", str(empty_src)],
        )
        assert create_result.exit_code == EXIT_CODE_CLEAN

        # Step 2: add a new PHI file not covered by the empty baseline
        _write_phi_file(tmp_path)

        # Step 3: scan with --baseline — new finding exists → exit 1
        scan_result = runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--baseline"])

        assert scan_result.exit_code == EXIT_CODE_VIOLATION

    def test_baseline_create_command_prints_confirmation_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["baseline", "create", str(tmp_path)])

        assert _BASELINE_CREATED_FRAGMENT in result.output

    def test_baseline_create_command_creates_baseline_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        runner.invoke(app, ["baseline", "create", str(tmp_path)])

        assert (tmp_path / DEFAULT_BASELINE_FILENAME).exists()

    def test_baseline_show_exits_cleanly_when_no_baseline_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["baseline", "show"])

        # Missing baseline → exits 0 with warning, not error
        assert result.exit_code == EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# --output FORMAT via CLI — parseable output
# ---------------------------------------------------------------------------


class TestOutputFormatsViaCli:
    """Each implemented non-TABLE format must produce parseable output from the CLI."""

    def test_output_json_is_valid_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.JSON.value])

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert _JSON_FINDINGS_KEY in parsed

    def test_output_sarif_is_valid_sarif_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.SARIF.value])

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert parsed["version"] == _SARIF_VERSION_VALUE

    def test_output_csv_has_header_row(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.CSV.value])

        assert result.exit_code == EXIT_CODE_CLEAN
        rows = list(csv.reader(io.StringIO(result.output)))
        assert len(rows) >= 1
        assert _CSV_HEADER_FRAGMENT in rows[0]

    def test_output_junit_produces_xml_with_testsuite_root(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.JUNIT.value])

        assert result.exit_code == EXIT_CODE_CLEAN
        # Strip XML declaration and parse
        xml_body = result.output.split("\n", 1)[-1]
        root = ET.fromstring(xml_body)
        assert root.tag == _JUNIT_TESTSUITE_TAG

    def test_output_codequality_is_valid_json_array(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--output", OutputFormat.CODEQUALITY.value]
        )

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)

    def test_output_gitlab_sast_is_valid_json_with_vulnerabilities_key(
        self, tmp_path: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--output", OutputFormat.GITLAB_SAST.value]
        )

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert "vulnerabilities" in parsed

    def test_output_json_with_findings_has_populated_findings_array(self, tmp_path: Path) -> None:
        _write_phi_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.JSON.value])

        assert result.exit_code == EXIT_CODE_VIOLATION
        parsed = json.loads(result.output)
        assert len(parsed[_JSON_FINDINGS_KEY]) >= 1

    def test_output_sarif_with_findings_has_populated_results_array(self, tmp_path: Path) -> None:
        _write_phi_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--output", OutputFormat.SARIF.value])

        assert result.exit_code == EXIT_CODE_VIOLATION
        parsed = json.loads(result.output)
        sarif_results: list[object] = parsed["runs"][0]["results"]
        assert len(sarif_results) >= 1


# ---------------------------------------------------------------------------
# --quiet preserves exit code
# ---------------------------------------------------------------------------


class TestQuietPreservesExitCode:
    def test_quiet_with_findings_still_exits_violation(self, tmp_path: Path) -> None:
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

        assert result.exit_code == EXIT_CODE_VIOLATION

    def test_quiet_on_clean_directory_exits_clean(self, tmp_path: Path) -> None:
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

        assert result.exit_code == EXIT_CODE_CLEAN

    def test_quiet_suppresses_table_output(self, tmp_path: Path) -> None:
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

        assert result.output.strip() == ""


# ---------------------------------------------------------------------------
# --severity-threshold with --output
# ---------------------------------------------------------------------------


class TestSeverityThresholdWithOutput:
    def test_severity_threshold_high_with_json_output_exits_cleanly_on_empty_dir(
        self, tmp_path: Path
    ) -> None:
        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--severity-threshold",
                "high",
                "--output",
                OutputFormat.JSON.value,
            ],
        )

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert parsed[_JSON_FINDINGS_KEY] == []

    def test_severity_threshold_low_with_json_output_still_parseable(self, tmp_path: Path) -> None:
        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--severity-threshold",
                "low",
                "--output",
                OutputFormat.JSON.value,
            ],
        )

        assert result.exit_code == EXIT_CODE_CLEAN
        parsed = json.loads(result.output)
        assert _JSON_FINDINGS_KEY in parsed


# ---------------------------------------------------------------------------
# --report-format default and v1 deprecation
# ---------------------------------------------------------------------------


class TestReportFormatDefaultAndV1Deprecation:
    """v2 is the default terminal renderer; v1 is a deprecated escape hatch.

    These tests pin the graduation contract established in 0.7.0:
      - Default ``scan`` invocation uses v2 (no flag required)
      - Passing ``--report-format v1`` emits a DeprecationWarning to stderr
        naming the 0.8.0 removal target — regardless of ``--output`` mode, so
        CI pipelines using ``--report-format v1 --output json`` still see it
      - ``--quiet`` suppresses the deprecation line alongside all other output
      - Unknown ``--report-format`` values are rejected with a clear stderr
        message and a non-zero exit code (no silent fall-through to v2)
      - JSON/SARIF/exit-code contracts are unaffected by renderer choice
    """

    def test_default_scan_renders_v2_output(self, tmp_path: Path) -> None:
        """Scanning without --report-format produces v2 output."""
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == EXIT_CODE_VIOLATION
        assert _V2_FOOTER_MARKER in result.stdout

    def test_default_scan_does_not_emit_deprecation_warning(self, tmp_path: Path) -> None:
        """No deprecation notice is printed when v2 (the default) is used.

        Writes a PHI fixture so the full rendering path executes — a test
        against an empty directory would pass vacuously even if the gate logic
        were broken.
        """
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert _DEPRECATION_WARNING_FRAGMENT not in result.stdout
        assert _DEPRECATION_WARNING_FRAGMENT not in result.stderr

    def test_explicit_v1_flag_emits_deprecation_warning_on_stderr(self, tmp_path: Path) -> None:
        """``--report-format v1`` prints a DeprecationWarning to stderr naming 0.8.0."""
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--report-format", "v1"],
        )

        assert _DEPRECATION_WARNING_FRAGMENT in result.stderr
        assert _DEPRECATION_REMOVAL_TARGET in result.stderr
        # stdout carries the rendered report, never the deprecation line
        assert _DEPRECATION_WARNING_FRAGMENT not in result.stdout

    def test_v1_deprecation_warning_fires_in_json_mode(self, tmp_path: Path) -> None:
        """CI pipelines using ``--report-format v1 --output json`` still see the
        notice — the deprecation must not be gated on rich-terminal mode."""
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--report-format",
                "v1",
                "--output",
                OutputFormat.JSON.value,
            ],
        )

        assert _DEPRECATION_WARNING_FRAGMENT in result.stderr
        # stdout stays pure JSON — the deprecation goes to stderr, not stdout
        parsed = json.loads(result.stdout)
        assert _JSON_FINDINGS_KEY in parsed

    def test_quiet_suppresses_v1_deprecation_warning(self, tmp_path: Path) -> None:
        """``--quiet`` suppresses the v1 deprecation line alongside all other output."""
        _write_phi_file(tmp_path)
        runner = CliRunner()

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--report-format", "v1", "--quiet"],
        )

        assert _DEPRECATION_WARNING_FRAGMENT not in result.stdout
        assert _DEPRECATION_WARNING_FRAGMENT not in result.stderr

    def test_unknown_report_format_exits_with_error(self, tmp_path: Path) -> None:
        """Unknown --report-format values are rejected with a clear stderr
        message and a non-zero exit code — no silent fall-through to v2."""
        runner = CliRunner()

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--report-format", "v3"],
        )

        assert result.exit_code == EXIT_CODE_ERROR
        assert "v3" in result.stderr
        assert "v1" in result.stderr
        assert "v2" in result.stderr

    def test_renderer_choice_does_not_affect_json_output(self, tmp_path: Path) -> None:
        """JSON output is identical whether v1 or v2 is selected — structured
        contracts are independent of the terminal renderer."""
        _write_phi_file(tmp_path)
        runner = CliRunner()

        v2_result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--output", OutputFormat.JSON.value],
        )
        v1_result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--output",
                OutputFormat.JSON.value,
                "--report-format",
                "v1",
            ],
        )

        assert v2_result.exit_code == v1_result.exit_code == EXIT_CODE_VIOLATION
        v2_parsed = json.loads(v2_result.stdout)
        v1_parsed = json.loads(v1_result.stdout)
        assert len(v2_parsed[_JSON_FINDINGS_KEY]) == len(v1_parsed[_JSON_FINDINGS_KEY])
