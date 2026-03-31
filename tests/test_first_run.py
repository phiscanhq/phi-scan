# phi-scan:ignore-file
"""Tests for first-run experience — configuration defaults and helpful error messages.

Verifies:
  - Running 'phi-scan scan' with no .phi-scanner.yml in CWD does not crash;
    it uses built-in defaults and exits with the expected exit code.
  - Running 'phi-scan config init' in a directory with no config file creates
    a valid .phi-scanner.yml that the config loader can parse without error.
  - Re-running 'phi-scan config init' when a config already exists does not
    overwrite the existing file.
  - An invalid config file causes load_config() to raise ConfigurationError with
    a message that identifies the bad field; the CLI falls back to built-in defaults
    and continues scanning rather than exiting with code 2.
  - An unrecognised --output format produces an exit code 2 message that names
    the bad value.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from phi_scan.cli import app
from phi_scan.config import load_config
from phi_scan.constants import (
    DEFAULT_CONFIG_FILENAME,
    EXIT_CODE_CLEAN,
    EXIT_CODE_ERROR,
)
from phi_scan.exceptions import ConfigurationError

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

_CONFIG_INIT_CREATED_FRAGMENT: str = DEFAULT_CONFIG_FILENAME
_INVALID_SEVERITY_VALUE: str = "critical"
_INVALID_OUTPUT_FORMAT_VALUE: str = "pdf"
_ORIGINAL_CONFIG_CONTENT: str = "version: 1\n"

# Follow-symlinks violation causes a clear error at config load time.
_CONFIG_WITH_SYMLINKS_ENABLED: str = "version: 1\nscan:\n  follow_symlinks: true\n"

# Invalid severity_threshold value that must be caught at config load time.
_CONFIG_WITH_INVALID_SEVERITY: str = "version: 1\nscan:\n  severity_threshold: critical\n"


# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------

_runner = CliRunner()


# ---------------------------------------------------------------------------
# No config file → uses defaults, does not crash
# ---------------------------------------------------------------------------


class TestNoConfigFileUsesDefaults:
    def test_scan_without_config_file_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Running scan with no .phi-scanner.yml must use defaults and exit cleanly."""
        monkeypatch.chdir(tmp_path)

        result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

        assert result.exit_code == EXIT_CODE_CLEAN

    def test_no_config_file_does_not_print_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing config must not produce a Python traceback in output."""
        monkeypatch.chdir(tmp_path)

        result = _runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

        assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# config init → creates loadable config
# ---------------------------------------------------------------------------


class TestConfigInit:
    def test_config_init_creates_config_file_in_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)

        _runner.invoke(app, ["config", "init"])

        assert (tmp_path / DEFAULT_CONFIG_FILENAME).exists()

    def test_config_init_config_file_is_parseable_by_load_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The generated config must load without ConfigurationError."""
        monkeypatch.chdir(tmp_path)
        _runner.invoke(app, ["config", "init"])
        config_path = tmp_path / DEFAULT_CONFIG_FILENAME

        # Must not raise ConfigurationError
        scan_config = load_config(config_path)

        assert scan_config is not None

    def test_config_init_does_not_overwrite_existing_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / DEFAULT_CONFIG_FILENAME
        config_path.write_text(_ORIGINAL_CONFIG_CONTENT, encoding="utf-8")

        _runner.invoke(app, ["config", "init"])

        assert config_path.read_text(encoding="utf-8") == _ORIGINAL_CONFIG_CONTENT

    def test_config_init_prints_config_filename_in_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)

        result = _runner.invoke(app, ["config", "init"])

        assert _CONFIG_INIT_CREATED_FRAGMENT in result.output

    def test_scan_after_config_init_uses_generated_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scan run after config init must succeed using the generated config."""
        monkeypatch.chdir(tmp_path)
        _runner.invoke(app, ["config", "init"])
        # Scan a clean source subdirectory — config init creates .phi-scanner.yml in
        # CWD which itself may trigger false-positive detections when scanned.
        src = tmp_path / "src"
        src.mkdir()

        result = _runner.invoke(app, ["scan", str(src), "--quiet"])

        assert result.exit_code == EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# Invalid config — load_config raises, CLI falls back to defaults
# ---------------------------------------------------------------------------


class TestInvalidConfigErrorMessages:
    """Invalid config fields are caught by load_config, not by the CLI exit code.

    The CLI catches ConfigurationError, logs a WARNING, and falls back to built-in
    defaults rather than exiting with code 2. Tests here verify two things:
      1. load_config() raises ConfigurationError with a descriptive message.
      2. The CLI scan continues with defaults and exits 0 on a clean source dir.
    """

    def test_follow_symlinks_true_raises_configuration_error(self, tmp_path: Path) -> None:
        """load_config raises ConfigurationError when follow_symlinks is true."""
        config_path = tmp_path / DEFAULT_CONFIG_FILENAME
        config_path.write_text(_CONFIG_WITH_SYMLINKS_ENABLED, encoding="utf-8")

        with pytest.raises(ConfigurationError) as exc_info:
            load_config(config_path)

        assert "symlink" in str(exc_info.value).lower()

    def test_follow_symlinks_true_cli_falls_back_to_defaults_and_exits_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI falls back to defaults on follow_symlinks error; exits 0 on clean dir."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / DEFAULT_CONFIG_FILENAME).write_text(
            _CONFIG_WITH_SYMLINKS_ENABLED, encoding="utf-8"
        )
        src = tmp_path / "src"
        src.mkdir()

        result = _runner.invoke(app, ["scan", str(src), "--quiet"])

        assert result.exit_code == EXIT_CODE_CLEAN

    def test_invalid_severity_threshold_raises_configuration_error(self, tmp_path: Path) -> None:
        """load_config raises ConfigurationError for invalid severity_threshold."""
        config_path = tmp_path / DEFAULT_CONFIG_FILENAME
        config_path.write_text(_CONFIG_WITH_INVALID_SEVERITY, encoding="utf-8")

        with pytest.raises(ConfigurationError) as exc_info:
            load_config(config_path)

        assert _INVALID_SEVERITY_VALUE in str(exc_info.value)

    def test_invalid_severity_threshold_cli_falls_back_to_defaults_and_exits_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI falls back to defaults on invalid severity_threshold; exits 0 on clean dir."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / DEFAULT_CONFIG_FILENAME).write_text(
            _CONFIG_WITH_INVALID_SEVERITY, encoding="utf-8"
        )
        src = tmp_path / "src"
        src.mkdir()

        result = _runner.invoke(app, ["scan", str(src), "--quiet"])

        assert result.exit_code == EXIT_CODE_CLEAN

    def test_unrecognised_output_format_cli_flag_exits_with_error_code(
        self, tmp_path: Path
    ) -> None:
        result = _runner.invoke(
            app, ["scan", str(tmp_path), "--output", _INVALID_OUTPUT_FORMAT_VALUE]
        )

        assert result.exit_code == EXIT_CODE_ERROR

    def test_unrecognised_output_format_names_bad_value_in_output(self, tmp_path: Path) -> None:
        result = _runner.invoke(
            app, ["scan", str(tmp_path), "--output", _INVALID_OUTPUT_FORMAT_VALUE]
        )

        assert _INVALID_OUTPUT_FORMAT_VALUE in result.output
