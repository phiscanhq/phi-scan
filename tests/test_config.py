"""Tests for phi_scan.config — YAML config loading and validation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from phi_scan.config import create_default_config, load_config
from phi_scan.constants import (
    AUDIT_RETENTION_DAYS,
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_DATABASE_PATH,
    MAX_FILE_SIZE_MB,
    OutputFormat,
    SeverityLevel,
)
from phi_scan.exceptions import ConfigurationError
from phi_scan.models import ScanConfig

_SUPPORTED_VERSION: int = 1
_CUSTOM_MAX_FILE_SIZE_MB: int = 25
_TEST_FILE_ENCODING: str = "utf-8"


def _write_config(tmp_path: Path, config_dict: dict[str, object]) -> Path:
    """Write a minimal valid config dict as YAML and return the file path."""
    config_file = tmp_path / ".phi-scanner.yml"
    config_file.write_text(
        yaml.dump(config_dict, default_flow_style=False, sort_keys=False),
        encoding=_TEST_FILE_ENCODING,
    )
    return config_file


def _build_minimal_config() -> dict[str, object]:
    """Return the smallest valid config that passes all validation."""
    return {"version": _SUPPORTED_VERSION}


# ---------------------------------------------------------------------------
# load_config — happy path
# ---------------------------------------------------------------------------


def test_load_config_returns_scan_config_for_valid_yaml(tmp_path: Path) -> None:
    config_file = _write_config(tmp_path, _build_minimal_config())

    scan_config = load_config(config_file)

    assert isinstance(scan_config, ScanConfig)


def test_load_config_uses_scan_defaults_when_scan_section_is_absent(
    tmp_path: Path,
) -> None:
    config_file = _write_config(tmp_path, _build_minimal_config())

    scan_config = load_config(config_file)

    assert scan_config.confidence_threshold == DEFAULT_CONFIDENCE_THRESHOLD
    assert scan_config.severity_threshold == SeverityLevel.LOW
    assert scan_config.max_file_size_mb == MAX_FILE_SIZE_MB
    assert scan_config.should_follow_symlinks is False
    assert scan_config.include_extensions is None
    assert scan_config.exclude_paths == []
    assert scan_config.output_format is OutputFormat.TABLE
    assert scan_config.database_path == Path(DEFAULT_DATABASE_PATH).expanduser()


def test_load_config_maps_confidence_threshold_from_yaml(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": 0.8}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.confidence_threshold == 0.8


def test_load_config_maps_severity_threshold_low_to_severity_level(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"severity_threshold": "low"}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.severity_threshold is SeverityLevel.LOW


def test_load_config_maps_severity_threshold_high_to_severity_level(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"severity_threshold": "high"}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.severity_threshold is SeverityLevel.HIGH


def test_load_config_maps_max_file_size_mb_from_yaml(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"max_file_size_mb": _CUSTOM_MAX_FILE_SIZE_MB}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.max_file_size_mb == _CUSTOM_MAX_FILE_SIZE_MB


def test_load_config_maps_exclude_paths_from_yaml(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"exclude_paths": [".git/", "node_modules/"]}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.exclude_paths == [".git/", "node_modules/"]


def test_load_config_maps_include_extensions_from_yaml(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"include_extensions": [".py", ".ts"]}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.include_extensions == [".py", ".ts"]


def test_load_config_maps_include_extensions_null_to_none(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"include_extensions": None}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.include_extensions is None


def test_load_config_should_follow_symlinks_is_always_false(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["scan"] = {"follow_symlinks": False}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.should_follow_symlinks is False


# ---------------------------------------------------------------------------
# load_config — output format validation
# ---------------------------------------------------------------------------


def test_load_config_maps_gitlab_sast_format_to_output_format_member(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["output"] = {"format": "gitlab-sast"}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert scan_config.output_format is OutputFormat.GITLAB_SAST


def test_load_config_defaults_output_format_to_table(tmp_path: Path) -> None:
    config_file = _write_config(tmp_path, _build_minimal_config())

    scan_config = load_config(config_file)

    assert scan_config.output_format is OutputFormat.TABLE


def test_load_config_raises_configuration_error_for_invalid_output_format(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["output"] = {"format": "not-a-format"}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


# ---------------------------------------------------------------------------
# load_config — error conditions
# ---------------------------------------------------------------------------


def test_load_config_raises_configuration_error_for_missing_file(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "nonexistent.yml")


def test_load_config_raises_configuration_error_for_invalid_yaml(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / ".phi-scanner.yml"
    config_file.write_text("key: [unclosed", encoding=_TEST_FILE_ENCODING)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_when_yaml_is_not_a_mapping(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / ".phi-scanner.yml"
    config_file.write_text("- item1\n- item2\n", encoding=_TEST_FILE_ENCODING)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_missing_version(
    tmp_path: Path,
) -> None:
    config_file = _write_config(tmp_path, {"scan": {}})

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_wrong_version(
    tmp_path: Path,
) -> None:
    config_file = _write_config(tmp_path, {"version": 99})

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_when_follow_symlinks_is_true(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"follow_symlinks": True}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_invalid_severity_threshold(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"severity_threshold": "extreme"}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_non_string_database_path(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["audit"] = {"database_path": 12345}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_null_confidence_threshold(
    tmp_path: Path,
) -> None:
    # YAML null (None in Python) triggers TypeError in float() — distinct user mistake
    # from passing a non-numeric string like "abc".
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": None}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_confidence_threshold_above_maximum(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": 1.1}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_confidence_threshold_below_minimum(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": -0.1}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_accepts_confidence_threshold_at_minimum_boundary(
    tmp_path: Path,
) -> None:
    # Arrange
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": CONFIDENCE_SCORE_MINIMUM}

    # Act
    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    # Assert
    assert scan_config.confidence_threshold == CONFIDENCE_SCORE_MINIMUM


def test_load_config_accepts_confidence_threshold_at_maximum_boundary(
    tmp_path: Path,
) -> None:
    # Arrange
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": CONFIDENCE_SCORE_MAXIMUM}

    # Act
    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    # Assert
    assert scan_config.confidence_threshold == CONFIDENCE_SCORE_MAXIMUM


def test_load_config_expands_tilde_in_database_path(tmp_path: Path) -> None:
    config = _build_minimal_config()
    config["audit"] = {"database_path": "~/.phi-scanner/audit.db"}

    config_file = _write_config(tmp_path, config)
    scan_config = load_config(config_file)

    assert not scan_config.database_path.parts[0].startswith("~")


# ---------------------------------------------------------------------------
# create_default_config
# ---------------------------------------------------------------------------


def test_create_default_config_writes_file_at_output_path(tmp_path: Path) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)

    assert output_path.exists()


def test_create_default_config_output_is_valid_yaml(tmp_path: Path) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)

    config_document = yaml.safe_load(output_path.read_text(encoding=_TEST_FILE_ENCODING))
    assert isinstance(config_document, dict)


def test_create_default_config_output_has_supported_version(tmp_path: Path) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)

    config_document = yaml.safe_load(output_path.read_text(encoding=_TEST_FILE_ENCODING))
    assert config_document["version"] == _SUPPORTED_VERSION


def test_create_default_config_output_has_follow_symlinks_false(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)

    config_document = yaml.safe_load(output_path.read_text(encoding=_TEST_FILE_ENCODING))
    assert config_document["scan"]["follow_symlinks"] is False


def test_create_default_config_output_sets_retention_days_to_hipaa_minimum(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)

    config_document = yaml.safe_load(output_path.read_text(encoding=_TEST_FILE_ENCODING))
    assert config_document["audit"]["retention_days"] == AUDIT_RETENTION_DAYS


def test_create_default_config_output_is_loadable_by_load_config(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    create_default_config(output_path)
    scan_config = load_config(output_path)

    assert isinstance(scan_config, ScanConfig)


def test_create_default_config_raises_configuration_error_on_write_failure(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / ".phi-scanner.yml"

    with patch("pathlib.Path.write_text", side_effect=OSError("permission denied")):
        with pytest.raises(ConfigurationError):
            create_default_config(output_path)


# ---------------------------------------------------------------------------
# load_config — invalid field type coercions
# ---------------------------------------------------------------------------


def test_load_config_raises_configuration_error_for_non_numeric_confidence_threshold(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"confidence_threshold": "banana"}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_load_config_raises_configuration_error_for_non_integer_max_file_size_mb(
    tmp_path: Path,
) -> None:
    config = _build_minimal_config()
    config["scan"] = {"max_file_size_mb": "large"}

    config_file = _write_config(tmp_path, config)

    with pytest.raises(ConfigurationError):
        load_config(config_file)
