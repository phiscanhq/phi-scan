"""Shared pytest fixtures for PhiScan test suite."""

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture constants — no magic values in fixture bodies
# ---------------------------------------------------------------------------

_SAMPLE_FILE_CONTENT: str = 'greeting = "hello world"\n'
_SAMPLE_CONFIG_CONTENT: str = (
    "version: 1\n"
    "scan:\n"
    "  confidence_threshold: 0.6\n"
    "  severity_threshold: low\n"
    "  max_file_size_mb: 10\n"
    "  follow_symlinks: false\n"
    "  include_extensions: null\n"
    "  exclude_paths: []\n"
    "output:\n"
    "  format: table\n"
    "  quiet: false\n"
    "audit:\n"
    "  database_path: ~/.phi-scanner/audit.db\n"
)

# Public alias kept for backward-compatibility with existing test imports.
SAMPLE_FILE_CONTENT: str = _SAMPLE_FILE_CONTENT


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal temporary project directory with nested files for scan tests.

    Layout::

        tmp_path/
        ├── src/
        │   ├── example.py
        │   └── utils/
        │       └── helpers.py
        ├── tests/
        │   └── test_example.py
        └── config/
            └── settings.yml

    Returns:
        tmp_path — the project root containing the nested structure.
    """
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "example.py").write_text(_SAMPLE_FILE_CONTENT)

    utils_dir = src_dir / "utils"
    utils_dir.mkdir()
    (utils_dir / "helpers.py").write_text(_SAMPLE_FILE_CONTENT)

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_example.py").write_text(_SAMPLE_FILE_CONTENT)

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yml").write_text(_SAMPLE_FILE_CONTENT)

    return tmp_path


@pytest.fixture()
def tmp_config(tmp_path: Path) -> Path:
    """Write a minimal valid .phi-scanner.yml to tmp_path and return the file path.

    Returns:
        Path to the written config file.
    """
    config_path = tmp_path / ".phi-scanner.yml"
    config_path.write_text(_SAMPLE_CONFIG_CONTENT, encoding="utf-8")
    return config_path
