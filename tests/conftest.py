"""Shared pytest fixtures for PhiScan test suite."""

from pathlib import Path

import pytest

from phi_scan.config import create_default_config
from phi_scan.constants import DEFAULT_TEXT_ENCODING

# ---------------------------------------------------------------------------
# Fixture constants — no magic values in fixture bodies
# ---------------------------------------------------------------------------

_SAMPLE_FILE_CONTENT: str = 'greeting = "hello world"\n'


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
    (src_dir / "example.py").write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    utils_dir = src_dir / "utils"
    utils_dir.mkdir()
    (utils_dir / "helpers.py").write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_example.py").write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yml").write_text(_SAMPLE_FILE_CONTENT, encoding=DEFAULT_TEXT_ENCODING)

    return tmp_path


@pytest.fixture()
def tmp_config(tmp_path: Path) -> Path:
    """Write the default .phi-scanner.yml to tmp_path and return the file path.

    Uses create_default_config so the fixture stays in sync with the schema
    without duplicating default values inline.

    Returns:
        Path to the written config file.
    """
    config_path = tmp_path / ".phi-scanner.yml"
    create_default_config(config_path)
    return config_path
