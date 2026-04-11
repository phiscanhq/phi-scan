"""Shared dependency-export utilities for the supply-chain CI scripts.

Both ``pip_audit_runner.py`` (S9) and ``sbom_generator.py`` (S10) need
to export the production dependency set from the uv lockfile and
strip editable install lines before pip-audit consumes the
requirements. Keeping that logic in a single place prevents the two
scripts from drifting apart if the export flags, the filter rules,
or the pip-audit requirements flag ever need to change.

The module intentionally exposes only the names the two entry-point
scripts need. Nothing in ``phi_scan/`` imports this file; it lives
under ``.github/scripts/`` because it is CI tooling, not runtime
code.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPOSITORY_ROOT: Path = Path(__file__).resolve().parents[2]
REQUIREMENTS_OUTPUT_PATH: Path = REPOSITORY_ROOT / "pip-audit-requirements.txt"
EDITABLE_INSTALL_PREFIX: str = "-e"

UV_EXPORT_COMMAND: tuple[str, ...] = (
    "uv",
    "export",
    "--quiet",
    "--no-hashes",
    "--no-dev",
    "--format",
    "requirements-txt",
)

PIP_AUDIT_REQUIREMENTS_FLAG: str = "-r"

EXPORT_FAILURE_EXIT_CODE: int = 3


class DependencyExportError(Exception):
    """Raised when ``uv export`` fails to produce a requirements file."""


def _filter_editable_install_lines(raw_export_output: str) -> list[str]:
    return [
        line
        for line in raw_export_output.splitlines()
        if not line.startswith(EDITABLE_INSTALL_PREFIX)
    ]


def export_production_requirements() -> Path:
    """Export the production dependency set and return the file path.

    Runs ``uv export`` with the no-dev / no-hashes flags, strips
    editable install lines so pip-audit does not reject the file, and
    writes the filtered output to ``REQUIREMENTS_OUTPUT_PATH``. Raises
    ``DependencyExportError`` on any ``uv export`` failure so callers
    can decide how to surface the error before exiting.
    """
    try:
        export_completed = subprocess.run(
            UV_EXPORT_COMMAND,
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as export_error:
        raise DependencyExportError(
            f"uv export failed with exit code {export_error.returncode}: "
            f"{export_error.stderr.strip()}"
        ) from export_error
    filtered_lines = _filter_editable_install_lines(export_completed.stdout)
    REQUIREMENTS_OUTPUT_PATH.write_text("\n".join(filtered_lines) + "\n")
    return REQUIREMENTS_OUTPUT_PATH


def log_command_invocation(command: list[str]) -> None:
    print(f"Running: {' '.join(command)}", flush=True)
