"""CycloneDX SBOM generator for the S10 release-time supply-chain gate.

Exports the production dependency set from the uv lockfile and hands off
to ``pip-audit`` in CycloneDX-JSON output mode so the release workflow
can attach a machine-readable Software Bill of Materials to every
GitHub Release. Designed to be invoked as a single step in
``.github/workflows/release.yml`` and also runnable locally so
maintainers can regenerate the SBOM for a tagged build.

Policy is documented in ``docs/supply-chain.md``. The short version:

    * The SBOM lists the exact production dependency closure that ships
      on PyPI — dev dependencies and editable installs are excluded.
    * The file is written to ``sbom.cyclonedx.json`` at the repository
      root and is ignored by git (regenerated per release).
    * Failure to export requirements or to produce a valid SBOM exits
      non-zero so the release workflow hard-fails before publish.

Local command::

    uv run --python 3.12 python .github/scripts/sbom_generator.py

Exits non-zero on export failure or pip-audit SBOM generation failure.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPOSITORY_ROOT: Path = Path(__file__).resolve().parents[2]
_REQUIREMENTS_OUTPUT_PATH: Path = _REPOSITORY_ROOT / "pip-audit-requirements.txt"
_SBOM_OUTPUT_PATH: Path = _REPOSITORY_ROOT / "sbom.cyclonedx.json"
_EDITABLE_INSTALL_PREFIX: str = "-e"

_UV_EXPORT_COMMAND: tuple[str, ...] = (
    "uv",
    "export",
    "--quiet",
    "--no-hashes",
    "--no-dev",
    "--format",
    "requirements-txt",
)
_PIP_AUDIT_SBOM_COMMAND: tuple[str, ...] = (
    "uv",
    "run",
    "--python",
    "3.12",
    "--with",
    "pip-audit",
    "pip-audit",
    "--disable-pip",
    "--no-deps",
    "--format",
    "cyclonedx-json",
    "-o",
)

_EXPORT_FAILURE_EXIT_CODE: int = 3
_SBOM_FAILURE_EXIT_CODE: int = 4


def _export_production_requirements() -> Path:
    try:
        export_completed = subprocess.run(
            _UV_EXPORT_COMMAND,
            cwd=_REPOSITORY_ROOT,
            capture_output=True,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError as export_error:
        print(
            f"uv export failed with exit code {export_error.returncode}:\n{export_error.stderr}",
            file=sys.stderr,
        )
        sys.exit(_EXPORT_FAILURE_EXIT_CODE)
    filtered_lines = [
        line
        for line in export_completed.stdout.splitlines()
        if not line.startswith(_EDITABLE_INSTALL_PREFIX)
    ]
    _REQUIREMENTS_OUTPUT_PATH.write_text("\n".join(filtered_lines) + "\n")
    return _REQUIREMENTS_OUTPUT_PATH


def _build_sbom_command(requirements_path: Path, sbom_output_path: Path) -> list[str]:
    command: list[str] = list(_PIP_AUDIT_SBOM_COMMAND)
    command.append(str(sbom_output_path))
    command.extend(["-r", str(requirements_path)])
    return command


def _generate_sbom(requirements_path: Path) -> int:
    command = _build_sbom_command(requirements_path, _SBOM_OUTPUT_PATH)
    print(f"Running: {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=_REPOSITORY_ROOT, check=False)
    return completed.returncode


def main() -> int:
    requirements_path = _export_production_requirements()
    sbom_exit_code = _generate_sbom(requirements_path)
    if sbom_exit_code != 0:
        print(
            f"pip-audit SBOM generation failed with exit code {sbom_exit_code}.",
            file=sys.stderr,
        )
        return _SBOM_FAILURE_EXIT_CODE
    if not _SBOM_OUTPUT_PATH.exists():
        print(
            f"pip-audit reported success but {_SBOM_OUTPUT_PATH.name} was not written.",
            file=sys.stderr,
        )
        return _SBOM_FAILURE_EXIT_CODE
    print(f"CycloneDX SBOM written to {_SBOM_OUTPUT_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
