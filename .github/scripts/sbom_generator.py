"""CycloneDX document generator for the S10 release-time supply-chain gate.

Exports the production dependency set from the uv lockfile and hands off
to ``pip-audit`` in CycloneDX-JSON output mode so the release workflow
can attach a machine-readable Software Bill of Materials to every
GitHub Release. Designed to be invoked as a single step in
``.github/workflows/release.yml`` and also runnable locally so
maintainers can regenerate the document for a tagged build.

Policy is documented in ``docs/supply-chain.md``. The short version:

    * The CycloneDX document lists the exact production dependency
      closure that ships on PyPI — dev dependencies and editable
      installs are excluded.
    * The file is written to ``sbom.cyclonedx.json`` at the repository
      root and is ignored by git (regenerated per release).
    * Failure to export requirements or to produce a valid document
      exits non-zero so the release workflow hard-fails before publish.

Local command:

    ``uv run --python 3.12 python .github/scripts/sbom_generator.py``

Exits non-zero on export failure or pip-audit failure.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _supply_chain_export import (
    EXPORT_FAILURE_EXIT_CODE,
    PIP_AUDIT_REQUIREMENTS_FLAG,
    REPOSITORY_ROOT,
    DependencyExportError,
    export_production_requirements,
    log_command_invocation,
)

_CYCLONEDX_OUTPUT_PATH: Path = REPOSITORY_ROOT / "sbom.cyclonedx.json"

_PIP_AUDIT_CYCLONEDX_COMMAND: tuple[str, ...] = (
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
)
_PIP_AUDIT_OUTPUT_FLAG: str = "-o"

_SUCCESS_EXIT_CODE: int = 0
_CYCLONEDX_FAILURE_EXIT_CODE: int = 4


def _build_cyclonedx_command(requirements_path: Path) -> list[str]:
    command: list[str] = list(_PIP_AUDIT_CYCLONEDX_COMMAND)
    command.extend([_PIP_AUDIT_OUTPUT_FLAG, str(_CYCLONEDX_OUTPUT_PATH)])
    command.extend([PIP_AUDIT_REQUIREMENTS_FLAG, str(requirements_path)])
    return command


def _execute_cyclonedx_command(command: list[str]) -> int:
    audit_completed = subprocess.run(command, cwd=REPOSITORY_ROOT, check=False)
    return audit_completed.returncode


def main() -> int:
    try:
        requirements_path = export_production_requirements()
    except DependencyExportError as export_error:
        print(f"Dependency export failed: {export_error}", file=sys.stderr)
        return EXPORT_FAILURE_EXIT_CODE
    if _CYCLONEDX_OUTPUT_PATH.is_symlink():
        print(
            f"{_CYCLONEDX_OUTPUT_PATH.name} is a symlink; refusing to follow it "
            "during write. Remove the symlink and re-run.",
            file=sys.stderr,
        )
        return _CYCLONEDX_FAILURE_EXIT_CODE
    command = _build_cyclonedx_command(requirements_path)
    log_command_invocation(command)
    cyclonedx_exit_code = _execute_cyclonedx_command(command)
    if cyclonedx_exit_code != _SUCCESS_EXIT_CODE:
        print(
            f"pip-audit CycloneDX generation failed with exit code {cyclonedx_exit_code}.",
            file=sys.stderr,
        )
        return _CYCLONEDX_FAILURE_EXIT_CODE
    if not _CYCLONEDX_OUTPUT_PATH.exists():
        print(
            f"pip-audit reported success but {_CYCLONEDX_OUTPUT_PATH.name} was not written.",
            file=sys.stderr,
        )
        return _CYCLONEDX_FAILURE_EXIT_CODE
    print(f"CycloneDX document written to {_CYCLONEDX_OUTPUT_PATH}", flush=True)
    return _SUCCESS_EXIT_CODE


if __name__ == "__main__":
    sys.exit(main())
