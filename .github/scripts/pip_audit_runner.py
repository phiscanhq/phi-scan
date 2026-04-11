"""Supply-chain vulnerability scan runner for the S9 CI gate.

Exports the production dependency set from the uv lockfile, applies the
policy-enforced ignore list from ``.pip-audit-ignore.toml``, and hands
off to ``pip-audit``. Designed to be invoked as a single step in
``.github/workflows/ci.yml`` so the gate fails the merge on any
unexplained dependency advisory.

Policy is documented in ``docs/supply-chain.md``. The short version:

    * Every entry in ``.pip-audit-ignore.toml`` must have an ``id``
      matching ``CVE-YYYY-N+`` or ``GHSA-xxxx-xxxx-xxxx``, a human
      ``reason``, and a ``tracking`` URL.
    * ``expires`` is optional. If set, the runner fails once the date
      has passed so stale ignores cannot hide in the file.
    * No wildcards. Any ``id`` that does not match the advisory-ID
      regex causes the runner to fail before pip-audit is invoked.

Exits non-zero on policy violation, export failure, or any
pip-audit-reported vulnerability that is not covered by an accepted
entry in the ignore list.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

from supply_chain_export import (
    EXPORT_FAILURE_EXIT_CODE,
    PIP_AUDIT_REQUIREMENTS_FLAG,
    REPOSITORY_ROOT,
    DependencyExportError,
    execute_audit_command,
    export_production_requirements,
    log_command_invocation,
)

_IGNORE_FILE_NAME: str = ".pip-audit-ignore.toml"
_IGNORE_FILE_PATH: Path = REPOSITORY_ROOT / _IGNORE_FILE_NAME

_IGNORED_ENTRIES_KEY: str = "ignored"
_ENTRY_ID_KEY: str = "id"
_ENTRY_REASON_KEY: str = "reason"
_ENTRY_TRACKING_KEY: str = "tracking"
_ENTRY_EXPIRES_KEY: str = "expires"
_REQUIRED_ENTRY_KEYS: frozenset[str] = frozenset(
    {_ENTRY_ID_KEY, _ENTRY_REASON_KEY, _ENTRY_TRACKING_KEY}
)
_ALLOWED_ENTRY_KEYS: frozenset[str] = frozenset(
    {_ENTRY_ID_KEY, _ENTRY_REASON_KEY, _ENTRY_TRACKING_KEY, _ENTRY_EXPIRES_KEY}
)

_ADVISORY_ID_PATTERN: re.Pattern[str] = re.compile(
    r"^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$"
)

_PIP_AUDIT_BASE_COMMAND: tuple[str, ...] = (
    "uv",
    "run",
    "--python",
    "3.12",
    "--with",
    "pip-audit",
    "pip-audit",
    "--disable-pip",
    "--no-deps",
    "--strict",
)
_PIP_AUDIT_IGNORE_FLAG: str = "--ignore-vuln"
_TOML_BINARY_READ_MODE: str = "rb"

_POLICY_VIOLATION_EXIT_CODE: int = 2


class PipAuditPolicyError(Exception):
    """Raised when ``.pip-audit-ignore.toml`` violates the documented policy."""


def _load_ignore_entries() -> list[dict[str, object]]:
    if not _IGNORE_FILE_PATH.exists():
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} is missing from the repository root. "
            "The file must exist even when empty; see docs/supply-chain.md."
        )
    with _IGNORE_FILE_PATH.open(_TOML_BINARY_READ_MODE) as ignore_file:
        parsed_document = tomllib.load(ignore_file)
    raw_entries = parsed_document.get(_IGNORED_ENTRIES_KEY, [])
    if not isinstance(raw_entries, list):
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} top-level 'ignored' must be an array of tables."
        )
    for entry_index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            raise PipAuditPolicyError(
                f"{_IGNORE_FILE_NAME} entry #{entry_index} must be a TOML table."
            )
    return [dict(raw_entry) for raw_entry in raw_entries]


_TRACKING_URL_SCHEMES: tuple[str, ...] = ("http://", "https://")


def _validate_entry_keys(entry_index: int, entry: dict[str, object]) -> None:
    present_keys = set(entry.keys())
    missing_keys = _REQUIRED_ENTRY_KEYS - present_keys
    if missing_keys:
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} is missing required "
            f"key(s) {sorted(missing_keys)}. Every entry must declare id, "
            "reason, and tracking."
        )
    unknown_keys = present_keys - _ALLOWED_ENTRY_KEYS
    if unknown_keys:
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} has unknown key(s) "
            f"{sorted(unknown_keys)}. Allowed: {sorted(_ALLOWED_ENTRY_KEYS)}."
        )


def _validate_advisory_id_format(entry_index: int, advisory_id: object) -> str:
    if not isinstance(advisory_id, str) or not _ADVISORY_ID_PATTERN.match(advisory_id):
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} id={advisory_id!r} does "
            "not match the advisory-ID pattern CVE-YYYY-N+ or "
            "GHSA-xxxx-xxxx-xxxx. Wildcards and blanket ignores are not allowed."
        )
    return advisory_id


def _validate_reason_field(entry_index: int, reason_value: object) -> None:
    if not isinstance(reason_value, str) or not reason_value.strip():
        raise PipAuditPolicyError(f"{_IGNORE_FILE_NAME} entry #{entry_index} has empty reason.")


def _validate_tracking_field(entry_index: int, tracking_value: object) -> None:
    if not isinstance(tracking_value, str) or not tracking_value.startswith(_TRACKING_URL_SCHEMES):
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} tracking must be an "
            "http(s) URL pointing at a tracking issue."
        )


def _validate_entry(entry_index: int, entry: dict[str, object]) -> str:
    _validate_entry_keys(entry_index, entry)
    advisory_id = _validate_advisory_id_format(entry_index, entry[_ENTRY_ID_KEY])
    _validate_reason_field(entry_index, entry[_ENTRY_REASON_KEY])
    _validate_tracking_field(entry_index, entry[_ENTRY_TRACKING_KEY])
    _validate_expiry(entry_index, entry, advisory_id)
    return advisory_id


def _validate_expiry(entry_index: int, entry: dict[str, object], advisory_id: str) -> None:
    if _ENTRY_EXPIRES_KEY not in entry:
        return
    expires_value = entry[_ENTRY_EXPIRES_KEY]
    if not isinstance(expires_value, dt.date):
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} expires must be a "
            "TOML date literal (YYYY-MM-DD), not a string."
        )
    today = dt.date.today()
    if expires_value < today:
        raise PipAuditPolicyError(
            f"{_IGNORE_FILE_NAME} entry #{entry_index} ({advisory_id}) "
            f"expired on {expires_value.isoformat()}. Re-review the risk "
            "and update or remove the entry."
        )


def _collect_validated_ignore_ids() -> list[str]:
    raw_entries = _load_ignore_entries()
    return [_validate_entry(entry_index, entry) for entry_index, entry in enumerate(raw_entries)]


def _log_ignore_list_state(ignored_advisory_ids: list[str]) -> None:
    if ignored_advisory_ids:
        print(
            f"Applying ignore list from {_IGNORE_FILE_NAME}: {ignored_advisory_ids}",
            flush=True,
        )
        return
    print(
        f"{_IGNORE_FILE_NAME} has no active entries — running pip-audit with zero ignores.",
        flush=True,
    )


def _build_pip_audit_command(requirements_path: Path, ignored_advisory_ids: list[str]) -> list[str]:
    command: list[str] = list(_PIP_AUDIT_BASE_COMMAND)
    command.extend([PIP_AUDIT_REQUIREMENTS_FLAG, str(requirements_path)])
    for advisory_id in ignored_advisory_ids:
        command.extend([_PIP_AUDIT_IGNORE_FLAG, advisory_id])
    return command


def main() -> int:
    try:
        ignored_advisory_ids = _collect_validated_ignore_ids()
    except PipAuditPolicyError as policy_error:
        print(f"Policy violation: {policy_error}", file=sys.stderr)
        return _POLICY_VIOLATION_EXIT_CODE
    try:
        requirements_path = export_production_requirements()
    except DependencyExportError as export_error:
        print(f"Dependency export failed: {export_error}", file=sys.stderr)
        return EXPORT_FAILURE_EXIT_CODE
    _log_ignore_list_state(ignored_advisory_ids)
    command = _build_pip_audit_command(requirements_path, ignored_advisory_ids)
    log_command_invocation(command)
    return execute_audit_command(command)


if __name__ == "__main__":
    sys.exit(main())
