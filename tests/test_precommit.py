"""Structural tests for .pre-commit-hooks.yaml.

These tests verify that the pre-commit hook definition file exists, is valid
YAML, and contains the required fields with the values that the pre-commit
framework and phi-scan's own CLI contract demand.

No pre-commit framework installation is required to run these tests — they
inspect the file directly, catching schema drift before it breaks CI/CD setups
in consumer repositories.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# File location
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).parent.parent
_HOOKS_FILE: Path = _REPO_ROOT / ".pre-commit-hooks.yaml"

# ---------------------------------------------------------------------------
# Expected values — all literals named so no magic strings appear in tests
# ---------------------------------------------------------------------------

_EXPECTED_HOOK_ID: str = "phi-scan"
_EXPECTED_HOOK_NAME_PREFIX: str = "PhiScan"
_EXPECTED_LANGUAGE: str = "python"
# Entry must invoke the scan --diff command; the ref value may evolve but the
# command structure is part of the public hook contract.
_EXPECTED_ENTRY_COMMAND: str = "phi-scan scan --diff"
_EXPECTED_STAGES: frozenset[str] = frozenset(["pre-commit", "pre-push"])
_PASS_FILENAMES_KEY: str = "pass_filenames"
_PASS_FILENAMES_EXPECTED: bool = False
_MINIMUM_PRE_COMMIT_VERSION_KEY: str = "minimum_pre_commit_version"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def hooks_list() -> list[dict[str, object]]:
    """Load and return the parsed list of hook definitions."""
    raw_text = _HOOKS_FILE.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw_text)
    assert isinstance(parsed, list), ".pre-commit-hooks.yaml must be a YAML list"
    return parsed  # type: ignore[return-value]


@pytest.fixture(scope="module")
def phi_scan_hook(hooks_list: list[dict[str, object]]) -> dict[str, object]:
    """Return the hook definition with id == 'phi-scan'."""
    matching = [h for h in hooks_list if h.get("id") == _EXPECTED_HOOK_ID]
    assert matching, f"No hook with id={_EXPECTED_HOOK_ID!r} found in {_HOOKS_FILE}"
    return matching[0]


# ---------------------------------------------------------------------------
# File-level tests
# ---------------------------------------------------------------------------


class TestPreCommitHooksFileStructure:
    """Validate that the hooks file exists and has a well-formed top-level shape."""

    def test_hooks_file_exists(self) -> None:
        assert _HOOKS_FILE.exists(), f"{_HOOKS_FILE} not found in repository root"

    def test_hooks_file_is_valid_yaml(self) -> None:
        raw_text = _HOOKS_FILE.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw_text)
        assert parsed is not None

    def test_hooks_file_is_a_list(self, hooks_list: list[dict[str, object]]) -> None:
        assert isinstance(hooks_list, list)

    def test_hooks_file_contains_at_least_one_hook(
        self, hooks_list: list[dict[str, object]]
    ) -> None:
        assert len(hooks_list) >= 1

    def test_every_hook_has_an_id(self, hooks_list: list[dict[str, object]]) -> None:
        for hook in hooks_list:
            assert "id" in hook, f"Hook missing 'id' field: {hook}"


# ---------------------------------------------------------------------------
# Hook identity tests
# ---------------------------------------------------------------------------


class TestPhiScanHookIdentity:
    """Verify the phi-scan hook has the correct identifier and display name."""

    def test_hook_id_is_phi_scan(self, phi_scan_hook: dict[str, object]) -> None:
        assert phi_scan_hook["id"] == _EXPECTED_HOOK_ID

    def test_hook_name_starts_with_phiscan(self, phi_scan_hook: dict[str, object]) -> None:
        name = str(phi_scan_hook.get("name", ""))
        assert name.startswith(_EXPECTED_HOOK_NAME_PREFIX), (
            f"Hook name {name!r} should start with {_EXPECTED_HOOK_NAME_PREFIX!r}"
        )

    def test_hook_has_description(self, phi_scan_hook: dict[str, object]) -> None:
        description = str(phi_scan_hook.get("description", "")).strip()
        assert description, "Hook is missing a description"


# ---------------------------------------------------------------------------
# Hook execution contract tests
# ---------------------------------------------------------------------------


class TestPhiScanHookExecutionContract:
    """Verify the fields that control how pre-commit invokes the hook."""

    def test_language_is_python(self, phi_scan_hook: dict[str, object]) -> None:
        assert phi_scan_hook.get("language") == _EXPECTED_LANGUAGE

    def test_entry_invokes_scan_diff(self, phi_scan_hook: dict[str, object]) -> None:
        entry = str(phi_scan_hook.get("entry", ""))
        assert entry.startswith(_EXPECTED_ENTRY_COMMAND), (
            f"Entry {entry!r} must start with {_EXPECTED_ENTRY_COMMAND!r}. "
            "The hook must invoke 'phi-scan scan --diff <ref>' so that phi-scan "
            "determines its own file list from the git diff rather than relying "
            "on pre-commit's file arguments."
        )

    def test_pass_filenames_is_false(self, phi_scan_hook: dict[str, object]) -> None:
        # phi-scan drives its own file discovery from the git diff; pre-commit
        # must not inject individual file paths as positional arguments.
        assert phi_scan_hook.get(_PASS_FILENAMES_KEY) is _PASS_FILENAMES_EXPECTED

    def test_stages_include_pre_commit(self, phi_scan_hook: dict[str, object]) -> None:
        stages: frozenset[str] = frozenset(phi_scan_hook.get("stages", []))  # type: ignore[arg-type]
        assert "pre-commit" in stages

    def test_stages_include_pre_push(self, phi_scan_hook: dict[str, object]) -> None:
        stages: frozenset[str] = frozenset(phi_scan_hook.get("stages", []))  # type: ignore[arg-type]
        assert "pre-push" in stages

    def test_stages_match_expected_set(self, phi_scan_hook: dict[str, object]) -> None:
        stages: frozenset[str] = frozenset(phi_scan_hook.get("stages", []))  # type: ignore[arg-type]
        assert stages == _EXPECTED_STAGES

    def test_minimum_pre_commit_version_is_set(self, phi_scan_hook: dict[str, object]) -> None:
        assert _MINIMUM_PRE_COMMIT_VERSION_KEY in phi_scan_hook, (
            "minimum_pre_commit_version should be declared to prevent installation "
            "on very old pre-commit versions that lack required features."
        )
