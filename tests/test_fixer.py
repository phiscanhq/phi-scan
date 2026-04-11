"""Tests for phi_scan.fixer — Phase 2F auto-fix engine.

Covers all eight Phase 2F tasks:
    2F.1 fixer module exists and exports the expected public API
    2F.2 generate_synthetic_value returns a valid string for every HIPAA category
    2F.3 --dry-run (fix_file DRY_RUN) produces a unified diff without modifying files
    2F.4 --apply (fix_file APPLY) overwrites the file in place
    2F.5 --patch (fix_file PATCH) writes a .patch file
    2F.6 Deterministic: same PHI value always maps to same synthetic value
    2F.7 Suppressed lines are not replaced
    2F.8 Interactive mode: apply_approved_replacements honours caller-selected subset
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import phi_scan.fixer as fixer_module
from phi_scan.constants import DEFAULT_TEXT_ENCODING, PhiCategory
from phi_scan.fixer import (
    FixMode,
    FixReplacement,
    FixResult,
    apply_approved_replacements,
    collect_file_replacements,
    fix_file,
    generate_synthetic_value,
)

# ---------------------------------------------------------------------------
# Test constants — no magic values in test bodies
# ---------------------------------------------------------------------------

_SSN_VALUE: str = "123-45-6789"
_SSN_LINE: str = f'patient_ssn = "{_SSN_VALUE}"\n'
_SSN_SUPPRESS_ALL_LINE: str = f'patient_ssn = "{_SSN_VALUE}"  # phi-scan:ignore\n'
_SSN_SUPPRESS_NEXT_LINE_DIRECTIVE: str = "# phi-scan:ignore-next-line\n"

_EMAIL_VALUE: str = "john.doe@hospital.org"
_EMAIL_LINE: str = f'contact_email = "{_EMAIL_VALUE}"\n'

# A line with no tokens long enough or structured enough to match any PHI pattern.
_CLEAN_LINE: str = "x = 1\n"

_PATCH_SUFFIX: str = ".patch"
_DIFF_HUNK_MARKER: str = "@@"
_DIFF_FROM_MARKER: str = "---"
_DIFF_TO_MARKER: str = "+++"

# Structural-safety constants for threat-model row F-3 (P0).
# The fixer is the only module that writes synthetic values back to source
# files. Any form of dynamic code execution in that path would let an
# attacker who can stage a crafted input file achieve code execution on
# the scanning host. This test pins the structural invariant that the
# module is pure text replacement — no subprocess, no eval/exec, no
# dynamic import.
_FIXER_MODULE_PATH: Path = Path(fixer_module.__file__)

_FIXER_BANNED_IMPORT_MODULE_NAMES: frozenset[str] = frozenset(
    {
        "subprocess",
        "os.system",
        "pty",
        "importlib",
    }
)
_FIXER_BANNED_CALL_NAMES: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
    }
)
_FIXER_BANNED_ATTRIBUTE_CHAINS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "exec"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execvp"),
        ("os", "spawn"),
        ("os", "spawnv"),
    }
)

# SHA-256 hex digest of "abc" — fixed reference value for determinism tests.
_ABC_HASH: str = "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469432f1cc029d8cbe90"

# A second distinct hash used to verify two different inputs produce different outputs.
_DEF_HASH: str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"

# Expected email synthetic prefix — proves RFC 2606 domain is used.
_EXPECTED_EMAIL_DOMAIN_SUFFIX: str = "@example.com"

# Expected SSN synthetic area — proves reserved range is used.
_EXPECTED_SSN_PREFIX: str = "000-00-"

# Expected MRN synthetic prefix.
_EXPECTED_MRN_PREFIX: str = "MRN-"

# Expected IP synthetic prefix (RFC 5737 TEST-NET-1).
_EXPECTED_IP_PREFIX: str = "192.0.2."

# Expected URL synthetic base.
_EXPECTED_URL_BASE: str = "https://example.com/resource/"

# Minimum expected account/plan/device number string length (prefix + 6 digits).
_MIN_SYNTHETIC_ID_LENGTH: int = 7


# ---------------------------------------------------------------------------
# 2F.1 — Public API exports
# ---------------------------------------------------------------------------


def test_fixer_module_exports_fix_mode() -> None:
    assert FixMode.DRY_RUN == "dry-run"
    assert FixMode.APPLY == "apply"
    assert FixMode.PATCH == "patch"


def test_fixer_module_exports_fix_replacement_dataclass() -> None:
    replacement = FixReplacement(
        line_number=1,
        start_column=0,
        end_column=5,
        synthetic_text="world",
        hipaa_category=PhiCategory.NAME,
    )

    assert replacement.line_number == 1
    assert replacement.start_column == 0
    assert replacement.synthetic_text == "world"


def test_fixer_module_exports_fix_result_dataclass() -> None:
    result = FixResult(
        file_path=Path("example.py"),
        replacements_applied=(),
        unified_diff="",
        patch_path=None,
    )

    assert result.file_path == Path("example.py")
    assert result.replacements_applied == ()
    assert result.patch_path is None


# ---------------------------------------------------------------------------
# 2F.2 — Synthetic generators per HIPAA category
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hipaa_category",
    [
        PhiCategory.NAME,
        PhiCategory.GEOGRAPHIC,
        PhiCategory.DATE,
        PhiCategory.PHONE,
        PhiCategory.FAX,
        PhiCategory.EMAIL,
        PhiCategory.SSN,
        PhiCategory.MRN,
        PhiCategory.HEALTH_PLAN,
        PhiCategory.ACCOUNT,
        PhiCategory.CERTIFICATE,
        PhiCategory.VEHICLE,
        PhiCategory.DEVICE,
        PhiCategory.URL,
        PhiCategory.IP,
        PhiCategory.BIOMETRIC,
        PhiCategory.PHOTO,
        PhiCategory.UNIQUE_ID,
        PhiCategory.SUBSTANCE_USE_DISORDER,
        PhiCategory.QUASI_IDENTIFIER_COMBINATION,
    ],
)
def test_generate_synthetic_value_returns_non_empty_string_for_every_category(
    hipaa_category: PhiCategory,
) -> None:
    synthetic = generate_synthetic_value(hipaa_category, _ABC_HASH)

    assert isinstance(synthetic, str)
    assert len(synthetic) > 0


def test_generate_synthetic_ssn_uses_reserved_area() -> None:
    synthetic = generate_synthetic_value(PhiCategory.SSN, _ABC_HASH)

    assert synthetic.startswith(_EXPECTED_SSN_PREFIX)


def test_generate_synthetic_mrn_uses_mrn_prefix() -> None:
    synthetic = generate_synthetic_value(PhiCategory.MRN, _ABC_HASH)

    assert synthetic.startswith(_EXPECTED_MRN_PREFIX)


def test_generate_synthetic_email_uses_rfc2606_domain() -> None:
    synthetic = generate_synthetic_value(PhiCategory.EMAIL, _ABC_HASH)

    assert synthetic.endswith(_EXPECTED_EMAIL_DOMAIN_SUFFIX)


def test_generate_synthetic_ip_uses_rfc5737_prefix() -> None:
    synthetic = generate_synthetic_value(PhiCategory.IP, _ABC_HASH)

    assert synthetic.startswith(_EXPECTED_IP_PREFIX)


def test_generate_synthetic_url_uses_rfc2606_base() -> None:
    synthetic = generate_synthetic_value(PhiCategory.URL, _ABC_HASH)

    assert synthetic.startswith(_EXPECTED_URL_BASE)


def test_generate_synthetic_account_has_expected_minimum_length() -> None:
    synthetic = generate_synthetic_value(PhiCategory.ACCOUNT, _ABC_HASH)

    assert len(synthetic) >= _MIN_SYNTHETIC_ID_LENGTH


def test_generate_synthetic_fax_same_format_as_phone() -> None:
    fax_synthetic = generate_synthetic_value(PhiCategory.FAX, _ABC_HASH)
    phone_synthetic = generate_synthetic_value(PhiCategory.PHONE, _ABC_HASH)

    # Both use the FCC fictional range — same generator, same seed → same output.
    assert fax_synthetic == phone_synthetic


# ---------------------------------------------------------------------------
# 2F.3 — DRY_RUN shows diff without modifying file
# ---------------------------------------------------------------------------


def test_fix_file_dry_run_returns_non_empty_diff_for_file_with_ssn(
    tmp_path: Path,
) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(target_file, FixMode.DRY_RUN)

    assert _DIFF_HUNK_MARKER in result.unified_diff
    assert _DIFF_FROM_MARKER in result.unified_diff
    assert _DIFF_TO_MARKER in result.unified_diff


def test_fix_file_dry_run_does_not_modify_file(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)
    original_content = target_file.read_text(encoding=DEFAULT_TEXT_ENCODING)

    fix_file(target_file, FixMode.DRY_RUN)

    assert target_file.read_text(encoding=DEFAULT_TEXT_ENCODING) == original_content


def test_fix_file_dry_run_returns_empty_diff_for_clean_file(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(_CLEAN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(clean_file, FixMode.DRY_RUN)

    assert result.unified_diff == ""
    assert result.replacements_applied == ()


# ---------------------------------------------------------------------------
# 2F.4 — APPLY overwrites file in place
# ---------------------------------------------------------------------------


def test_fix_file_apply_modifies_file_content(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(target_file, FixMode.APPLY)
    modified_content = target_file.read_text(encoding=DEFAULT_TEXT_ENCODING)

    assert len(result.replacements_applied) > 0
    assert _SSN_VALUE not in modified_content


def test_fix_file_apply_does_not_modify_clean_file(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(_CLEAN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    fix_file(clean_file, FixMode.APPLY)

    assert clean_file.read_text(encoding=DEFAULT_TEXT_ENCODING) == _CLEAN_LINE


# ---------------------------------------------------------------------------
# 2F.5 — PATCH writes a .patch file
# ---------------------------------------------------------------------------


def test_fix_file_patch_writes_patch_file(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)
    patch_dir = tmp_path / "patches"
    patch_dir.mkdir()

    result = fix_file(target_file, FixMode.PATCH, patch_dir=patch_dir)

    assert result.patch_path is not None
    assert result.patch_path.suffix == _PATCH_SUFFIX
    assert result.patch_path.exists()


def test_fix_file_patch_content_is_valid_unified_diff(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(target_file, FixMode.PATCH)

    assert result.patch_path is not None
    patch_content = result.patch_path.read_text(encoding=DEFAULT_TEXT_ENCODING)
    assert _DIFF_HUNK_MARKER in patch_content


def test_fix_file_patch_does_not_modify_source_file(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    fix_file(target_file, FixMode.PATCH)

    assert target_file.read_text(encoding=DEFAULT_TEXT_ENCODING) == _SSN_LINE


def test_fix_file_patch_returns_none_patch_path_for_clean_file(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(_CLEAN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(clean_file, FixMode.PATCH)

    assert result.patch_path is None


# ---------------------------------------------------------------------------
# 2F.6 — Deterministic replacements
# ---------------------------------------------------------------------------


def test_generate_synthetic_value_is_deterministic_for_same_inputs() -> None:
    first_call = generate_synthetic_value(PhiCategory.SSN, _ABC_HASH)
    second_call = generate_synthetic_value(PhiCategory.SSN, _ABC_HASH)

    assert first_call == second_call


def test_generate_synthetic_value_differs_for_different_hashes() -> None:
    synthetic_abc = generate_synthetic_value(PhiCategory.NAME, _ABC_HASH)
    synthetic_def = generate_synthetic_value(PhiCategory.NAME, _DEF_HASH)

    assert synthetic_abc != synthetic_def


def test_collect_file_replacements_same_phi_value_gets_same_synthetic(
    tmp_path: Path,
) -> None:
    # The same SSN appears on two lines — both should get the same synthetic.
    two_lines = _SSN_LINE + _SSN_LINE
    target_file = tmp_path / "patient.py"
    target_file.write_text(two_lines, encoding=DEFAULT_TEXT_ENCODING)

    replacements = collect_file_replacements(target_file)
    # Both lines match the same SSN format; filter by HIPAA category.
    ssn_replacements = [r for r in replacements if r.hipaa_category == PhiCategory.SSN]

    assert len(ssn_replacements) == 2
    # Same PHI value → same hash → same seed → same synthetic replacement.
    assert ssn_replacements[0].synthetic_text == ssn_replacements[1].synthetic_text


# ---------------------------------------------------------------------------
# 2F.7 — Suppressed lines are not replaced
# ---------------------------------------------------------------------------


def test_collect_file_replacements_skips_suppressed_line(tmp_path: Path) -> None:
    suppressed_file = tmp_path / "suppressed.py"
    suppressed_file.write_text(_SSN_SUPPRESS_ALL_LINE, encoding=DEFAULT_TEXT_ENCODING)

    replacements = collect_file_replacements(suppressed_file)

    assert len(replacements) == 0


def test_collect_file_replacements_skips_line_after_ignore_next_line(
    tmp_path: Path,
) -> None:
    content = _SSN_SUPPRESS_NEXT_LINE_DIRECTIVE + _SSN_LINE
    target_file = tmp_path / "patient.py"
    target_file.write_text(content, encoding=DEFAULT_TEXT_ENCODING)

    replacements = collect_file_replacements(target_file)

    assert len(replacements) == 0


def test_fix_file_apply_does_not_replace_suppressed_line(tmp_path: Path) -> None:
    suppressed_file = tmp_path / "suppressed.py"
    suppressed_file.write_text(_SSN_SUPPRESS_ALL_LINE, encoding=DEFAULT_TEXT_ENCODING)
    original_content = suppressed_file.read_text(encoding=DEFAULT_TEXT_ENCODING)

    fix_file(suppressed_file, FixMode.APPLY)

    assert suppressed_file.read_text(encoding=DEFAULT_TEXT_ENCODING) == original_content


def test_fix_file_unsuppressed_line_is_replaced_when_next_line_suppressed(
    tmp_path: Path,
) -> None:
    # phi-scan:ignore-next-line only suppresses the NEXT line, not the current.
    content = _SSN_LINE + _SSN_SUPPRESS_NEXT_LINE_DIRECTIVE + _SSN_LINE
    target_file = tmp_path / "patient.py"
    target_file.write_text(content, encoding=DEFAULT_TEXT_ENCODING)

    replacements = collect_file_replacements(target_file)
    # First SSN (line 1) is NOT suppressed; third SSN (line 3) is suppressed.
    ssn_replacements = [r for r in replacements if r.hipaa_category == PhiCategory.SSN]

    assert len(ssn_replacements) == 1
    assert ssn_replacements[0].line_number == 1


# ---------------------------------------------------------------------------
# 2F.8 — Interactive mode: apply_approved_replacements applies subset
# ---------------------------------------------------------------------------


def test_apply_approved_replacements_applies_only_approved_items(
    tmp_path: Path,
) -> None:
    content = _SSN_LINE + _EMAIL_LINE
    target_file = tmp_path / "patient.py"
    target_file.write_text(content, encoding=DEFAULT_TEXT_ENCODING)
    all_replacements = collect_file_replacements(target_file)
    # SSN is on line 1; email is on line 2.  Approve only the line-1 replacements.
    line_one_only = [r for r in all_replacements if r.line_number == 1]

    result = apply_approved_replacements(target_file, line_one_only)
    modified_content = target_file.read_text(encoding=DEFAULT_TEXT_ENCODING)

    assert len(result.replacements_applied) == len(line_one_only)
    assert _SSN_VALUE not in modified_content
    # The email on line 2 was NOT approved — it must remain.
    assert _EMAIL_VALUE in modified_content


def test_apply_approved_replacements_with_empty_list_does_not_modify_file(
    tmp_path: Path,
) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)
    original_content = target_file.read_text(encoding=DEFAULT_TEXT_ENCODING)

    result = apply_approved_replacements(target_file, [])

    assert result.replacements_applied == ()
    assert target_file.read_text(encoding=DEFAULT_TEXT_ENCODING) == original_content


def test_apply_approved_replacements_returns_unified_diff(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)
    all_replacements = collect_file_replacements(target_file)

    result = apply_approved_replacements(target_file, all_replacements)

    assert _DIFF_HUNK_MARKER in result.unified_diff


# ---------------------------------------------------------------------------
# Additional correctness tests
# ---------------------------------------------------------------------------


def test_collect_file_replacements_returns_empty_list_for_clean_file(
    tmp_path: Path,
) -> None:
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(_CLEAN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    replacements = collect_file_replacements(clean_file)

    assert replacements == []


def test_fix_result_patch_path_is_none_for_dry_run(tmp_path: Path) -> None:
    target_file = tmp_path / "patient.py"
    target_file.write_text(_SSN_LINE, encoding=DEFAULT_TEXT_ENCODING)

    result = fix_file(target_file, FixMode.DRY_RUN)

    assert result.patch_path is None


def test_fix_replacement_is_immutable() -> None:
    replacement = FixReplacement(
        line_number=1,
        start_column=0,
        end_column=5,
        synthetic_text="world",
        hipaa_category=PhiCategory.NAME,
    )

    with pytest.raises((TypeError, AttributeError)):
        replacement.line_number = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Structural safety — threat-model F-3 (P0)
# ---------------------------------------------------------------------------


def _collect_attribute_chain(node: ast.Attribute) -> tuple[str, ...]:
    """Return the dotted-name tuple for a chain like ``os.system`` or ``a.b.c``.

    Non-Name roots (subscripts, calls, etc.) return an empty tuple — those
    cannot match the static banned-chain list and are not a concern for
    this structural check.
    """
    chain: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return ()
    chain.append(current.id)
    return tuple(reversed(chain))


def _find_fixer_module_safety_violations(module_source: str) -> list[str]:
    violations: list[str] = []
    tree = ast.parse(module_source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _FIXER_BANNED_IMPORT_MODULE_NAMES:
                    violations.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module in _FIXER_BANNED_IMPORT_MODULE_NAMES:
                violations.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _FIXER_BANNED_CALL_NAMES:
                violations.append(f"{func.id}(...)")
            elif isinstance(func, ast.Attribute):
                chain = _collect_attribute_chain(func)
                if chain in _FIXER_BANNED_ATTRIBUTE_CHAINS:
                    violations.append(".".join(chain) + "(...)")
    return violations


def test_fixer_module_contains_no_dynamic_code_execution() -> None:
    """Structural regression gate for threat-model row F-3 (P0).

    The fixer must remain pure Python text replacement. This test parses
    ``phi_scan/fixer.py`` with ``ast`` and fails if any banned import,
    banned call name, or banned attribute chain appears anywhere in the
    module. Any future change that introduces ``subprocess``, ``eval``,
    ``exec``, ``os.system``, dynamic import, or similar code-execution
    primitives will fail this gate and require an explicit security
    review — not a silent merge.
    """
    module_source = _FIXER_MODULE_PATH.read_text(encoding=DEFAULT_TEXT_ENCODING)
    violations = _find_fixer_module_safety_violations(module_source)
    assert not violations, (
        "phi_scan/fixer.py introduced code-execution primitives banned by "
        "threat-model row F-3 (P0). Violations: "
        f"{violations}. Any such change requires a security review and an "
        "update to docs/threat-model.md before merge."
    )
