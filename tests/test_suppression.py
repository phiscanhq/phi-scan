"""Tests for phi_scan.suppression — inline suppression comment parser."""

from __future__ import annotations

import hashlib
from pathlib import Path

from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.models import ScanFinding
from phi_scan.suppression import is_finding_suppressed, load_suppressions

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPRESS_ALL_SENTINEL: str = "*"
_SUPPRESS_FILE_SENTINEL_LINE: int = -1

_ENTITY_TYPE_SSN: str = "SSN"
_ENTITY_TYPE_MRN: str = "MRN"
_ENTITY_TYPE_EMAIL: str = "EMAIL"

_LINE_1: int = 1
_LINE_2: int = 2
_LINE_3: int = 3
_LINE_5: int = 5
_LINE_6: int = 6

_FAKE_VALUE_HASH: str = hashlib.sha256(b"test-value").hexdigest()
_FAKE_FILE_PATH: Path = Path("test_file.py")
_FAKE_CODE_CONTEXT: str = "ssn = '[REDACTED]'"
_FAKE_REMEDIATION_HINT: str = "Remove SSN."


def _make_finding(
    entity_type: str = _ENTITY_TYPE_SSN,
    line_number: int = _LINE_1,
) -> ScanFinding:
    return ScanFinding(
        file_path=_FAKE_FILE_PATH,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_FAKE_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_FAKE_CODE_CONTEXT,
        remediation_hint=_FAKE_REMEDIATION_HINT,
    )


# ---------------------------------------------------------------------------
# load_suppressions — line-level ignore
# ---------------------------------------------------------------------------


class TestLoadSuppressionsIgnoreLine:
    def test_hash_suppress_all_on_same_line(self) -> None:
        lines = ['ssn = "123-45-6789"  # phi-scan:ignore\n']

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_SUPPRESS_ALL_SENTINEL}

    def test_double_slash_suppress_all_on_same_line(self) -> None:
        lines = ['var ssn = "123-45-6789";  // phi-scan:ignore\n']

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_SUPPRESS_ALL_SENTINEL}

    def test_sql_suppress_all_on_same_line(self) -> None:
        lines = ["SELECT ssn FROM patients -- phi-scan:ignore\n"]

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_SUPPRESS_ALL_SENTINEL}

    def test_html_suppress_all_on_same_line(self) -> None:
        lines = ["<!-- phi-scan:ignore -->\n"]

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_SUPPRESS_ALL_SENTINEL}

    def test_typed_ignore_single_entity_type(self) -> None:
        lines = ['ssn = "123-45-6789"  # phi-scan:ignore[SSN]\n']

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_ENTITY_TYPE_SSN}

    def test_typed_ignore_multiple_entity_types(self) -> None:
        lines = ["record = data  # phi-scan:ignore[SSN,MRN]\n"]

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_1] == {_ENTITY_TYPE_SSN, _ENTITY_TYPE_MRN}

    def test_typed_ignore_normalises_to_uppercase(self) -> None:
        lines = ['ssn = "val"  # phi-scan:ignore[ssn]\n']

        suppression_map = load_suppressions(lines)

        assert _ENTITY_TYPE_SSN in suppression_map[_LINE_1]

    def test_unrelated_line_not_in_suppression_map(self) -> None:
        lines = ['ssn = "123-45-6789"\n']

        suppression_map = load_suppressions(lines)

        assert _LINE_1 not in suppression_map


class TestLoadSuppressionsIgnoreNextLine:
    def test_ignore_next_line_targets_following_line(self) -> None:
        lines = [
            "# phi-scan:ignore-next-line\n",
            'ssn = "123-45-6789"\n',
        ]

        suppression_map = load_suppressions(lines)

        assert _LINE_2 in suppression_map
        assert suppression_map[_LINE_2] == {_SUPPRESS_ALL_SENTINEL}

    def test_ignore_next_line_does_not_suppress_directive_line_itself(self) -> None:
        lines = [
            "# phi-scan:ignore-next-line\n",
            'ssn = "123-45-6789"\n',
        ]

        suppression_map = load_suppressions(lines)

        assert _LINE_1 not in suppression_map

    def test_double_slash_ignore_next_line(self) -> None:
        lines = [
            "// phi-scan:ignore-next-line\n",
            'var ssn = "123-45-6789";\n',
        ]

        suppression_map = load_suppressions(lines)

        assert suppression_map[_LINE_2] == {_SUPPRESS_ALL_SENTINEL}


class TestLoadSuppressionsIgnoreFile:
    def test_ignore_file_in_first_line_returns_sentinel(self) -> None:
        lines = [
            "# phi-scan:ignore-file\n",
            'ssn = "123-45-6789"\n',
        ]

        suppression_map = load_suppressions(lines)

        assert _SUPPRESS_FILE_SENTINEL_LINE in suppression_map

    def test_ignore_file_in_fifth_line_is_accepted(self) -> None:
        lines = [
            "# line 1\n",
            "# line 2\n",
            "# line 3\n",
            "# line 4\n",
            "# phi-scan:ignore-file\n",
            'ssn = "123-45-6789"\n',
        ]

        suppression_map = load_suppressions(lines)

        assert _SUPPRESS_FILE_SENTINEL_LINE in suppression_map

    def test_ignore_file_after_fifth_line_is_ignored(self) -> None:
        lines = [
            "# line 1\n",
            "# line 2\n",
            "# line 3\n",
            "# line 4\n",
            "# line 5\n",
            "# phi-scan:ignore-file\n",  # line 6 — too late
        ]

        suppression_map = load_suppressions(lines)

        assert _SUPPRESS_FILE_SENTINEL_LINE not in suppression_map

    def test_ignore_file_short_circuits_remaining_parsing(self) -> None:
        lines = [
            "# phi-scan:ignore-file\n",
            'ssn = "123-45-6789"  # phi-scan:ignore\n',
        ]

        suppression_map = load_suppressions(lines)

        # Only the file sentinel should be present — per-line entries are not
        # generated because parsing stops at the file-level directive.
        assert list(suppression_map.keys()) == [_SUPPRESS_FILE_SENTINEL_LINE]


class TestLoadSuppressionsEmptyInput:
    def test_empty_file_returns_empty_map(self) -> None:
        suppression_map = load_suppressions([])

        assert suppression_map == {}

    def test_file_with_no_directives_returns_empty_map(self) -> None:
        lines = ["greeting = 'hello world'\n", "x = 1\n"]

        suppression_map = load_suppressions(lines)

        assert suppression_map == {}


# ---------------------------------------------------------------------------
# is_finding_suppressed
# ---------------------------------------------------------------------------


class TestIsFindingSuppressed:
    def test_suppressed_when_file_sentinel_present(self) -> None:
        finding = _make_finding(line_number=_LINE_3)
        suppression_map = {_SUPPRESS_FILE_SENTINEL_LINE: {_SUPPRESS_ALL_SENTINEL}}

        assert is_finding_suppressed(finding, suppression_map) is True

    def test_suppressed_when_all_sentinel_on_same_line(self) -> None:
        finding = _make_finding(line_number=_LINE_1)
        suppression_map = {_LINE_1: {_SUPPRESS_ALL_SENTINEL}}

        assert is_finding_suppressed(finding, suppression_map) is True

    def test_suppressed_when_entity_type_listed_on_same_line(self) -> None:
        finding = _make_finding(entity_type=_ENTITY_TYPE_SSN, line_number=_LINE_1)
        suppression_map = {_LINE_1: {_ENTITY_TYPE_SSN}}

        assert is_finding_suppressed(finding, suppression_map) is True

    def test_not_suppressed_when_different_entity_type_listed(self) -> None:
        finding = _make_finding(entity_type=_ENTITY_TYPE_EMAIL, line_number=_LINE_1)
        suppression_map = {_LINE_1: {_ENTITY_TYPE_SSN}}

        assert is_finding_suppressed(finding, suppression_map) is False

    def test_not_suppressed_when_line_not_in_map(self) -> None:
        finding = _make_finding(line_number=_LINE_2)
        suppression_map = {_LINE_1: {_SUPPRESS_ALL_SENTINEL}}

        assert is_finding_suppressed(finding, suppression_map) is False

    def test_not_suppressed_when_suppression_map_empty(self) -> None:
        finding = _make_finding(line_number=_LINE_1)

        assert is_finding_suppressed(finding, {}) is False

    def test_entity_type_check_is_case_insensitive(self) -> None:
        finding = _make_finding(entity_type="ssn", line_number=_LINE_1)
        suppression_map = {_LINE_1: {_ENTITY_TYPE_SSN}}

        assert is_finding_suppressed(finding, suppression_map) is True

    def test_suppressed_when_one_of_multiple_types_matches(self) -> None:
        finding = _make_finding(entity_type=_ENTITY_TYPE_MRN, line_number=_LINE_1)
        suppression_map = {_LINE_1: {_ENTITY_TYPE_SSN, _ENTITY_TYPE_MRN}}

        assert is_finding_suppressed(finding, suppression_map) is True
