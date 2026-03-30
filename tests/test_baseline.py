"""Tests for phi_scan.baseline — baseline snapshot management."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phi_scan.baseline import (
    BaselineEntry,
    BaselineSnapshot,
    BaselineSummary,
    compute_baseline_diff,
    create_baseline,
    detect_baseline_drift,
    filter_baselined_findings,
    get_baseline_summary,
    is_finding_baselined,
    load_baseline,
)
from phi_scan.constants import (
    BASELINE_DRIFT_WARNING_PERCENT,
    BASELINE_SCHEMA_VERSION,
    DEFAULT_BASELINE_MAX_AGE_DAYS,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import BaselineError
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAKE_VALUE_HASH: str = hashlib.sha256(b"baseline-test-value").hexdigest()
_FAKE_ALT_VALUE_HASH: str = hashlib.sha256(b"baseline-other-value").hexdigest()
_FAKE_ENTITY_TYPE: str = "us_ssn"
_FAKE_ALT_ENTITY_TYPE: str = "email"
_FAKE_CODE_CONTEXT: str = 'ssn = "123-45-6789"'
_FAKE_REMEDIATION_HINT: str = "Replace with synthetic value."

_FINDING_FILE_PATH: Path = Path("src/api/patient.py")
_OTHER_FILE_PATH: Path = Path("src/utils/seed.py")

_BASELINE_SCHEMA_VERSION_ZERO: int = 0

# A fixed timezone-aware "now" used across tests to make expiry calculations
# deterministic without depending on wall-clock time.
_FIXED_NOW: datetime = datetime(2026, 3, 29, 12, 0, 0, tzinfo=UTC)
_NEAR_FUTURE: datetime = _FIXED_NOW + timedelta(days=1)
_FAR_FUTURE: datetime = _FIXED_NOW + timedelta(days=DEFAULT_BASELINE_MAX_AGE_DAYS)
_PAST: datetime = _FIXED_NOW - timedelta(seconds=1)


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _make_finding(
    file_path: Path = _FINDING_FILE_PATH,
    entity_type: str = _FAKE_ENTITY_TYPE,
    value_hash: str = _FAKE_VALUE_HASH,
    line_number: int = 1,
) -> ScanFinding:
    return ScanFinding(
        file_path=file_path,
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=PhiCategory.SSN,
        confidence=0.95,
        detection_layer=DetectionLayer.REGEX,
        value_hash=value_hash,
        severity=SeverityLevel.HIGH,
        code_context=_FAKE_CODE_CONTEXT,
        remediation_hint=_FAKE_REMEDIATION_HINT,
    )


def _make_entry(
    file_path: Path = _FINDING_FILE_PATH,
    entity_type: str = _FAKE_ENTITY_TYPE,
    value_hash: str = _FAKE_VALUE_HASH,
    expires_at: datetime = _FAR_FUTURE,
    created_at: datetime = _FIXED_NOW,
) -> BaselineEntry:
    return BaselineEntry(
        file_path=file_path,
        line_number=1,
        line_content_hash=hashlib.sha256(_FAKE_CODE_CONTEXT.encode()).hexdigest(),
        entity_type=entity_type,
        hipaa_category=PhiCategory.SSN,
        value_hash=value_hash,
        severity=SeverityLevel.HIGH,
        created_at=created_at,
        expires_at=expires_at,
    )


def _make_snapshot(
    entries: tuple[BaselineEntry, ...] = (),
    max_age_days: int = DEFAULT_BASELINE_MAX_AGE_DAYS,
) -> BaselineSnapshot:
    return BaselineSnapshot(
        entries=entries,
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at=_FIXED_NOW,
        scanner_version="0.1.0",
        baseline_max_age_days=max_age_days,
    )


def _make_scan_result(findings: tuple[ScanFinding, ...] = ()) -> ScanResult:
    from types import MappingProxyType

    from phi_scan.constants import RiskLevel

    is_clean = len(findings) == 0
    risk = RiskLevel.CLEAN if is_clean else RiskLevel.CRITICAL
    return ScanResult(
        findings=findings,
        files_scanned=1,
        files_with_findings=0 if is_clean else 1,
        scan_duration=0.1,
        is_clean=is_clean,
        risk_level=risk,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )


# ---------------------------------------------------------------------------
# load_baseline — file missing
# ---------------------------------------------------------------------------


class TestLoadBaselineReturnsNoneForMissingFile:
    def test_returns_none_when_baseline_file_does_not_exist(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.phi-scanbaseline"

        result = load_baseline(baseline_path=missing)

        assert result is None


# ---------------------------------------------------------------------------
# create_baseline / save_baseline / load_baseline round-trip
# ---------------------------------------------------------------------------


class TestCreateBaseline:
    def test_creates_baseline_file(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        finding = _make_finding()
        scan_result = _make_scan_result((finding,))

        create_baseline(scan_result, baseline_path=baseline_file)

        assert baseline_file.exists()

    def test_created_snapshot_has_one_entry_per_finding(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        findings = (_make_finding(), _make_finding(_OTHER_FILE_PATH))
        scan_result = _make_scan_result(findings)

        snapshot = create_baseline(scan_result, baseline_path=baseline_file)

        assert len(snapshot.entries) == len(findings)

    def test_creates_empty_baseline_for_clean_scan(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        scan_result = _make_scan_result(())

        snapshot = create_baseline(scan_result, baseline_path=baseline_file)

        assert len(snapshot.entries) == 0
        assert baseline_file.exists()

    def test_entry_expires_after_max_age_days(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        max_age = 30
        scan_result = _make_scan_result((_make_finding(),))

        snapshot = create_baseline(scan_result, max_age, baseline_path=baseline_file)

        entry = snapshot.entries[0]
        age = (entry.expires_at - entry.created_at).days
        assert age == max_age

    def test_entry_preserves_file_path(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        finding = _make_finding(file_path=_FINDING_FILE_PATH)
        scan_result = _make_scan_result((finding,))

        snapshot = create_baseline(scan_result, baseline_path=baseline_file)

        assert snapshot.entries[0].file_path == _FINDING_FILE_PATH

    def test_entry_preserves_value_hash(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        finding = _make_finding(value_hash=_FAKE_VALUE_HASH)
        scan_result = _make_scan_result((finding,))

        snapshot = create_baseline(scan_result, baseline_path=baseline_file)

        assert snapshot.entries[0].value_hash == _FAKE_VALUE_HASH

    def test_snapshot_schema_version_is_current(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        scan_result = _make_scan_result((_make_finding(),))

        snapshot = create_baseline(scan_result, baseline_path=baseline_file)

        assert snapshot.schema_version == BASELINE_SCHEMA_VERSION


class TestLoadBaselineRoundTrip:
    def test_saved_and_loaded_snapshot_has_same_entry_count(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        findings = (_make_finding(), _make_finding(_OTHER_FILE_PATH))
        scan_result = _make_scan_result(findings)
        create_baseline(scan_result, baseline_path=baseline_file)

        loaded = load_baseline(baseline_path=baseline_file)

        assert loaded is not None
        assert len(loaded.entries) == len(findings)

    def test_saved_and_loaded_entry_preserves_file_path(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        finding = _make_finding(file_path=_FINDING_FILE_PATH)
        create_baseline(_make_scan_result((finding,)), baseline_path=baseline_file)

        loaded = load_baseline(baseline_path=baseline_file)

        assert loaded is not None
        assert loaded.entries[0].file_path == _FINDING_FILE_PATH

    def test_saved_and_loaded_entry_preserves_value_hash(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        finding = _make_finding(value_hash=_FAKE_VALUE_HASH)
        create_baseline(_make_scan_result((finding,)), baseline_path=baseline_file)

        loaded = load_baseline(baseline_path=baseline_file)

        assert loaded is not None
        assert loaded.entries[0].value_hash == _FAKE_VALUE_HASH

    def test_saved_and_loaded_entry_preserves_expires_at_date(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        max_age = 45
        create_baseline(_make_scan_result((_make_finding(),)), max_age, baseline_path=baseline_file)

        loaded = load_baseline(baseline_path=baseline_file)

        assert loaded is not None
        age_days = (loaded.entries[0].expires_at - loaded.entries[0].created_at).days
        assert age_days == max_age

    def test_raises_baseline_error_for_malformed_yaml(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".phi-scanbaseline"
        baseline_file.write_text(": :\n  - bad: [yaml", encoding="utf-8")

        with pytest.raises(BaselineError):
            load_baseline(baseline_path=baseline_file)

    def test_raises_baseline_error_for_wrong_schema_version(self, tmp_path: Path) -> None:
        import yaml as _yaml

        baseline_file = tmp_path / ".phi-scanbaseline"
        baseline_file.write_text(
            _yaml.safe_dump({"schema_version": _BASELINE_SCHEMA_VERSION_ZERO, "entries": []}),
            encoding="utf-8",
        )

        with pytest.raises(BaselineError, match="schema version"):
            load_baseline(baseline_path=baseline_file)


# ---------------------------------------------------------------------------
# is_finding_baselined
# ---------------------------------------------------------------------------


class TestIsFindingBaselined:
    def test_finding_in_active_baseline_is_baselined(self) -> None:
        entry = _make_entry(expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding()

        assert is_finding_baselined(finding, snapshot) is True

    def test_finding_not_in_baseline_is_not_baselined(self) -> None:
        entry = _make_entry(value_hash=_FAKE_ALT_VALUE_HASH, expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding(value_hash=_FAKE_VALUE_HASH)

        assert is_finding_baselined(finding, snapshot) is False

    def test_expired_entry_is_not_baselined(self) -> None:
        entry = _make_entry(expires_at=_PAST)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding()

        assert is_finding_baselined(finding, snapshot) is False

    def test_different_file_is_not_baselined(self) -> None:
        entry = _make_entry(file_path=_OTHER_FILE_PATH, expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding(file_path=_FINDING_FILE_PATH)

        assert is_finding_baselined(finding, snapshot) is False

    def test_different_entity_type_is_not_baselined(self) -> None:
        entry = _make_entry(entity_type=_FAKE_ALT_ENTITY_TYPE, expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding(entity_type=_FAKE_ENTITY_TYPE)

        assert is_finding_baselined(finding, snapshot) is False

    def test_empty_snapshot_finding_is_not_baselined(self) -> None:
        snapshot = _make_snapshot(())
        finding = _make_finding()

        assert is_finding_baselined(finding, snapshot) is False


# ---------------------------------------------------------------------------
# filter_baselined_findings
# ---------------------------------------------------------------------------


class TestFilterBaselinedFindings:
    def test_new_finding_not_in_snapshot_goes_to_new(self) -> None:
        snapshot = _make_snapshot(())
        finding = _make_finding()

        new_findings, baselined = filter_baselined_findings([finding], snapshot)

        assert finding in new_findings
        assert finding not in baselined

    def test_matched_finding_goes_to_baselined(self) -> None:
        entry = _make_entry(expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding()

        new_findings, baselined = filter_baselined_findings([finding], snapshot)

        assert finding in baselined
        assert finding not in new_findings

    def test_expired_entry_makes_finding_new(self) -> None:
        entry = _make_entry(expires_at=_PAST)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding()

        new_findings, baselined = filter_baselined_findings([finding], snapshot)

        assert finding in new_findings
        assert finding not in baselined

    def test_empty_findings_returns_two_empty_lists(self) -> None:
        snapshot = _make_snapshot((_make_entry(expires_at=_FAR_FUTURE),))

        new_findings, baselined = filter_baselined_findings([], snapshot)

        assert new_findings == []
        assert baselined == []

    def test_mixed_findings_split_correctly(self) -> None:
        entry = _make_entry(expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        baselined_finding = _make_finding()
        new_finding = _make_finding(value_hash=_FAKE_ALT_VALUE_HASH)

        new_findings, baselined = filter_baselined_findings(
            [baselined_finding, new_finding], snapshot
        )

        assert new_finding in new_findings
        assert baselined_finding in baselined


# ---------------------------------------------------------------------------
# compute_baseline_diff
# ---------------------------------------------------------------------------


class TestComputeBaselineDiff:
    def test_new_finding_not_in_baseline_is_in_new_findings(self) -> None:
        snapshot = _make_snapshot(())
        finding = _make_finding()
        scan_result = _make_scan_result((finding,))

        diff = compute_baseline_diff(snapshot, scan_result)

        assert finding in diff.new_findings

    def test_resolved_entry_not_in_scan_is_in_resolved(self) -> None:
        entry = _make_entry(expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        scan_result = _make_scan_result(())

        diff = compute_baseline_diff(snapshot, scan_result)

        assert entry in diff.resolved_entries

    def test_persisting_finding_in_both_is_in_persisting(self) -> None:
        entry = _make_entry(expires_at=_FAR_FUTURE)
        snapshot = _make_snapshot((entry,))
        finding = _make_finding()
        scan_result = _make_scan_result((finding,))

        diff = compute_baseline_diff(snapshot, scan_result)

        assert finding in diff.persisting_findings
        assert finding not in diff.new_findings

    def test_empty_scan_all_active_entries_are_resolved(self) -> None:
        entries = (
            _make_entry(expires_at=_FAR_FUTURE),
            _make_entry(file_path=_OTHER_FILE_PATH, expires_at=_FAR_FUTURE),
        )
        snapshot = _make_snapshot(entries)
        scan_result = _make_scan_result(())

        diff = compute_baseline_diff(snapshot, scan_result)

        assert len(diff.resolved_entries) == len(entries)

    def test_expired_entries_not_counted_as_resolved(self) -> None:
        entry = _make_entry(expires_at=_PAST)
        snapshot = _make_snapshot((entry,))
        scan_result = _make_scan_result(())

        diff = compute_baseline_diff(snapshot, scan_result)

        # An expired entry that's also absent from the scan should NOT appear as
        # "resolved" — it was already inactive due to expiry, not remediation.
        assert entry not in diff.resolved_entries


# ---------------------------------------------------------------------------
# get_baseline_summary
# ---------------------------------------------------------------------------


class TestGetBaselineSummary:
    def test_total_entries_count_matches_snapshot(self) -> None:
        entries = (_make_entry(expires_at=_FAR_FUTURE), _make_entry(expires_at=_PAST))
        snapshot = _make_snapshot(entries)

        summary = get_baseline_summary(snapshot, Path(".phi-scanbaseline"))

        assert summary.total_entries == len(entries)

    def test_active_entries_excludes_expired(self) -> None:
        active_entry = _make_entry(expires_at=_FAR_FUTURE)
        expired_entry = _make_entry(expires_at=_PAST)
        snapshot = _make_snapshot((active_entry, expired_entry))

        summary = get_baseline_summary(snapshot, Path(".phi-scanbaseline"))

        assert summary.active_entries == 1
        assert summary.expired_entries == 1

    def test_category_counts_active_entries_only(self) -> None:
        active_entry = _make_entry(expires_at=_FAR_FUTURE)
        expired_entry = _make_entry(expires_at=_PAST)
        snapshot = _make_snapshot((active_entry, expired_entry))

        summary = get_baseline_summary(snapshot, Path(".phi-scanbaseline"))

        # Only the active entry should be counted
        assert summary.category_counts.get(PhiCategory.SSN, 0) == 1

    def test_baseline_path_stored_in_summary(self) -> None:
        expected_path = Path("my/.phi-scanbaseline")
        snapshot = _make_snapshot(())

        summary = get_baseline_summary(snapshot, expected_path)

        assert summary.baseline_path == expected_path

    def test_returns_baseline_summary_dataclass(self) -> None:
        snapshot = _make_snapshot(())

        summary = get_baseline_summary(snapshot, Path(".phi-scanbaseline"))

        assert isinstance(summary, BaselineSummary)


# ---------------------------------------------------------------------------
# detect_baseline_drift
# ---------------------------------------------------------------------------


class TestCheckBaselineDrift:
    def test_no_drift_when_count_unchanged(self) -> None:
        entry = _make_entry()
        old_snapshot = _make_snapshot((entry,))
        new_snapshot = _make_snapshot((entry,))

        assert detect_baseline_drift(old_snapshot, new_snapshot) == 0

    def test_positive_drift_when_entries_increase(self) -> None:
        old_entry = _make_entry()
        new_entry = _make_entry(file_path=_OTHER_FILE_PATH)
        old_snapshot = _make_snapshot((old_entry,))
        new_snapshot = _make_snapshot((old_entry, new_entry))

        drift = detect_baseline_drift(old_snapshot, new_snapshot)

        assert drift == 100

    def test_negative_drift_when_entries_decrease(self) -> None:
        entry_a = _make_entry()
        entry_b = _make_entry(file_path=_OTHER_FILE_PATH)
        old_snapshot = _make_snapshot((entry_a, entry_b))
        new_snapshot = _make_snapshot((entry_a,))

        drift = detect_baseline_drift(old_snapshot, new_snapshot)

        assert drift == -50

    def test_returns_zero_when_old_snapshot_is_empty(self) -> None:
        old_snapshot = _make_snapshot(())
        new_snapshot = _make_snapshot((_make_entry(),))

        assert detect_baseline_drift(old_snapshot, new_snapshot) == 0

    def test_drift_above_warning_threshold_is_detectable(self) -> None:
        # Construct a scenario where drift exceeds BASELINE_DRIFT_WARNING_PERCENT.
        # With 1 old entry → 2 new entries, drift = 100% which exceeds 20%.
        old_entry = _make_entry()
        new_entry = _make_entry(file_path=_OTHER_FILE_PATH)
        old_snapshot = _make_snapshot((old_entry,))
        new_snapshot = _make_snapshot((old_entry, new_entry))

        drift = detect_baseline_drift(old_snapshot, new_snapshot)

        assert drift > BASELINE_DRIFT_WARNING_PERCENT
