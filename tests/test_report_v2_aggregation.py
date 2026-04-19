"""Tests for the v2 report aggregation layer."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from phi_scan.constants import PhiCategory, RiskLevel, SeverityLevel
from phi_scan.models import ScanFinding, ScanResult
from phi_scan.report.v2.aggregation import (
    build_line_title,
    compute_category_severity_distribution,
    compute_hotspot_count,
    dedupe_remediations,
    group_by_file,
    group_by_line,
    rank_top_actions,
)

_HASH_PLACEHOLDER: str = "a" * 64


def _make_finding(
    file_path: str = "test.py",
    line_number: int = 1,
    entity_type: str = "SSN",
    hipaa_category: PhiCategory = PhiCategory.SSN,
    confidence: float = 0.9,
    severity: SeverityLevel = SeverityLevel.HIGH,
    remediation_hint: str = "Remove SSN",
    code_context: str = "SSN: [REDACTED]",
) -> ScanFinding:
    return ScanFinding(
        file_path=Path(file_path),
        line_number=line_number,
        entity_type=entity_type,
        hipaa_category=hipaa_category,
        confidence=confidence,
        detection_layer="regex",
        value_hash=_HASH_PLACEHOLDER,
        severity=severity,
        code_context=code_context,
        remediation_hint=remediation_hint,
    )


def _make_scan_result(findings: list[ScanFinding]) -> ScanResult:
    severity_counts: dict[SeverityLevel, int] = {}
    category_counts: dict[PhiCategory, int] = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        category_counts[finding.hipaa_category] = category_counts.get(finding.hipaa_category, 0) + 1
    is_clean = len(findings) == 0
    return ScanResult(
        findings=tuple(findings),
        files_scanned=1,
        files_with_findings=0 if is_clean else 1,
        scan_duration=0.05,
        is_clean=is_clean,
        risk_level=RiskLevel.CLEAN if is_clean else RiskLevel.CRITICAL,
        severity_counts=MappingProxyType(severity_counts),
        category_counts=MappingProxyType(category_counts),
    )


class TestGroupByLine:
    def test_groups_findings_on_same_line(self) -> None:
        findings = (
            _make_finding(line_number=1, entity_type="SSN"),
            _make_finding(line_number=1, entity_type="DATE", hipaa_category=PhiCategory.DATE),
            _make_finding(line_number=2, entity_type="EMAIL", hipaa_category=PhiCategory.EMAIL),
        )
        aggregates = group_by_line(findings)
        assert len(aggregates) == 2
        line_1 = [a for a in aggregates if a.line_number == 1][0]
        assert line_1.finding_count == 2
        assert "SSN" in line_1.category_counts
        assert "DATE" in line_1.category_counts

    def test_highest_severity_is_correct(self) -> None:
        findings = (
            _make_finding(line_number=1, severity=SeverityLevel.LOW),
            _make_finding(line_number=1, severity=SeverityLevel.HIGH),
        )
        aggregates = group_by_line(findings)
        assert aggregates[0].highest_severity == SeverityLevel.HIGH

    def test_category_counts_track_duplicates(self) -> None:
        findings = (
            _make_finding(line_number=1, entity_type="ACCOUNT_NUMBER"),
            _make_finding(line_number=1, entity_type="ACCOUNT_NUMBER"),
            _make_finding(line_number=1, entity_type="SSN"),
        )
        aggregates = group_by_line(findings)
        assert aggregates[0].category_counts["ACCOUNT_NUMBER"] == 2
        assert aggregates[0].category_counts["SSN"] == 1

    def test_combined_fix_deduplicates(self) -> None:
        findings = (
            _make_finding(line_number=1, remediation_hint="Fix A"),
            _make_finding(line_number=1, remediation_hint="Fix A"),
            _make_finding(line_number=1, remediation_hint="Fix B"),
        )
        aggregates = group_by_line(findings)
        assert aggregates[0].combined_fix == "Fix A; Fix B"


class TestGroupByFile:
    def test_groups_by_file_path(self) -> None:
        findings = (
            _make_finding(file_path="a.py", line_number=1),
            _make_finding(file_path="a.py", line_number=2),
            _make_finding(file_path="b.py", line_number=1),
        )
        line_aggregates = group_by_line(findings)
        file_aggregates = group_by_file(line_aggregates)
        assert len(file_aggregates) == 2
        assert file_aggregates[0].file_path == Path("a.py")
        assert file_aggregates[1].file_path == Path("b.py")

    def test_lines_sorted_by_severity_then_count_then_line(self) -> None:
        findings = (
            _make_finding(file_path="a.py", line_number=10, severity=SeverityLevel.LOW),
            _make_finding(file_path="a.py", line_number=5, severity=SeverityLevel.HIGH),
            _make_finding(file_path="a.py", line_number=1, severity=SeverityLevel.HIGH),
            _make_finding(file_path="a.py", line_number=1, severity=SeverityLevel.HIGH),
        )
        line_aggregates = group_by_line(findings)
        file_aggregates = group_by_file(line_aggregates)
        lines = file_aggregates[0].line_aggregates
        assert lines[0].line_number == 1
        assert lines[1].line_number == 5
        assert lines[2].line_number == 10


class TestDedupeRemediations:
    def test_groups_by_remediation_hint(self) -> None:
        findings = (
            _make_finding(line_number=1, remediation_hint="Remove SSN"),
            _make_finding(line_number=2, remediation_hint="Remove SSN"),
            _make_finding(line_number=3, remediation_hint="Fix dates"),
        )
        actions = dedupe_remediations(findings)
        assert len(actions) == 2
        ssn_action = [a for a in actions if a.remediation_hint == "Remove SSN"][0]
        assert ssn_action.finding_count == 2

    def test_no_duplicate_remediation_strings(self) -> None:
        findings = (
            _make_finding(remediation_hint="Hint A"),
            _make_finding(remediation_hint="Hint A"),
            _make_finding(remediation_hint="Hint B"),
            _make_finding(remediation_hint="Hint B"),
            _make_finding(remediation_hint="Hint C"),
        )
        actions = dedupe_remediations(findings)
        hints = [a.remediation_hint for a in actions]
        assert len(hints) == len(set(hints))

    def test_sorted_by_severity_then_count(self) -> None:
        findings = (
            _make_finding(line_number=1, severity=SeverityLevel.LOW, remediation_hint="Low fix"),
            _make_finding(line_number=2, severity=SeverityLevel.HIGH, remediation_hint="High fix"),
        )
        actions = dedupe_remediations(findings)
        assert actions[0].remediation_hint == "High fix"
        assert actions[1].remediation_hint == "Low fix"

    def test_mean_confidence(self) -> None:
        findings = (
            _make_finding(confidence=0.8, remediation_hint="Fix"),
            _make_finding(confidence=0.6, remediation_hint="Fix"),
        )
        actions = dedupe_remediations(findings)
        assert abs(actions[0].mean_confidence - 0.7) < 0.001

    def test_affected_lines_deduplicated(self) -> None:
        findings = (
            _make_finding(line_number=1, remediation_hint="Fix"),
            _make_finding(line_number=1, remediation_hint="Fix"),
            _make_finding(line_number=2, remediation_hint="Fix"),
        )
        actions = dedupe_remediations(findings)
        assert len(actions[0].affected_lines) == 2


class TestRankTopActions:
    def test_returns_top_5(self) -> None:
        findings = tuple(
            _make_finding(remediation_hint=f"Fix {i}", line_number=i) for i in range(1, 8)
        )
        actions = dedupe_remediations(findings)
        top = rank_top_actions(actions)
        assert len(top) <= 5

    def test_ranked_by_severity_weight_score(self) -> None:
        findings = (
            _make_finding(
                line_number=1,
                severity=SeverityLevel.HIGH,
                remediation_hint="High",
            ),
            _make_finding(
                line_number=2,
                severity=SeverityLevel.LOW,
                remediation_hint="Low 1",
            ),
            _make_finding(
                line_number=3,
                severity=SeverityLevel.LOW,
                remediation_hint="Low 2",
            ),
        )
        actions = dedupe_remediations(findings)
        top = rank_top_actions(actions)
        assert top[0].remediation_hint == "High"


class TestHotspotCount:
    def test_counts_lines_with_multiple_categories(self) -> None:
        findings = (
            _make_finding(line_number=1, entity_type="SSN"),
            _make_finding(
                line_number=1,
                entity_type="DATE",
                hipaa_category=PhiCategory.DATE,
            ),
            _make_finding(line_number=2, entity_type="SSN"),
        )
        aggregates = group_by_line(findings)
        assert compute_hotspot_count(aggregates) == 1


class TestCategorySeverityDistribution:
    def test_builds_per_category_distribution(self) -> None:
        findings = (
            _make_finding(hipaa_category=PhiCategory.SSN, severity=SeverityLevel.HIGH),
            _make_finding(hipaa_category=PhiCategory.SSN, severity=SeverityLevel.MEDIUM),
            _make_finding(hipaa_category=PhiCategory.EMAIL, severity=SeverityLevel.LOW),
        )
        distribution = compute_category_severity_distribution(findings)
        assert distribution["ssn"][SeverityLevel.HIGH] == 1
        assert distribution["ssn"][SeverityLevel.MEDIUM] == 1
        assert distribution["email"][SeverityLevel.LOW] == 1


class TestBuildLineTitle:
    def test_sweeney_risk_title(self) -> None:
        findings = (
            _make_finding(
                line_number=1,
                entity_type="DATE",
                hipaa_category=PhiCategory.DATE,
            ),
            _make_finding(
                line_number=1,
                entity_type="GEOGRAPHIC",
                hipaa_category=PhiCategory.GEOGRAPHIC,
            ),
            _make_finding(
                line_number=1,
                entity_type="AGE_OVER_THRESHOLD",
                hipaa_category=PhiCategory.UNIQUE_ID,
            ),
        )
        aggregates = group_by_line(findings)
        title = build_line_title(aggregates[0])
        assert "Sweeney" in title

    def test_ssn_title(self) -> None:
        findings = (_make_finding(line_number=1, entity_type="SSN"),)
        aggregates = group_by_line(findings)
        title = build_line_title(aggregates[0])
        assert "Social Security" in title

    def test_cluster_title_for_many_categories(self) -> None:
        findings = tuple(
            _make_finding(
                line_number=1,
                entity_type=f"TYPE_{i}",
                hipaa_category=PhiCategory.UNIQUE_ID,
            )
            for i in range(6)
        )
        aggregates = group_by_line(findings)
        title = build_line_title(aggregates[0])
        assert "cluster" in title.lower()
