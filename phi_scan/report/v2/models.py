"""Aggregation dataclasses for the v2 terminal report renderer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from phi_scan.constants import SEVERITY_RANK, PhiCategory, SeverityLevel
from phi_scan.models import ScanFinding


@dataclass(frozen=True)
class LineAggregate:
    """All findings on a single (file_path, line_number).

    ``display_context`` holds the pre-redacted code context from the first
    finding on this line.  ScanFinding enforces at construction time that
    ``code_context`` always contains ``[REDACTED]`` in place of the matched
    PHI value, so ``display_context`` is safe for terminal rendering.
    """

    file_path: Path
    line_number: int
    findings: tuple[ScanFinding, ...]
    highest_severity: SeverityLevel
    category_counts: dict[str, int]
    display_context: str
    combined_fix: str
    unique_fix_count: int

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.highest_severity]


@dataclass(frozen=True)
class RemediationAction:
    """Findings grouped by unique remediation_hint string."""

    remediation_hint: str
    title: str
    hipaa_category: PhiCategory
    finding_count: int
    highest_severity: SeverityLevel
    mean_confidence: float
    affected_lines: tuple[tuple[Path, int], ...]
    severity_weight_score: float

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.highest_severity]


@dataclass(frozen=True)
class FileAggregate:
    """All line aggregates for a single file, sorted by severity/count/line."""

    file_path: Path
    line_aggregates: tuple[LineAggregate, ...]
    total_finding_count: int
    highest_severity: SeverityLevel
