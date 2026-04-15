# phi-scan:ignore-file
"""Comment-body formatting for CI/CD PR/MR comments.

Produces the sanitised markdown body posted by platform adapters.
The body contains only counts, file names, and line numbers — never raw
entity values.
"""

from __future__ import annotations

from dataclasses import dataclass

from phi_scan.ci._base import SanitisedCommentBody
from phi_scan.models import ScanResult

__all__ = [
    "BaselineComparison",
    "build_comment_body",
    "build_comment_body_with_baseline",
]

_COMMENT_HEADER_CLEAN: str = "## phi-scan: No PHI/PII Violations Found"
_COMMENT_HEADER_VIOLATIONS: str = "## phi-scan: PHI/PII Violations Detected"
_COMMENT_BADGE_CLEAN: str = "![clean](https://img.shields.io/badge/phi--scan-clean-green)"
_COMMENT_BADGE_VIOLATIONS: str = (
    "![violations](https://img.shields.io/badge/phi--scan-violations-red)"
)

_MAX_COMMENT_LENGTH: int = 60_000
_COMMENT_BODY_NEWLINE_SPLIT_LIMIT: int = 2
_COMMENT_MIN_SECTION_COUNT: int = 2
_BASELINE_CONTEXT_FORMAT: str = (
    "**{new_findings_count} new** | "
    "{baselined_count} baselined | "
    "{resolved_count} resolved since last scan"
)
_MAX_FINDINGS_IN_COMMENT_TABLE: int = 50


@dataclass(frozen=True)
class BaselineComparison:
    """Counts from a baseline comparison to include in PR/MR comment context."""

    new_findings_count: int
    baselined_count: int
    resolved_count: int


def _format_severity_summary(scan_result: ScanResult) -> str:
    """Join non-zero severity counts into a comma-separated summary string."""
    return ", ".join(
        f"{count} {level.value}"
        for level, count in sorted(
            scan_result.severity_counts.items(),
            key=lambda severity_item: severity_item[0].value,
        )
        if count > 0
    )


def _build_clean_comment_lines(scan_result: ScanResult) -> list[str]:
    """Lines for the 'no violations' comment body."""
    return [
        _COMMENT_BADGE_CLEAN,
        "",
        f"**{_COMMENT_HEADER_CLEAN}**",
        "",
        f"Scanned **{scan_result.files_scanned}** file(s) — no PHI/PII detected.",
        "",
        f"*Scan duration: {scan_result.scan_duration:.2f}s*",
    ]


def _build_findings_table_lines(scan_result: ScanResult) -> list[str]:
    """Markdown table rows for the findings section (capped + truncation row)."""
    findings_count = len(scan_result.findings)
    rows = [
        "| File | Line | Type | Severity | Confidence |",
        "|------|------|------|----------|------------|",
    ]
    for finding in scan_result.findings[:_MAX_FINDINGS_IN_COMMENT_TABLE]:
        rows.append(
            f"| `{finding.file_path}` | {finding.line_number} "
            f"| {finding.hipaa_category.value} "
            f"| {finding.severity.value} "
            f"| {finding.confidence:.0%} |"
        )
    if findings_count > _MAX_FINDINGS_IN_COMMENT_TABLE:
        rows.append(f"| … and {findings_count - _MAX_FINDINGS_IN_COMMENT_TABLE} more | | | | |")
    return rows


def _build_violations_comment_lines(scan_result: ScanResult) -> list[str]:
    """Lines for the 'violations detected' comment body."""
    findings_count = len(scan_result.findings)
    severity_summary = _format_severity_summary(scan_result)
    header_lines = [
        _COMMENT_BADGE_VIOLATIONS,
        "",
        f"**{_COMMENT_HEADER_VIOLATIONS}**",
        "",
        f"phi-scan detected **{findings_count}** PHI/PII finding(s) across "
        f"**{scan_result.files_with_findings}** file(s).",
        "",
        f"**Risk level:** {scan_result.risk_level.value}  ",
        f"**Severity breakdown:** {severity_summary}",
        "",
        "### Findings",
        "",
    ]
    footer_lines = [
        "",
        "> **Action required:** Remove or de-identify all flagged values before merging.",
        "> Run `phi-scan scan . --output table` locally for full details.",
        "",
        f"*Scan duration: {scan_result.scan_duration:.2f}s | "
        f"Files scanned: {scan_result.files_scanned}*",
    ]
    return header_lines + _build_findings_table_lines(scan_result) + footer_lines


def _truncate_comment_body(comment_body: str) -> str:
    """Cap the body at ``_MAX_COMMENT_LENGTH`` and append a truncation note."""
    if len(comment_body) <= _MAX_COMMENT_LENGTH:
        return comment_body
    return comment_body[:_MAX_COMMENT_LENGTH] + "\n\n*(comment truncated — too many findings)*"


def build_comment_body(scan_result: ScanResult) -> SanitisedCommentBody:
    """Build a markdown PR/MR comment body from a ``ScanResult``.

    The body contains only counts, file names, and line numbers — never raw
    entity values. Truncated to ``_MAX_COMMENT_LENGTH`` characters to stay
    within platform comment size limits.
    """
    if scan_result.is_clean:
        return SanitisedCommentBody("\n".join(_build_clean_comment_lines(scan_result)))
    body_lines = _build_violations_comment_lines(scan_result)
    return SanitisedCommentBody(_truncate_comment_body("\n".join(body_lines)))


def _insert_baseline_context_into_comment(
    comment_body: str,
    baseline_line: str,
) -> str:
    """Insert a baseline context line after the first header line of a comment body."""
    lines = comment_body.split("\n", _COMMENT_BODY_NEWLINE_SPLIT_LIMIT)
    if len(lines) < _COMMENT_MIN_SECTION_COUNT:
        return baseline_line + "\n\n" + comment_body
    return "\n".join([lines[0], "", baseline_line, "", *lines[1:]])


def build_comment_body_with_baseline(
    scan_result: ScanResult,
    baseline_comparison: BaselineComparison,
) -> SanitisedCommentBody:
    """Build a PR/MR comment body that includes baseline comparison context."""
    baseline_line = _BASELINE_CONTEXT_FORMAT.format(
        new_findings_count=baseline_comparison.new_findings_count,
        baselined_count=baseline_comparison.baselined_count,
        resolved_count=baseline_comparison.resolved_count,
    )
    return SanitisedCommentBody(
        _insert_baseline_context_into_comment(build_comment_body(scan_result), baseline_line)
    )
