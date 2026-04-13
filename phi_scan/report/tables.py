"""Compliance matrix row builder — shared between HTML and PDF report layers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from phi_scan.compliance import ComplianceControl
    from phi_scan.models import ScanResult


def _build_compliance_matrix_rows(
    scan_result: ScanResult,
    framework_annotations: Mapping[int, tuple[ComplianceControl, ...]] | None,
) -> list[dict[str, object]]:
    """Build pre-processed compliance matrix rows for the HTML template.

    Returns one dict per finding that has at least one applicable control,
    with controls grouped by framework for template rendering.
    """
    if not framework_annotations:
        return []
    rows: list[dict[str, object]] = []
    for idx, finding in enumerate(scan_result.findings):
        controls = framework_annotations.get(idx, ())
        if not controls:
            continue
        by_framework: dict[str, list[str]] = {}
        for control in controls:
            fw_label = control.framework.value.upper()
            by_framework.setdefault(fw_label, []).append(control.control_id)
        rows.append(
            {
                "index": idx + 1,
                "file_path": str(finding.file_path),
                "line_number": finding.line_number,
                "category": finding.hipaa_category.value,
                "frameworks": by_framework,
            }
        )
    return rows
