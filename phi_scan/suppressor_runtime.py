"""Suppressor runtime — execute loaded suppressor plugins against host findings.

Integrates the Plugin API v1.1 ``BaseSuppressor`` hook with the scan
pipeline. Each loaded suppressor is consulted once per surviving
finding in deterministic ``(distribution_name, entry_point_name)``
order. The first ``SuppressDecision`` with ``is_suppressed=True``
drops the finding; later suppressors for the same finding are not
consulted.

Exception isolation mirrors ``phi_scan.plugin_runtime`` exactly: a
broad ``except Exception`` at one designated boundary per suppressor
invocation, rate-limited warning emission per suppressor, and a final
summary line when the budget was exceeded.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

from phi_scan.models import ScanFinding
from phi_scan.plugin_api import (
    BaseSuppressor,
    SuppressDecision,
    SuppressorFindingView,
)
from phi_scan.plugin_loader import LoadedSuppressor, PluginRegistry

__all__ = ["apply_suppressor_pass"]

_LOG: logging.Logger = logging.getLogger(__name__)

_MAX_WARNINGS_PER_SUPPRESSOR: int = 5

_SUPPRESSOR_WARNING_LOG: str = "Suppressor %r at %s:%d — %s"
_SUPPRESSOR_SUMMARY_LOG: str = (
    "Suppressor %r produced %d warnings during this scan (first %d shown above)"
)
_EVALUATE_EXCEPTION_ERROR: str = "evaluate() raised {error_type}: {error_message}"
_INVALID_RETURN_TYPE_ERROR: str = "returned {actual_type} instead of SuppressDecision"


@dataclass(frozen=True)
class _SuppressorInvocation:
    """One suppressor's invocation against one host finding."""

    loaded_suppressor: LoadedSuppressor
    finding_view: SuppressorFindingView
    line_text: str
    finding: ScanFinding


class _SuppressorWarningBudget:
    """Tracks warning emissions per suppressor for the duration of one scan."""

    def __init__(self, limit: int = _MAX_WARNINGS_PER_SUPPRESSOR) -> None:
        self._limit = limit
        self._counts: Counter[str] = Counter()

    def claim_suppressor_warning_slot(self, suppressor_name: str) -> bool:
        self._counts[suppressor_name] += 1
        return self._counts[suppressor_name] <= self._limit

    def log_suppressor_warning(
        self, suppressor_name: str, finding: ScanFinding, message: str
    ) -> None:
        if not self.claim_suppressor_warning_slot(suppressor_name):
            return
        _LOG.warning(
            _SUPPRESSOR_WARNING_LOG,
            suppressor_name,
            finding.file_path,
            finding.line_number,
            message,
        )

    def emit_suppressor_warning_summary(self) -> None:
        for suppressor_name, total_count in self._counts.items():
            if total_count > self._limit:
                _LOG.warning(
                    _SUPPRESSOR_SUMMARY_LOG,
                    suppressor_name,
                    total_count,
                    self._limit,
                )


def apply_suppressor_pass(
    findings: list[ScanFinding],
    registry: PluginRegistry,
    file_content: str,
) -> list[ScanFinding]:
    """Filter ``findings`` through every loaded suppressor in deterministic order.

    Args:
        findings: Host findings that have already passed inline
            ``phi-scan:ignore`` suppression. May be empty.
        registry: The scan-scoped plugin registry. Only
            ``registry.loaded_suppressors`` is consulted.
        file_content: Decoded text of the scanned file; used to
            reconstruct the line text passed to ``evaluate``.

    Returns:
        The subset of ``findings`` that no suppressor chose to drop,
        in input order. Empty list when every finding was suppressed
        or when ``findings`` was empty.
    """
    if not registry.loaded_suppressors or not findings:
        return findings
    file_lines = file_content.splitlines()
    warning_budget = _SuppressorWarningBudget()
    retained_findings = _retain_unsuppressed_findings(
        findings, registry.loaded_suppressors, file_lines, warning_budget
    )
    warning_budget.emit_suppressor_warning_summary()
    return retained_findings


def _retain_unsuppressed_findings(
    findings: list[ScanFinding],
    loaded_suppressors: tuple[LoadedSuppressor, ...],
    file_lines: list[str],
    warning_budget: _SuppressorWarningBudget,
) -> list[ScanFinding]:
    retained_findings: list[ScanFinding] = []
    for finding in findings:
        if _is_finding_suppressed(finding, loaded_suppressors, file_lines, warning_budget):
            continue
        retained_findings.append(finding)
    return retained_findings


def _is_finding_suppressed(
    finding: ScanFinding,
    loaded_suppressors: tuple[LoadedSuppressor, ...],
    file_lines: list[str],
    warning_budget: _SuppressorWarningBudget,
) -> bool:
    finding_view = _build_finding_view(finding)
    line_text = _resolve_line_text(finding, file_lines)
    for loaded_suppressor in loaded_suppressors:
        invocation = _SuppressorInvocation(
            loaded_suppressor=loaded_suppressor,
            finding_view=finding_view,
            line_text=line_text,
            finding=finding,
        )
        decision = _evaluate_suppressor_with_isolation(invocation, warning_budget)
        if decision is not None and decision.is_suppressed:
            return True
    return False


def _build_finding_view(finding: ScanFinding) -> SuppressorFindingView:
    return SuppressorFindingView(
        entity_type=finding.entity_type,
        confidence=finding.confidence,
        line_number=finding.line_number,
        file_path=finding.file_path,
        file_extension=finding.file_path.suffix.lower(),
    )


def _resolve_line_text(finding: ScanFinding, file_lines: list[str]) -> str:
    line_index = finding.line_number - 1
    if 0 <= line_index < len(file_lines):
        return file_lines[line_index]
    return ""


def _evaluate_suppressor_with_isolation(
    invocation: _SuppressorInvocation,
    warning_budget: _SuppressorWarningBudget,
) -> SuppressDecision | None:
    """Call ``suppressor.evaluate`` under exception isolation.

    This is the single designated suppressor-plugin exception boundary
    (mirroring ``plugin_runtime._invoke_detect_with_isolation``). Any
    exception raised by ``evaluate`` is caught, logged through the
    rate-limited warning budget, and the finding is treated as not
    suppressed by this plugin — other suppressors and the surrounding
    scan proceed unaffected. The broad ``except Exception`` is
    required by the suppressor-plugin failure-semantics contract;
    ``BaseException`` (``KeyboardInterrupt``, ``SystemExit``) is
    deliberately not caught. A non-``SuppressDecision`` return value
    is treated the same way.
    """
    suppressor: BaseSuppressor = invocation.loaded_suppressor.suppressor
    try:
        decision = suppressor.evaluate(invocation.finding_view, invocation.line_text)
    except Exception as exception:  # noqa: BLE001 — suppressor isolation boundary (see docstring)
        warning_budget.log_suppressor_warning(
            suppressor.name,
            invocation.finding,
            _EVALUATE_EXCEPTION_ERROR.format(
                error_type=type(exception).__name__,
                error_message=str(exception),
            ),
        )
        return None
    if not isinstance(decision, SuppressDecision):
        warning_budget.log_suppressor_warning(
            suppressor.name,
            invocation.finding,
            _INVALID_RETURN_TYPE_ERROR.format(actual_type=type(decision).__name__),
        )
        return None
    return decision
