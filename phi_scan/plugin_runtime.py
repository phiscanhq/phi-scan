"""Plugin runtime — execute loaded recognizer plugins against scanned files.

Integrates the Plugin API v1 (``phi_scan.plugin_api``) with the scan
path. The host iterates the file's lines, calls each loaded plugin's
``detect(line, context)`` exactly once per line, validates the returned
findings, computes the value hash and redacted code context, and emits
host ``ScanFinding`` objects that flow through the same downstream
filtering, suppression, baseline, and output pipeline as built-in
findings.

The plugin pass is independent of the built-in detection cache — plugin
findings are recomputed on every scan so that plugin updates take effect
immediately without a cache invalidation step.
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from phi_scan.constants import (
    CODE_CONTEXT_REDACTED_VALUE,
    DetectionLayer,
    PhiCategory,
)
from phi_scan.hashing import compute_value_hash, severity_from_confidence
from phi_scan.models import ScanFinding
from phi_scan.plugin_api import (
    BaseRecognizer,
    ScanContext,
)
from phi_scan.plugin_api import (
    ScanFinding as PluginScanFinding,
)
from phi_scan.plugin_loader import LoadedPlugin, PluginRegistry

__all__ = ["run_plugin_pass"]

_logger: logging.Logger = logging.getLogger(__name__)

_MAX_WARNINGS_PER_RECOGNIZER: int = 5
_PLUGIN_REMEDIATION_HINT: str = (
    "Review the matched value and replace or de-identify if it is real PHI/PII."
)

_RETURN_TYPE_ERROR: str = "returned {actual_type} instead of list[ScanFinding]"
_MALFORMED_FINDING_ERROR: str = "returned malformed ScanFinding: {error}"
_OFFSET_OVERRUN_ERROR: str = "end_offset {end_offset} exceeds line length {line_length}"
_UNDECLARED_ENTITY_TYPE_ERROR: str = (
    "entity_type {entity_type!r} not declared in entity_types {declared}"
)
_DETECT_EXCEPTION_ERROR: str = "detect() raised {error_type}: {error_message}"

_PLUGIN_WARNING_LOG: str = "Plugin %r at %s:%d — %s"
_PLUGIN_SUMMARY_LOG: str = "Plugin %r produced %d warnings during this scan (first %d shown above)"


class _RecognizerWarningBudget:
    """Tracks warning emissions per recognizer for the duration of one scan."""

    def __init__(self, limit: int = _MAX_WARNINGS_PER_RECOGNIZER) -> None:
        self._limit = limit
        self._counts: Counter[str] = Counter()

    def should_log(self, recognizer_name: str) -> bool:
        self._counts[recognizer_name] += 1
        return self._counts[recognizer_name] <= self._limit

    def emit_summary(self) -> None:
        for recognizer_name, total_count in self._counts.items():
            if total_count > self._limit:
                _logger.warning(
                    _PLUGIN_SUMMARY_LOG,
                    recognizer_name,
                    total_count,
                    self._limit,
                )


def run_plugin_pass(
    file_content: str,
    file_path: Path,
    registry: PluginRegistry,
) -> list[ScanFinding]:
    """Run every loaded plugin against each line of ``file_content``.

    Args:
        file_content: Decoded text content of the file. Empty strings
            and content without newlines are handled naturally.
        file_path: Relative path recorded on each produced
            ``ScanFinding``. Plugins see the same path in
            ``ScanContext.file_path`` but must not open it.
        registry: Plugin registry loaded once per scan invocation.
            Only ``registry.loaded`` is consulted; skipped plugins do
            not participate in the runtime pass.

    Returns:
        Deterministically sorted list of ``ScanFinding`` objects, one
        per plugin-reported match that passed validation. Empty list
        when no plugins produced findings (or when the registry has
        no loaded plugins).
    """
    if not registry.loaded:
        return []
    warning_budget = _RecognizerWarningBudget()
    findings: list[ScanFinding] = []
    file_extension = file_path.suffix.lower()
    lines = file_content.splitlines()
    for line_index, line_text in enumerate(lines, start=1):
        context = ScanContext(
            file_path=file_path,
            line_number=line_index,
            file_extension=file_extension,
        )
        for loaded_plugin in registry.loaded:
            findings.extend(
                _run_single_plugin_on_line(
                    loaded_plugin=loaded_plugin,
                    line_text=line_text,
                    context=context,
                    file_path=file_path,
                    warning_budget=warning_budget,
                )
            )
    warning_budget.emit_summary()
    return _sort_plugin_findings(findings)


def _run_single_plugin_on_line(
    loaded_plugin: LoadedPlugin,
    line_text: str,
    context: ScanContext,
    file_path: Path,
    warning_budget: _RecognizerWarningBudget,
) -> list[ScanFinding]:
    """Invoke one plugin on one line, returning validated host findings."""
    recognizer = loaded_plugin.recognizer
    raw_findings = _safely_invoke_detect(
        recognizer=recognizer,
        line_text=line_text,
        context=context,
        warning_budget=warning_budget,
    )
    if raw_findings is None:
        return []
    declared_entity_types = frozenset(recognizer.entity_types)
    host_findings: list[ScanFinding] = []
    for plugin_finding in raw_findings:
        host_finding = _translate_plugin_finding_to_host(
            plugin_finding=plugin_finding,
            line_text=line_text,
            file_path=file_path,
            context=context,
            recognizer=recognizer,
            declared_entity_types=declared_entity_types,
            warning_budget=warning_budget,
        )
        if host_finding is not None:
            host_findings.append(host_finding)
    return host_findings


def _safely_invoke_detect(
    recognizer: BaseRecognizer,
    line_text: str,
    context: ScanContext,
    warning_budget: _RecognizerWarningBudget,
) -> list[PluginScanFinding] | None:
    """Call ``recognizer.detect`` under exception isolation."""
    try:
        result = recognizer.detect(line_text, context)
    except Exception as exception:
        _log_plugin_warning(
            recognizer_name=recognizer.name,
            context=context,
            message=_DETECT_EXCEPTION_ERROR.format(
                error_type=type(exception).__name__,
                error_message=str(exception),
            ),
            warning_budget=warning_budget,
        )
        return None
    if not isinstance(result, list):
        _log_plugin_warning(
            recognizer_name=recognizer.name,
            context=context,
            message=_RETURN_TYPE_ERROR.format(actual_type=type(result).__name__),
            warning_budget=warning_budget,
        )
        return None
    return result


def _translate_plugin_finding_to_host(
    plugin_finding: PluginScanFinding,
    line_text: str,
    file_path: Path,
    context: ScanContext,
    recognizer: BaseRecognizer,
    declared_entity_types: frozenset[str],
    warning_budget: _RecognizerWarningBudget,
) -> ScanFinding | None:
    """Validate a plugin finding and translate it into a host ScanFinding."""
    if not isinstance(plugin_finding, PluginScanFinding):
        _log_plugin_warning(
            recognizer_name=recognizer.name,
            context=context,
            message=_MALFORMED_FINDING_ERROR.format(
                error=f"expected ScanFinding, got {type(plugin_finding).__name__}"
            ),
            warning_budget=warning_budget,
        )
        return None
    if plugin_finding.entity_type not in declared_entity_types:
        _log_plugin_warning(
            recognizer_name=recognizer.name,
            context=context,
            message=_UNDECLARED_ENTITY_TYPE_ERROR.format(
                entity_type=plugin_finding.entity_type,
                declared=sorted(declared_entity_types),
            ),
            warning_budget=warning_budget,
        )
        return None
    if plugin_finding.end_offset > len(line_text):
        _log_plugin_warning(
            recognizer_name=recognizer.name,
            context=context,
            message=_OFFSET_OVERRUN_ERROR.format(
                end_offset=plugin_finding.end_offset,
                line_length=len(line_text),
            ),
            warning_budget=warning_budget,
        )
        return None
    matched_slice = line_text[plugin_finding.start_offset : plugin_finding.end_offset]
    redacted_context = (
        line_text[: plugin_finding.start_offset]
        + CODE_CONTEXT_REDACTED_VALUE
        + line_text[plugin_finding.end_offset :]
    ).rstrip()
    return ScanFinding(
        file_path=file_path,
        line_number=context.line_number,
        entity_type=plugin_finding.entity_type,
        hipaa_category=PhiCategory.UNIQUE_ID,
        confidence=plugin_finding.confidence,
        detection_layer=DetectionLayer.PLUGIN,
        value_hash=compute_value_hash(matched_slice),
        severity=severity_from_confidence(plugin_finding.confidence),
        code_context=redacted_context,
        remediation_hint=_PLUGIN_REMEDIATION_HINT,
    )


def _log_plugin_warning(
    recognizer_name: str,
    context: ScanContext,
    message: str,
    warning_budget: _RecognizerWarningBudget,
) -> None:
    if not warning_budget.should_log(recognizer_name):
        return
    _logger.warning(
        _PLUGIN_WARNING_LOG,
        recognizer_name,
        context.file_path,
        context.line_number,
        message,
    )


def _sort_plugin_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Return plugin findings sorted for deterministic output."""
    return sorted(
        findings,
        key=lambda finding: (
            str(finding.file_path),
            finding.line_number,
            finding.entity_type,
            finding.value_hash,
        ),
    )
