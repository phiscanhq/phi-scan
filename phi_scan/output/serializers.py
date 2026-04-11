"""Serialization formatters: JSON, CSV, SARIF, JUnit, Code Quality, GitLab SAST."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree

from phi_scan import __version__
from phi_scan.constants import SeverityLevel
from phi_scan.models import ScanFinding, ScanResult

# ---------------------------------------------------------------------------
# SARIF 2.1.0 protocol constants
# ---------------------------------------------------------------------------

_SARIF_VERSION: str = "2.1.0"
_SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_SCHEMA_KEY: str = "$schema"
_SARIF_URI_BASE_ID: str = "%SRCROOT%"
_SARIF_TOOL_NAME: str = "PhiScan"
_SARIF_LEVEL_ERROR: str = "error"
_SARIF_LEVEL_WARNING: str = "warning"
_SARIF_LEVEL_NOTE: str = "note"
_SARIF_LEVEL_NONE: str = "none"

_SEVERITY_TO_SARIF_LEVEL: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _SARIF_LEVEL_ERROR,
    SeverityLevel.MEDIUM: _SARIF_LEVEL_WARNING,
    SeverityLevel.LOW: _SARIF_LEVEL_NOTE,
    SeverityLevel.INFO: _SARIF_LEVEL_NONE,
}

# ---------------------------------------------------------------------------
# JUnit XML protocol constants
# ---------------------------------------------------------------------------

_JUNIT_TESTSUITE_NAME: str = "phi-scan"
_JUNIT_TESTSUITE_TAG: str = "testsuite"
_JUNIT_TESTCASE_TAG: str = "testcase"
_JUNIT_FAILURE_TAG: str = "failure"
_JUNIT_FAILURE_TYPE: str = "PHIViolation"
_JUNIT_ERROR_COUNT: str = "0"
_JUNIT_INDENT: str = "  "
_JUNIT_ENCODING: str = "utf-8"
_JUNIT_DURATION_FORMAT: str = "{:.2f}"
_JUNIT_CONFIDENCE_FORMAT: str = "{:.2f}"
_JUNIT_TESTCASE_NAME_FORMAT: str = "{file_path}:{line_number} [{entity_type}]"
_JUNIT_FAILURE_MESSAGE_FORMAT: str = "[{severity}] PHI detected: {entity_type}"
_JUNIT_FAILURE_TEXT_FORMAT: str = (
    "file: {file_path}\nline: {line_number}\ncategory: {hipaa_category}\n"
    "confidence: {confidence}\nremediation: {remediation_hint}"
)

# ---------------------------------------------------------------------------
# GitLab Code Quality protocol constants
# ---------------------------------------------------------------------------

_CODEQUALITY_SEVERITY_CRITICAL: str = "critical"
_CODEQUALITY_SEVERITY_MAJOR: str = "major"
_CODEQUALITY_SEVERITY_MINOR: str = "minor"
_CODEQUALITY_SEVERITY_INFO: str = "info"
_SEVERITY_TO_CODEQUALITY: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _CODEQUALITY_SEVERITY_CRITICAL,
    SeverityLevel.MEDIUM: _CODEQUALITY_SEVERITY_MAJOR,
    SeverityLevel.LOW: _CODEQUALITY_SEVERITY_MINOR,
    SeverityLevel.INFO: _CODEQUALITY_SEVERITY_INFO,
}
_CODEQUALITY_DESCRIPTION_FORMAT: str = "PHI detected: {entity_type} ({category})"

# ---------------------------------------------------------------------------
# GitLab SAST protocol constants
# ---------------------------------------------------------------------------

_GITLAB_SAST_VERSION: str = "15.0.4"
_GITLAB_SAST_CATEGORY: str = "sast"
_GITLAB_SAST_SCANNER_ID: str = "phi-scan"
_GITLAB_SAST_SCANNER_NAME: str = "PhiScan"
_GITLAB_SAST_VENDOR_NAME: str = "PhiScan"
_GITLAB_SAST_SCAN_TYPE: str = "sast"
_GITLAB_SAST_SCAN_STATUS: str = "success"
_GITLAB_SAST_IDENTIFIER_TYPE: str = "phi_scan_rule"
_GITLAB_SAST_VULNERABILITY_NAME_FORMAT: str = "PHI detected: {entity_type}"
_GITLAB_SAST_DESCRIPTION_FORMAT: str = "{category} identifier found by the {layer} detection layer"
_GITLAB_SAST_TIMESTAMP_FORMAT: str = "%Y-%m-%dT%H:%M:%SZ"
_GITLAB_SAST_SEVERITY_CRITICAL: str = "Critical"
_GITLAB_SAST_SEVERITY_HIGH: str = "High"
_GITLAB_SAST_SEVERITY_MEDIUM: str = "Medium"
_GITLAB_SAST_SEVERITY_LOW: str = "Low"
_SEVERITY_TO_GITLAB_SAST: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _GITLAB_SAST_SEVERITY_CRITICAL,
    SeverityLevel.MEDIUM: _GITLAB_SAST_SEVERITY_HIGH,
    SeverityLevel.LOW: _GITLAB_SAST_SEVERITY_MEDIUM,
    SeverityLevel.INFO: _GITLAB_SAST_SEVERITY_LOW,
}
_GITLAB_SAST_CONFIDENCE_HIGH: str = "High"
_GITLAB_SAST_CONFIDENCE_MEDIUM: str = "Medium"
_GITLAB_SAST_CONFIDENCE_LOW: str = "Low"
_SEVERITY_TO_GITLAB_SAST_CONFIDENCE: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _GITLAB_SAST_CONFIDENCE_HIGH,
    SeverityLevel.MEDIUM: _GITLAB_SAST_CONFIDENCE_HIGH,
    SeverityLevel.LOW: _GITLAB_SAST_CONFIDENCE_MEDIUM,
    SeverityLevel.INFO: _GITLAB_SAST_CONFIDENCE_LOW,
}

# ---------------------------------------------------------------------------
# CSV field names (in output column order)
# ---------------------------------------------------------------------------

_CSV_FIELD_NAMES: list[str] = [
    "file_path",
    "line_number",
    "entity_type",
    "hipaa_category",
    "confidence",
    "severity",
    "detection_layer",
    "remediation_hint",
]

# ---------------------------------------------------------------------------
# Numeric and format constants
# ---------------------------------------------------------------------------

_JSON_INDENT: int = 2
_CONFIDENCE_FORMAT: str = "{:.2f}"

# Both Code Quality and GitLab SAST fingerprints are keyed on the same
# three non-PHI metadata fields. One constant prevents the two formatters
# from drifting silently if the fingerprint scheme is ever updated.
_FINDING_FINGERPRINT_INPUT_FORMAT: str = "{file_path}:{line_number}:{entity_type}"


def _serialize_finding_to_dict(finding: ScanFinding) -> dict[str, object]:
    """Serialize a ScanFinding to a JSON-serializable dict.

    code_context is intentionally omitted: it contains the raw source line
    that triggered the finding, which may hold the PHI value itself. JSON
    output is consumed by CI systems and log aggregators where raw PHI must
    never appear. File path and line number are sufficient for remediation.
    The value_hash field is a SHA-256 digest — it never contains raw PHI.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict with string keys and JSON-serializable values.
    """
    return {
        # file_path uses POSIX separators so output is stable across runner OS —
        # str(WindowsPath("src/a.py")) emits backslashes which would break
        # cross-platform golden comparisons and downstream consumers (GitHub code
        # scanning, GitLab code quality) that expect forward slashes.
        "file_path": finding.file_path.as_posix(),
        "line_number": finding.line_number,
        "entity_type": finding.entity_type,
        "hipaa_category": finding.hipaa_category.value,
        "confidence": finding.confidence,
        "detection_layer": finding.detection_layer.value,
        "severity": finding.severity.value,
        "value_hash": finding.value_hash,
        # remediation_hint must never contain raw PHI — the ScanFinding contract
        # requires it to hold only generic guidance (e.g. "Replace SSN with
        # synthetic value"), never the matched value itself.
        "remediation_hint": finding.remediation_hint,
    }


def _serialize_finding_to_csv_row(finding: ScanFinding) -> dict[str, object]:
    """Build a CSV row dict from a ScanFinding.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict whose keys match _CSV_FIELD_NAMES.
    """
    return {
        "file_path": finding.file_path.as_posix(),
        "line_number": finding.line_number,
        "entity_type": finding.entity_type,
        "hipaa_category": finding.hipaa_category.value,
        "confidence": finding.confidence,
        "severity": finding.severity.value,
        "detection_layer": finding.detection_layer.value,
        # remediation_hint must never contain raw PHI — see _serialize_finding_to_dict.
        "remediation_hint": finding.remediation_hint,
    }


def _build_sarif_rule(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF rule entry from the first finding for an entity type.

    Args:
        finding: A representative finding for the rule.

    Returns:
        A SARIF rule dict with id, name, shortDescription, and help.
    """
    return {
        "id": finding.entity_type,
        "name": finding.entity_type,
        "shortDescription": {"text": finding.hipaa_category.value},
        "help": {
            "text": finding.remediation_hint,
            "markdown": finding.remediation_hint,
        },
    }


def _build_sarif_rules(scan_result: ScanResult) -> list[dict[str, object]]:
    """Deduplicate findings into one SARIF rule per unique entity type.

    Args:
        scan_result: The completed scan result.

    Returns:
        List of SARIF rule dicts, one per distinct entity_type.
    """
    seen_entity_types: set[str] = set()
    rules: list[dict[str, object]] = []
    for finding in scan_result.findings:
        if finding.entity_type not in seen_entity_types:
            seen_entity_types.add(finding.entity_type)
            rules.append(_build_sarif_rule(finding))
    return rules


def _build_sarif_finding_message(finding: ScanFinding) -> str:
    """Build the human-readable SARIF result message for a finding.

    PHI-safety: this message is uploaded to GitHub Advanced Security (and other
    external CI platforms) as SARIF ``result.message.text``. It must never
    contain raw entity values. Fields used and their safety rationale:

    - ``hipaa_category.value`` — enum label (e.g. "SSN"), not a raw value
    - ``detection_layer.value`` — enum label (e.g. "regex"), not a raw value
    - ``confidence`` — float score, not a raw value
    - ``remediation_hint`` — pre-canned guidance text; ``ScanFinding.__post_init__``
      enforces that it is a non-empty string with no raw value embedded

    Fields intentionally excluded: ``value_hash``, ``code_context``,
    ``entity_type``, ``file_path``, ``line_number`` — none carry raw PHI but are
    also unnecessary in the human-readable message text.

    Args:
        finding: The finding to describe.

    Returns:
        A sentence describing the category, layer, confidence, and remediation.
        Maximum length is bounded by ``_MAXIMUM_REMEDIATION_HINT_LENGTH`` + overhead.
    """
    confidence_str = _CONFIDENCE_FORMAT.format(finding.confidence)
    # remediation_hint must never contain raw PHI — SARIF is consumed by GitHub
    # Advanced Security and other external CI platforms. Enforcement of this
    # constraint belongs in ScanFinding.__post_init__, not here; output.py trusts
    # the model-layer contract. See _serialize_finding_to_dict for the full note.
    return (
        # PHI-SAFE: hipaa_category.value + detection_layer.value + confidence (float)
        # + remediation_hint — no raw entity value, no code_context, no value_hash
        f"{finding.hipaa_category.value} identifier detected by the "
        f"{finding.detection_layer.value} layer "
        f"(confidence: {confidence_str}). {finding.remediation_hint}"
    )


def _build_sarif_location(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF physicalLocation entry for a finding.

    Args:
        finding: The finding whose file path and line number to encode.

    Returns:
        A SARIF location dict with artifactLocation and region.
    """
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.file_path.as_posix(),
                "uriBaseId": _SARIF_URI_BASE_ID,
            },
            "region": {"startLine": finding.line_number},
        }
    }


def _build_sarif_result(finding: ScanFinding) -> dict[str, object]:
    """Build a SARIF result dict for a single finding.

    Args:
        finding: The finding to encode as a SARIF result.

    Returns:
        A SARIF result dict with ruleId, level, message, and locations.
    """
    return {
        "ruleId": finding.entity_type,
        "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
        "message": {"text": _build_sarif_finding_message(finding)},
        "locations": [_build_sarif_location(finding)],
    }


def _build_sarif_run(scan_result: ScanResult) -> dict[str, object]:
    """Build the single SARIF run object for a completed scan.

    Args:
        scan_result: The completed scan result.

    Returns:
        A SARIF run dict with tool driver and results array.
    """
    return {
        "tool": {
            "driver": {
                "name": _SARIF_TOOL_NAME,
                "version": __version__,
                "rules": _build_sarif_rules(scan_result),
            }
        },
        "results": [_build_sarif_result(finding) for finding in scan_result.findings],
    }


def _build_junit_failure_element(finding: ScanFinding) -> ElementTree.Element:
    """Build a JUnit <failure> element for one PHI finding.

    PHI-safety: embeds file_path, line_number, entity_type, and
    remediation_hint — all non-PHI metadata fields. The raw PHI value is never
    included; entity_type (e.g. "us_ssn") is a detection-rule identifier.

    Args:
        finding: The PHI finding to represent as a failure.

    Returns:
        A configured failure Element with message, type, and text body.
    """
    failure = ElementTree.Element(
        _JUNIT_FAILURE_TAG,
        {
            "message": _JUNIT_FAILURE_MESSAGE_FORMAT.format(
                severity=finding.severity.value.upper(),
                entity_type=finding.entity_type,
            ),
            "type": _JUNIT_FAILURE_TYPE,
        },
    )
    failure.text = _JUNIT_FAILURE_TEXT_FORMAT.format(
        file_path=finding.file_path.as_posix(),
        line_number=finding.line_number,
        hipaa_category=finding.hipaa_category.value,
        confidence=_JUNIT_CONFIDENCE_FORMAT.format(finding.confidence),
        remediation_hint=finding.remediation_hint,
    )
    return failure


def _build_junit_testcase(finding: ScanFinding) -> ElementTree.Element:
    """Build a JUnit <testcase> element with a <failure> child for one finding.

    Args:
        finding: The PHI finding to represent as a test failure.

    Returns:
        A configured testcase Element with a failure child.
    """
    testcase = ElementTree.Element(
        _JUNIT_TESTCASE_TAG,
        {
            "name": _JUNIT_TESTCASE_NAME_FORMAT.format(
                file_path=finding.file_path.as_posix(),
                line_number=finding.line_number,
                entity_type=finding.entity_type,
            ),
            "classname": finding.hipaa_category.value,
        },
    )
    testcase.append(_build_junit_failure_element(finding))
    return testcase


def _compute_sha256_hexadecimal(raw: str) -> str:
    """Return the lowercase SHA-256 hex digest of raw encoded as UTF-8.

    Args:
        raw: The pre-formatted string to hash.

    Returns:
        64-character lowercase hexadecimal digest.
    """
    return hashlib.sha256(raw.encode()).hexdigest()


def _compute_finding_fingerprint(finding: ScanFinding) -> str:
    """Compute a stable SHA-256 fingerprint for a finding's location metadata.

    PHI-safety: only non-PHI metadata fields (file path, line number, entity
    type) are included in the fingerprint input. The raw PHI value is never
    hashed here — that is stored separately as finding.value_hash. Entity type
    (e.g. "us_ssn") is a detection-rule identifier, not the PHI value itself.

    Args:
        finding: The PHI finding to fingerprint.

    Returns:
        64-character lowercase hex digest, stable across runs for the same
        file/line/entity-type combination.
    """
    # file_path uses POSIX form so the fingerprint is identical across runner
    # OS — otherwise Windows and Linux CI would produce different dedup keys
    # for the same finding, breaking cross-platform code-quality merging.
    fingerprint_input = _FINDING_FINGERPRINT_INPUT_FORMAT.format(
        file_path=finding.file_path.as_posix(),
        line_number=finding.line_number,
        entity_type=finding.entity_type,
    )
    return _compute_sha256_hexadecimal(fingerprint_input)


def _build_codequality_entry(finding: ScanFinding) -> dict[str, object]:
    """Serialize one ScanFinding to a GitLab Code Quality issue dict.

    PHI-safety: description, location, and fingerprint contain only non-PHI
    metadata (entity_type rule name, file path, line number). The raw PHI
    value is never serialized into output. See _compute_finding_fingerprint
    for the PHI-safety rationale for entity_type.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict conforming to the gl-code-quality-report.json schema.
    """
    return {
        "description": _CODEQUALITY_DESCRIPTION_FORMAT.format(
            entity_type=finding.entity_type,
            category=finding.hipaa_category.value,
        ),
        "fingerprint": _compute_finding_fingerprint(finding),
        "severity": _SEVERITY_TO_CODEQUALITY[finding.severity],
        "location": {
            "path": finding.file_path.as_posix(),
            "lines": {"begin": finding.line_number},
        },
    }


def _build_gitlab_sast_location(finding: ScanFinding) -> dict[str, object]:
    """Build the location dict for a GitLab SAST vulnerability entry.

    PHI-safety: file_path is always relative — ScanFinding.__post_init__ rejects
    absolute paths, so finding.file_path.as_posix() is safe to serialize directly.

    Args:
        finding: The finding to extract location metadata from.

    Returns:
        A location dict with file path and start/end line numbers.
    """
    return {
        "file": finding.file_path.as_posix(),
        "start_line": finding.line_number,
        "end_line": finding.line_number,
    }


def _build_gitlab_sast_vulnerability(finding: ScanFinding) -> dict[str, object]:
    """Serialize one ScanFinding to a GitLab SAST vulnerability dict.

    PHI-safety: name, description, location, and identifiers contain only
    non-PHI metadata (entity_type rule name, HIPAA category, file path, line
    number). The raw PHI value is never serialized into output. See
    _compute_finding_fingerprint for the PHI-safety rationale for entity_type.

    Args:
        finding: The finding to serialize.

    Returns:
        A dict conforming to the gl-sast-report.json v15.0.4 schema.
    """
    return {
        "id": _compute_finding_fingerprint(finding),
        "category": _GITLAB_SAST_CATEGORY,
        "name": _GITLAB_SAST_VULNERABILITY_NAME_FORMAT.format(entity_type=finding.entity_type),
        "description": _GITLAB_SAST_DESCRIPTION_FORMAT.format(
            category=finding.hipaa_category.value,
            layer=finding.detection_layer.value,
        ),
        "severity": _SEVERITY_TO_GITLAB_SAST[finding.severity],
        "confidence": _SEVERITY_TO_GITLAB_SAST_CONFIDENCE[finding.severity],
        "scanner": {"id": _GITLAB_SAST_SCANNER_ID, "name": _GITLAB_SAST_SCANNER_NAME},
        "location": _build_gitlab_sast_location(finding),
        "identifiers": [
            {
                "type": _GITLAB_SAST_IDENTIFIER_TYPE,
                "name": finding.entity_type,
                "value": finding.entity_type,
            }
        ],
    }


def _build_gitlab_sast_scan_section(scan_result: ScanResult) -> dict[str, object]:
    """Build the scan metadata section of a GitLab SAST report.

    Args:
        scan_result: The completed scan result (used for timing).

    Returns:
        A scan dict with analyzer, scanner, type, timestamps, and status.
    """
    end_time = datetime.now(tz=UTC)
    start_time = end_time - timedelta(seconds=scan_result.scan_duration)
    start_time_iso = start_time.strftime(_GITLAB_SAST_TIMESTAMP_FORMAT)
    end_time_iso = end_time.strftime(_GITLAB_SAST_TIMESTAMP_FORMAT)
    analyzer_block = {
        "id": _GITLAB_SAST_SCANNER_ID,
        "name": _GITLAB_SAST_SCANNER_NAME,
        "vendor": {"name": _GITLAB_SAST_VENDOR_NAME},
        "version": __version__,
    }
    scanner_block = {
        "id": _GITLAB_SAST_SCANNER_ID,
        "name": _GITLAB_SAST_SCANNER_NAME,
        "vendor": {"name": _GITLAB_SAST_VENDOR_NAME},
        "version": __version__,
    }
    return {
        "analyzer": analyzer_block,
        "scanner": scanner_block,
        "type": _GITLAB_SAST_SCAN_TYPE,
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "status": _GITLAB_SAST_SCAN_STATUS,
    }


def format_json(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a JSON string.

    The value_hash field in each finding is a SHA-256 digest — this function
    never serializes raw PHI values.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented JSON string with findings array and summary metadata.
    """
    payload: dict[str, object] = {
        "files_scanned": scan_result.files_scanned,
        "files_with_findings": scan_result.files_with_findings,
        "scan_duration": scan_result.scan_duration,
        "is_clean": scan_result.is_clean,
        "risk_level": scan_result.risk_level.value,
        "severity_counts": {k.value: v for k, v in scan_result.severity_counts.items()},
        "category_counts": {k.value: v for k, v in scan_result.category_counts.items()},
        "findings": [_serialize_finding_to_dict(finding) for finding in scan_result.findings],
    }
    return json.dumps(payload, indent=_JSON_INDENT)


def format_csv(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a CSV string with headers.

    Args:
        scan_result: The completed scan result.

    Returns:
        CSV-formatted string with a header row and one data row per finding.
    """
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=_CSV_FIELD_NAMES)
    writer.writeheader()
    for finding in scan_result.findings:
        writer.writerow(_serialize_finding_to_csv_row(finding))
    return csv_buffer.getvalue()


def format_sarif(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to a SARIF 2.1.0 JSON string.

    SARIF (Static Analysis Results Interchange Format) is consumed by GitHub
    Advanced Security, Azure DevOps, and other CI/CD platforms for inline
    code annotations and security dashboards.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented SARIF 2.1.0 JSON string.
    """
    sarif_doc: dict[str, object] = {
        _SARIF_SCHEMA_KEY: _SARIF_SCHEMA_URL,
        "version": _SARIF_VERSION,
        "runs": [_build_sarif_run(scan_result)],
    }
    return json.dumps(sarif_doc, indent=_JSON_INDENT)


def format_junit(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to JUnit XML.

    Each PHI finding becomes a <testcase> with a <failure> child. Consumed
    by CircleCI Test Summary, Jenkins, Azure DevOps, and GitHub Actions test
    reporting panels.

    Args:
        scan_result: The completed scan result.

    Returns:
        JUnit XML string with an XML declaration, UTF-8 encoded.
    """
    suite_attrs = {
        "name": _JUNIT_TESTSUITE_NAME,
        "tests": str(len(scan_result.findings)),
        "failures": str(len(scan_result.findings)),
        "errors": _JUNIT_ERROR_COUNT,
        "time": _JUNIT_DURATION_FORMAT.format(scan_result.scan_duration),
    }
    suite = ElementTree.Element(_JUNIT_TESTSUITE_TAG, suite_attrs)
    for finding in scan_result.findings:
        suite.append(_build_junit_testcase(finding))
    ElementTree.indent(suite, space=_JUNIT_INDENT)
    serialized_xml_buffer = io.BytesIO()
    ElementTree.ElementTree(suite).write(
        serialized_xml_buffer, encoding=_JUNIT_ENCODING, xml_declaration=True
    )
    return serialized_xml_buffer.getvalue().decode(_JUNIT_ENCODING)


def format_codequality(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to the GitLab Code Quality JSON format.

    Produces the gl-code-quality-report.json schema. Findings appear as
    inline MR annotations in GitLab's merge request view.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented JSON array — one entry per finding; empty array when clean.
    """
    entries = [_build_codequality_entry(finding) for finding in scan_result.findings]
    return json.dumps(entries, indent=_JSON_INDENT)


def format_gitlab_sast(scan_result: ScanResult) -> str:
    """Serialize a ScanResult to the GitLab SAST JSON format (v15.0.4).

    Produces the gl-sast-report.json schema. Findings appear in GitLab's
    Security Dashboard and as MR security annotations.

    Args:
        scan_result: The completed scan result.

    Returns:
        Indented SAST JSON string — empty vulnerabilities array when clean.
    """
    sast_doc: dict[str, object] = {
        "version": _GITLAB_SAST_VERSION,
        "vulnerabilities": [
            _build_gitlab_sast_vulnerability(finding) for finding in scan_result.findings
        ],
        "scan": _build_gitlab_sast_scan_section(scan_result),
    }
    return json.dumps(sast_doc, indent=_JSON_INDENT)
