"""Bitbucket Code Insights report + inline annotations.

Extracted from phi_scan.ci_integration. Call sites continue to import from
phi_scan.ci_integration via re-export; this module owns the implementation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from phi_scan.ci import PullRequestContext
from phi_scan.ci._env import fetch_environment_variable
from phi_scan.ci._transport import (
    HttpMethod,
    HttpRequestConfig,
    OperationLabel,
    execute_http_request,
)
from phi_scan.constants import SeverityLevel
from phi_scan.models import ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_ENV_BITBUCKET_TOKEN: str = "BITBUCKET_TOKEN"
_JSON_CONTENT_TYPE: str = "application/json"
_AUTHORIZATION_BEARER_PREFIX: str = "Bearer "

_BITBUCKET_API_BASE_URL: str = "https://api.bitbucket.org/2.0"
_BITBUCKET_REPORTS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}"
)
_BITBUCKET_ANNOTATIONS_PATH: str = (
    "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_id}/annotations"
)
_BITBUCKET_REPORT_ID: str = "phi-scan"
_BITBUCKET_REPORT_TITLE: str = "phi-scan PHI/PII Scan"
_BITBUCKET_REPORT_TYPE: str = "SECURITY"
_BITBUCKET_REPORTER: str = "phi-scan"
_BITBUCKET_RESULT_PASSED: str = "PASSED"
_BITBUCKET_RESULT_FAILED: str = "FAILED"
_BITBUCKET_ANNOTATION_TYPE_VULNERABILITY: str = "VULNERABILITY"
_BITBUCKET_DATA_TYPE_NUMBER: str = "NUMBER"
_BITBUCKET_DATA_TYPE_TEXT: str = "TEXT"
_BITBUCKET_ANNOTATION_DEFAULT_SEVERITY: str = "MEDIUM"

_BITBUCKET_HIGH_SEVERITY_LABEL: str = "HIGH"
_BITBUCKET_MEDIUM_SEVERITY_LABEL: str = "MEDIUM"
_BITBUCKET_LOW_SEVERITY_LABEL: str = "LOW"
_BITBUCKET_INFO_SEVERITY_LABEL: str = _BITBUCKET_LOW_SEVERITY_LABEL
_BITBUCKET_ANNOTATION_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _BITBUCKET_HIGH_SEVERITY_LABEL,
    SeverityLevel.MEDIUM: _BITBUCKET_MEDIUM_SEVERITY_LABEL,
    SeverityLevel.LOW: _BITBUCKET_LOW_SEVERITY_LABEL,
    SeverityLevel.INFO: _BITBUCKET_INFO_SEVERITY_LABEL,
}

_BITBUCKET_ANNOTATIONS_BATCH_LIMIT: int = 1000
_SHA_LOG_PREFIX_LENGTH: int = 8
_BITBUCKET_ANNOTATION_EXTERNAL_ID_PREFIX: str = "phi-scan-"
_BITBUCKET_DATA_TITLE_TOTAL_FINDINGS: str = "Total findings"
_BITBUCKET_DATA_TITLE_RISK_LEVEL: str = "Risk level"

# PR context extras keys — set by phi_scan.ci.bitbucket when the adapter
# extracts workspace/repo identity from CI environment variables.
_EXTRAS_KEY_WORKSPACE: str = "workspace"
_EXTRAS_KEY_REPO_SLUG: str = "repo_slug"

# PHI safety contract for the Bitbucket Code Insights payload:
# - `path` and `line` expose source-file location metadata (non-PHI).
# - `message` embeds ScanFinding classification labels only — hipaa_category
#   (enum value like "SSN"), severity (enum value like "HIGH"), and a rounded
#   confidence percentage. No finding.value, value_hash, code_context, or
#   remediation_hint ever enters the payload. This is verified by
#   tests/test_ci_integration_remaining.py exercising the JSON body.


def _build_report_payload(scan_result: ScanResult) -> dict[str, Any]:
    findings_count = len(scan_result.findings)
    report_result = _BITBUCKET_RESULT_PASSED if scan_result.is_clean else _BITBUCKET_RESULT_FAILED
    return {
        "title": _BITBUCKET_REPORT_TITLE,
        "report_type": _BITBUCKET_REPORT_TYPE,
        "reporter": _BITBUCKET_REPORTER,
        "result": report_result,
        "data": [
            {
                "title": _BITBUCKET_DATA_TITLE_TOTAL_FINDINGS,
                "type": _BITBUCKET_DATA_TYPE_NUMBER,
                "value": findings_count,
            },
            {
                "title": _BITBUCKET_DATA_TITLE_RISK_LEVEL,
                "type": _BITBUCKET_DATA_TYPE_TEXT,
                "value": scan_result.risk_level.value,
            },
        ],
    }


def _build_annotations(scan_result: ScanResult) -> list[dict[str, Any]]:
    return [
        {
            "external_id": (
                f"{_BITBUCKET_ANNOTATION_EXTERNAL_ID_PREFIX}"
                f"{finding.file_path}-{finding.line_number}-{annotation_index}"
            ),
            "annotation_type": _BITBUCKET_ANNOTATION_TYPE_VULNERABILITY,
            "path": str(finding.file_path),
            "line": finding.line_number,
            "message": (
                f"{finding.hipaa_category.value} detected "
                f"({finding.severity.value}, {finding.confidence:.0%} confidence)"
            ),
            "severity": _BITBUCKET_ANNOTATION_SEVERITY_MAP.get(
                finding.severity, _BITBUCKET_ANNOTATION_DEFAULT_SEVERITY
            ),
        }
        for annotation_index, finding in enumerate(
            scan_result.findings[:_BITBUCKET_ANNOTATIONS_BATCH_LIMIT]
        )
    ]


@dataclass(frozen=True)
class _BitbucketReportContext:
    """Bundle of request values shared by the report + annotations POSTs."""

    headers: dict[str, str]
    workspace: str
    repo_slug: str
    sha: str


def _post_report(report_context: _BitbucketReportContext, scan_result: ScanResult) -> None:
    report_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_REPORTS_PATH.format(
        workspace=report_context.workspace,
        repo_slug=report_context.repo_slug,
        commit=report_context.sha,
        report_id=_BITBUCKET_REPORT_ID,
    )
    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.PUT,
            url=report_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_REPORT,
            headers=report_context.headers,
            json_body=_build_report_payload(scan_result),
        )
    )


def _post_annotations(report_context: _BitbucketReportContext, scan_result: ScanResult) -> int:
    annotations_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_ANNOTATIONS_PATH.format(
        workspace=report_context.workspace,
        repo_slug=report_context.repo_slug,
        commit=report_context.sha,
        report_id=_BITBUCKET_REPORT_ID,
    )
    annotations = _build_annotations(scan_result)
    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=annotations_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_ANNOTATIONS,
            headers=report_context.headers,
            json_body=annotations,
        )
    )
    return len(annotations)


def post_bitbucket_code_insights(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Post Bitbucket Code Insights report and inline annotations."""
    sha = pr_context.sha
    workspace = pr_context.extras.get(_EXTRAS_KEY_WORKSPACE, "")
    repo_slug = pr_context.extras.get(_EXTRAS_KEY_REPO_SLUG, "")

    if not sha or not workspace or not repo_slug:
        _LOG.debug("Bitbucket Code Insights: missing context — skipping")
        return

    token = fetch_environment_variable(_ENV_BITBUCKET_TOKEN)
    if not token:
        _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping Code Insights")
        return

    report_context = _BitbucketReportContext(
        headers={
            "Authorization": _AUTHORIZATION_BEARER_PREFIX + token,
            "Content-Type": _JSON_CONTENT_TYPE,
        },
        workspace=workspace,
        repo_slug=repo_slug,
        sha=sha,
    )

    _post_report(report_context, scan_result)

    if not scan_result.findings:
        return

    annotations_count = _post_annotations(report_context, scan_result)

    _LOG.debug(
        "Bitbucket: Code Insights report + %d annotation(s) posted for %s",
        annotations_count,
        sha[:_SHA_LOG_PREFIX_LENGTH],
    )
