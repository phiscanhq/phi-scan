"""Bitbucket Code Insights report + inline annotations.

Extracted from phi_scan.ci_integration. Call sites continue to import from
phi_scan.ci_integration via re-export; this module owns the implementation.
"""

from __future__ import annotations

import logging
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
                "title": "Total findings",
                "type": _BITBUCKET_DATA_TYPE_NUMBER,
                "value": findings_count,
            },
            {
                "title": "Risk level",
                "type": _BITBUCKET_DATA_TYPE_TEXT,
                "value": scan_result.risk_level.value,
            },
        ],
    }


def _build_annotations(scan_result: ScanResult) -> list[dict[str, Any]]:
    return [
        {
            "external_id": f"phi-scan-{finding.file_path}-{finding.line_number}-{annotation_index}",
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


def post_bitbucket_code_insights(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Post Bitbucket Code Insights report and inline annotations."""
    sha = pr_context.sha
    workspace = pr_context.extras.get("workspace", "")
    repo_slug = pr_context.extras.get("repo_slug", "")

    if not sha or not workspace or not repo_slug:
        _LOG.debug("Bitbucket Code Insights: missing context — skipping")
        return

    token = fetch_environment_variable(_ENV_BITBUCKET_TOKEN)
    if not token:
        _LOG.warning("Bitbucket: BITBUCKET_TOKEN not set — skipping Code Insights")
        return

    headers = {
        "Authorization": _AUTHORIZATION_BEARER_PREFIX + token,
        "Content-Type": _JSON_CONTENT_TYPE,
    }
    report_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_REPORTS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
        report_id=_BITBUCKET_REPORT_ID,
    )

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.PUT,
            url=report_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_REPORT,
            headers=headers,
            json_body=_build_report_payload(scan_result),
        )
    )

    if not scan_result.findings:
        return

    annotations_url = _BITBUCKET_API_BASE_URL + _BITBUCKET_ANNOTATIONS_PATH.format(
        workspace=workspace,
        repo_slug=repo_slug,
        commit=sha,
        report_id=_BITBUCKET_REPORT_ID,
    )
    annotations = _build_annotations(scan_result)

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=annotations_url,
            operation_label=OperationLabel.BITBUCKET_CODE_INSIGHTS_ANNOTATIONS,
            headers=headers,
            json_body=annotations,
        )
    )

    _LOG.debug(
        "Bitbucket: Code Insights report + %d annotation(s) posted for %s",
        len(annotations),
        sha[:_SHA_LOG_PREFIX_LENGTH],
    )
