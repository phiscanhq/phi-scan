"""AWS Security Hub ASFF conversion + BatchImportFindings import.

Extracted from phi_scan.ci_integration. Call sites continue to import from
phi_scan.ci_integration via re-export; this module owns the implementation.

PHI safety: ASFF findings transmit classification metadata only
(hipaa_category label, entity_type, confidence, file path, line number).
Raw detected values and value_hash never enter the payload. The remediation
hint is a predefined template or ``None`` → default string; it does not
embed PHI.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from phi_scan.ci import PullRequestContext
from phi_scan.ci._env import fetch_environment_variable
from phi_scan.constants import SeverityLevel
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanFinding, ScanResult

_LOG: logging.Logger = logging.getLogger(__name__)

_MAX_ERROR_RESPONSE_LOG_LENGTH: int = 200

_AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT: str = (
    "arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
)
_AWS_SECURITY_HUB_HIGH_SEVERITY_LABEL: str = "HIGH"
_AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL: str = "MEDIUM"
_AWS_SECURITY_HUB_LOW_SEVERITY_LABEL: str = "LOW"
_AWS_SECURITY_HUB_INFO_SEVERITY_LABEL: str = "INFORMATIONAL"
_AWS_SECURITY_HUB_SEVERITY_MAP: dict[SeverityLevel, str] = {
    SeverityLevel.HIGH: _AWS_SECURITY_HUB_HIGH_SEVERITY_LABEL,
    SeverityLevel.MEDIUM: _AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL,
    SeverityLevel.LOW: _AWS_SECURITY_HUB_LOW_SEVERITY_LABEL,
    SeverityLevel.INFO: _AWS_SECURITY_HUB_INFO_SEVERITY_LABEL,
}
_AWS_SEVERITY_SCORE_MAP: dict[str, int] = {
    _AWS_SECURITY_HUB_HIGH_SEVERITY_LABEL: 70,
    _AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL: 40,
    _AWS_SECURITY_HUB_LOW_SEVERITY_LABEL: 10,
    _AWS_SECURITY_HUB_INFO_SEVERITY_LABEL: 0,
}
_AWS_DEFAULT_SEVERITY_SCORE: int = 40

_ASFF_SCHEMA_VERSION: str = "2018-10-08"
_ASFF_TIMESTAMP_FORMAT: str = "%Y-%m-%dT%H:%M:%S.000Z"
_ASFF_FINDING_TYPE: str = "Software and Configuration Checks/Vulnerabilities/CVE"
_ASFF_RESOURCE_TYPE_OTHER: str = "Other"
_ASFF_DEFAULT_REMEDIATION: str = "Remove or de-identify the PHI/PII value."
_ASFF_BATCH_KEY: str = "Findings"

_ENV_AWS_SECURITY_HUB_ENABLED: str = "AWS_SECURITY_HUB"
_ENV_AWS_SECURITY_HUB_ENABLED_VALUE: str = "true"
_ENV_AWS_ACCOUNT_ID: str = "AWS_ACCOUNT_ID"
_ENV_AWS_DEFAULT_REGION: str = "AWS_DEFAULT_REGION"
_ENV_AWS_REGION: str = "AWS_REGION"
_ENV_GITHUB_REPOSITORY: str = "GITHUB_REPOSITORY"
_DEFAULT_AWS_REGION: str = "us-east-1"
_DEFAULT_REPOSITORY: str = "unknown/repo"

_AWS_CLI_ARGS: tuple[str, ...] = (
    "aws",
    "securityhub",
    "batch-import-findings",
    "--cli-input-json",
)


@dataclass(frozen=True)
class _AsffConversionContext:
    """Immutable inputs shared across all ASFF finding dicts in one batch."""

    aws_account_id: str
    aws_region: str
    repository: str
    product_arn: str
    timestamp_iso: str


def _build_asff_finding(
    finding: ScanFinding, conversion_context: _AsffConversionContext
) -> dict[str, Any]:
    severity_label = _AWS_SECURITY_HUB_SEVERITY_MAP.get(
        finding.severity, _AWS_SECURITY_HUB_MEDIUM_SEVERITY_LABEL
    )
    severity_score = _AWS_SEVERITY_SCORE_MAP.get(severity_label, _AWS_DEFAULT_SEVERITY_SCORE)
    return {
        "SchemaVersion": _ASFF_SCHEMA_VERSION,
        "Id": (
            f"{conversion_context.repository}/{finding.file_path}/"
            f"{finding.line_number}/{finding.entity_type}"
        ),
        "ProductArn": conversion_context.product_arn,
        "GeneratorId": f"phi-scan/{finding.entity_type}",
        "AwsAccountId": conversion_context.aws_account_id,
        "Types": [_ASFF_FINDING_TYPE],
        "FirstObservedAt": conversion_context.timestamp_iso,
        "UpdatedAt": conversion_context.timestamp_iso,
        "CreatedAt": conversion_context.timestamp_iso,
        "Severity": {"Label": severity_label, "Normalized": severity_score},
        "Title": (
            f"PHI/PII detected: {finding.hipaa_category.value} "
            f"in {finding.file_path}:{finding.line_number}"
        ),
        "Description": (
            f"phi-scan detected a {finding.hipaa_category.value} ({finding.entity_type}) "
            f"with {finding.confidence:.0%} confidence at "
            f"{finding.file_path} line {finding.line_number}. "
            "No raw value is stored — only a one-way hash of the detected entity."
        ),
        "Remediation": {
            "Recommendation": {
                "Text": finding.remediation_hint or _ASFF_DEFAULT_REMEDIATION,
            }
        },
        "SourceUrl": (
            f"https://github.com/{conversion_context.repository}/blob/HEAD/"
            f"{finding.file_path}#L{finding.line_number}"
        ),
        "Resources": [
            {
                "Type": _ASFF_RESOURCE_TYPE_OTHER,
                "Id": f"file://{finding.file_path}",
                "Details": {
                    "Other": {
                        "line_number": str(finding.line_number),
                        "entity_type": finding.entity_type,
                        "hipaa_category": finding.hipaa_category.value,
                        "confidence": f"{finding.confidence:.4f}",
                    }
                },
            }
        ],
    }


def convert_findings_to_asff(
    scan_result: ScanResult,
    aws_account_id: str,
    aws_region: str,
    repository: str,
) -> list[dict[str, Any]]:
    """Convert phi-scan findings to AWS Security Finding Format (ASFF)."""
    conversion_context = _AsffConversionContext(
        aws_account_id=aws_account_id,
        aws_region=aws_region,
        repository=repository,
        product_arn=_AWS_SECURITY_HUB_PRODUCT_ARN_FORMAT.format(
            region=aws_region, account_id=aws_account_id
        ),
        timestamp_iso=datetime.now(tz=UTC).strftime(_ASFF_TIMESTAMP_FORMAT),
    )
    return [_build_asff_finding(finding, conversion_context) for finding in scan_result.findings]


def _resolve_security_hub_inputs(pr_context: PullRequestContext) -> tuple[str, str, str] | None:
    account_id = fetch_environment_variable(_ENV_AWS_ACCOUNT_ID) or ""
    if not account_id:
        _LOG.warning("Security Hub: AWS_ACCOUNT_ID not set — skipping")
        return None
    region = (
        fetch_environment_variable(_ENV_AWS_DEFAULT_REGION)
        or fetch_environment_variable(_ENV_AWS_REGION)
        or _DEFAULT_AWS_REGION
    )
    repository = (
        pr_context.repository
        or fetch_environment_variable(_ENV_GITHUB_REPOSITORY)
        or _DEFAULT_REPOSITORY
    )
    return account_id, region, repository


def _invoke_aws_cli_batch_import(findings_json: str) -> None:
    try:
        aws_cli_result = subprocess.run(
            [*_AWS_CLI_ARGS, findings_json],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as not_found_error:
        raise CIIntegrationError(
            "AWS CLI not found — install awscli to enable Security Hub integration"
        ) from not_found_error
    if aws_cli_result.returncode != 0:
        raise CIIntegrationError(
            f"AWS Security Hub import failed (exit {aws_cli_result.returncode}): "
            f"{aws_cli_result.stderr.strip()[:_MAX_ERROR_RESPONSE_LOG_LENGTH]}"
        )


def import_findings_to_security_hub(
    scan_result: ScanResult,
    pr_context: PullRequestContext,
) -> None:
    """Import phi-scan findings to AWS Security Hub via BatchImportFindings."""
    if (
        fetch_environment_variable(_ENV_AWS_SECURITY_HUB_ENABLED)
        != _ENV_AWS_SECURITY_HUB_ENABLED_VALUE
    ):
        _LOG.debug("Security Hub: AWS_SECURITY_HUB not enabled — skipping")
        return

    if scan_result.is_clean:
        _LOG.debug("Security Hub: no findings to import")
        return

    resolved_inputs = _resolve_security_hub_inputs(pr_context)
    if resolved_inputs is None:
        return
    account_id, region, repository = resolved_inputs

    asff_findings = convert_findings_to_asff(scan_result, account_id, region, repository)
    findings_json = json.dumps({_ASFF_BATCH_KEY: asff_findings})
    _invoke_aws_cli_batch_import(findings_json)

    _LOG.debug("Security Hub: imported %d ASFF finding(s)", len(asff_findings))
