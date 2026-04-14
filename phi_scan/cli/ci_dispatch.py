"""CI/CD integration dispatch for the `phi-scan scan` command.

Runs PR comments, commit statuses, SARIF uploads, Azure DevOps extras,
Bitbucket Code Insights, and AWS Security Hub imports after a scan
completes. Each integration failure is logged as a warning and also
surfaced to the Rich console when the command is running in rich mode;
a single integration error never aborts the scan.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from phi_scan.ci_integration import (
    CIIntegrationError,
    CIPlatform,
    create_azure_boards_work_item,
    get_pr_context,
    import_findings_to_security_hub,
    post_bitbucket_code_insights,
    post_pr_comment,
    set_azure_build_tag,
    set_azure_pr_status,
    set_commit_status,
    upload_sarif_to_github,
)
from phi_scan.logging_config import get_logger
from phi_scan.models import ScanResult
from phi_scan.output import get_console

_logger = get_logger("cli")

_CI_LABEL_PR_COMMENT: str = "PR comment"
_CI_LABEL_COMMIT_STATUS: str = "commit status"
_CI_LABEL_AZURE_PR_STATUS: str = "Azure PR status"
_CI_LABEL_AZURE_BUILD_TAG: str = "Azure build tag"
_CI_LABEL_AZURE_BOARDS: str = "Azure Boards work item"
_CI_LABEL_BITBUCKET_INSIGHTS: str = "Bitbucket Code Insights"
_CI_LABEL_SARIF_UPLOAD: str = "SARIF upload"
_CI_LABEL_SECURITY_HUB: str = "Security Hub import"
_CI_INTEGRATION_FAILURE_LOG: str = "CI integration (%s) failed: %s"
_CI_INTEGRATION_RICH_WARNING: str = "[yellow]Warning:[/yellow] {label} failed — {error}"


@dataclass(frozen=True)
class CIIntegrationOptions:
    """Flags controlling which CI/CD integrations run after a scan."""

    should_post_comment: bool
    should_set_status: bool
    should_upload_sarif: bool

    @property
    def has_any_enabled(self) -> bool:
        """Return True when at least one integration flag is enabled."""
        return self.should_post_comment or self.should_set_status or self.should_upload_sarif


def _call_ci_integration(operation: Callable[[], None], label: str, is_rich_mode: bool) -> None:
    """Execute a CI integration operation, logging warnings on failure."""
    try:
        operation()
    except CIIntegrationError as integration_error:
        _logger.warning(_CI_INTEGRATION_FAILURE_LOG, label, integration_error)
        if is_rich_mode:
            get_console().print(
                _CI_INTEGRATION_RICH_WARNING.format(label=label, error=integration_error)
            )


def _dispatch_azure_devops_extras(
    scan_result: ScanResult, pr_context: Any, is_rich_mode: bool
) -> None:
    """Run Azure-specific PR status, build tag, and Boards work-item calls."""
    _call_ci_integration(
        lambda: set_azure_pr_status(scan_result, pr_context),
        _CI_LABEL_AZURE_PR_STATUS,
        is_rich_mode,
    )
    _call_ci_integration(
        lambda: set_azure_build_tag(scan_result, pr_context),
        _CI_LABEL_AZURE_BUILD_TAG,
        is_rich_mode,
    )
    _call_ci_integration(
        lambda: create_azure_boards_work_item(scan_result, pr_context),
        _CI_LABEL_AZURE_BOARDS,
        is_rich_mode,
    )


def _dispatch_commit_status_integrations(
    scan_result: ScanResult, pr_context: Any, is_rich_mode: bool
) -> None:
    """Post the generic commit status plus platform-specific status extras."""
    _call_ci_integration(
        lambda: set_commit_status(scan_result, pr_context),
        _CI_LABEL_COMMIT_STATUS,
        is_rich_mode,
    )
    if pr_context.platform is CIPlatform.AZURE_DEVOPS:
        _dispatch_azure_devops_extras(scan_result, pr_context, is_rich_mode)
    if pr_context.platform is CIPlatform.BITBUCKET:
        _call_ci_integration(
            lambda: post_bitbucket_code_insights(scan_result, pr_context),
            _CI_LABEL_BITBUCKET_INSIGHTS,
            is_rich_mode,
        )


def dispatch_ci_integrations(
    scan_result: ScanResult,
    integration_options: CIIntegrationOptions,
    is_rich_mode: bool,
) -> None:
    """Dispatch all enabled CI/CD platform integrations after a scan completes."""
    if not integration_options.has_any_enabled:
        return

    pr_context = get_pr_context()

    if integration_options.should_post_comment:
        _call_ci_integration(
            lambda: post_pr_comment(scan_result, pr_context),
            _CI_LABEL_PR_COMMENT,
            is_rich_mode,
        )
    if integration_options.should_set_status:
        _dispatch_commit_status_integrations(scan_result, pr_context, is_rich_mode)
    if integration_options.should_upload_sarif:
        _call_ci_integration(
            lambda: upload_sarif_to_github(scan_result, pr_context),
            _CI_LABEL_SARIF_UPLOAD,
            is_rich_mode,
        )

    _call_ci_integration(
        lambda: import_findings_to_security_hub(scan_result, pr_context),
        _CI_LABEL_SECURITY_HUB,
        is_rich_mode,
    )
