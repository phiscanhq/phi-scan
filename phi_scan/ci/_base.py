"""Base adapter class for CI/CD platform integrations.

All per-platform adapters inherit from ``BaseCIAdapter`` and implement
the two core methods: ``post_pr_comment`` and ``set_commit_status``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from phi_scan.ci._detect import PRContext
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanResult

__all__ = [
    "BaseCIAdapter",
]

_UNSUPPORTED_OPERATION_MESSAGE: str = "{adapter_name} does not support {operation}"


class BaseCIAdapter(ABC):
    """Abstract base class for per-platform CI/CD adapters.

    Each adapter encapsulates the platform-specific logic for posting
    PR comments and setting commit statuses.
    """

    @abstractmethod
    def post_pr_comment(self, comment_body: str, pr_context: PRContext) -> None:
        """Post a comment on the PR/MR associated with this build.

        Args:
            comment_body: Markdown comment text.
            pr_context: Platform context extracted from environment variables.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @abstractmethod
    def set_commit_status(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        """Report pass/fail status on the commit that triggered the build.

        Args:
            scan_result: The completed scan result.
            pr_context: Platform context extracted from environment variables.

        Raises:
            CIIntegrationError: On any HTTP or auth failure.
        """

    @property
    def supports_commit_status(self) -> bool:
        """Whether this platform supports setting commit status directly."""
        return True

    @property
    def supports_sarif_upload(self) -> bool:
        """Whether this platform supports native SARIF ingestion."""
        return False

    @property
    def supports_code_insights(self) -> bool:
        """Whether this platform supports inline code annotations."""
        return False

    @property
    def supports_work_item_creation(self) -> bool:
        """Whether this platform supports creating work items from findings."""
        return False

    @property
    def supports_security_hub(self) -> bool:
        """Whether this platform supports AWS Security Hub import."""
        return False

    def _raise_unsupported(self, operation: str) -> None:
        raise CIIntegrationError(
            _UNSUPPORTED_OPERATION_MESSAGE.format(
                adapter_name=type(self).__name__,
                operation=operation,
            )
        )

    def upload_sarif(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        """Upload SARIF to the platform's code scanning API."""
        self._raise_unsupported("SARIF upload")
