"""Base adapter class for CI/CD platform integrations.

All per-platform adapters inherit from ``BaseCIAdapter`` and implement
the two core methods: ``post_pr_comment`` and ``set_commit_status``.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import NewType, NoReturn

from phi_scan.ci._detect import PRContext
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanResult


class UnsupportedOperation(enum.StrEnum):
    """Named operations that an adapter may not support.

    ``COMMIT_STATUS`` is used by adapters whose ``set_commit_status``
    implementation explicitly aborts (e.g. AzureAdapter), since
    ``set_commit_status`` is abstract rather than a default-abort stub.
    """

    COMMIT_STATUS = "commit status"
    SARIF_UPLOAD = "SARIF upload"
    CODE_ANNOTATIONS = "code annotations"
    WORK_ITEM_CREATION = "work item creation"
    SECURITY_HUB_IMPORT = "Security Hub import"


SanitisedCommentBody = NewType("SanitisedCommentBody", str)
"""A comment string verified to contain only hashed references and
redacted metadata — never raw PHI values, code snippets, or matched
strings.  Created by ``build_comment_body`` in ``ci_integration``.
"""

__all__ = [
    "BaseCIAdapter",
    "SanitisedCommentBody",
]

_UNSUPPORTED_OPERATION_MESSAGE: str = "{adapter_name} does not support {operation_name}"


class BaseCIAdapter(ABC):
    """Abstract base class for per-platform CI/CD adapters.

    Each adapter encapsulates the platform-specific logic for posting
    PR comments and setting commit statuses.
    """

    @abstractmethod
    def post_pr_comment(self, comment_body: SanitisedCommentBody, pr_context: PRContext) -> None:
        """Post a comment on the PR/MR associated with this build.

        ``comment_body`` is typed as ``SanitisedCommentBody`` to enforce
        at the type level that only pre-sanitised content (hashed
        references, redacted metadata) reaches an external API.  Use
        ``build_comment_body`` in ``ci_integration`` to create one.

        Args:
            comment_body: Pre-sanitised Markdown comment text.
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
    def can_post_commit_status(self) -> bool:
        """Whether this platform supports setting commit status directly."""
        return True

    @property
    def can_upload_sarif_report(self) -> bool:
        """Whether this platform supports native SARIF ingestion."""
        return False

    @property
    def can_annotate_code_findings(self) -> bool:
        """Whether this platform supports inline code annotations."""
        return False

    @property
    def can_create_work_item_from_findings(self) -> bool:
        """Whether this platform supports creating work items from findings."""
        return False

    @property
    def can_import_findings_to_security_hub(self) -> bool:
        """Whether this platform supports AWS Security Hub import."""
        return False

    def _abort_unsupported_operation(self, operation_name: UnsupportedOperation) -> NoReturn:
        raise CIIntegrationError(
            _UNSUPPORTED_OPERATION_MESSAGE.format(
                adapter_name=type(self).__name__,
                operation_name=operation_name,
            )
        )

    def upload_sarif_report(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        """Upload SARIF to the platform's code scanning API."""
        self._abort_unsupported_operation(UnsupportedOperation.SARIF_UPLOAD)

    def annotate_code_findings(self, scan_result: ScanResult, pr_context: PRContext) -> None:
        """Post inline code annotations to the platform."""
        self._abort_unsupported_operation(UnsupportedOperation.CODE_ANNOTATIONS)

    def create_work_item_from_findings(
        self, scan_result: ScanResult, pr_context: PRContext
    ) -> None:
        """Create a work item or ticket from scan findings."""
        self._abort_unsupported_operation(UnsupportedOperation.WORK_ITEM_CREATION)

    def import_findings_to_security_hub(
        self, scan_result: ScanResult, pr_context: PRContext
    ) -> None:
        """Import findings into AWS Security Hub."""
        self._abort_unsupported_operation(UnsupportedOperation.SECURITY_HUB_IMPORT)
