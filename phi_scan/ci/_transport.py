"""Shared HTTP transport for CI/CD platform adapters.

Centralises the request/error pattern so that every outbound HTTP call
across all platform adapters goes through a single code path with
consistent error wrapping, timeout handling, and PHI-safety guarantees.

Security contract:
  - Error messages include only the numeric HTTP status code.
  - Reason phrases are excluded — proxies and WAFs can echo request
    fragments in non-standard reason phrases.
  - Response bodies are never included in error messages — API error
    responses for comment endpoints could echo back request content
    containing finding metadata.
  - ``operation_label`` propagates into exception messages and logs.
    It is typed as ``OperationLabel`` (a ``StrEnum``) so only pre-defined
    static labels are accepted — no dynamic content can leak into errors.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

import httpx

from phi_scan.exceptions import CIIntegrationError

__all__ = [
    "HttpMethod",
    "HttpRequestConfig",
    "OperationLabel",
    "execute_http_request",
]

_HTTP_TIMEOUT_SECONDS: float = 15.0
_HTTP_STATUS_ERROR_TEMPLATE: str = "{operation} failed (HTTP {status_code})"
_NETWORK_ERROR_TEMPLATE: str = "{operation} request failed (network error)"


class HttpMethod(enum.StrEnum):
    """HTTP methods used by CI/CD platform API calls."""

    POST = "POST"
    PUT = "PUT"


class OperationLabel(enum.StrEnum):
    """Labels for outbound CI/CD HTTP operations.

    Each member is a static string that appears in error messages and logs.
    Using an enum enforces the security contract: callers cannot interpolate
    PR content, file paths, or finding metadata into error messages.
    """

    GITHUB_COMMIT_STATUS = "GitHub commit status"
    GITHUB_SARIF_UPLOAD = "GitHub SARIF upload"
    GITLAB_MR_COMMENT = "GitLab MR comment"
    GITLAB_COMMIT_STATUS = "GitLab commit status"
    AZURE_PR_COMMENT = "Azure DevOps PR comment"
    AZURE_BUILD_TAG = "Azure DevOps build tag"
    AZURE_PR_STATUS = "Azure DevOps PR status"
    AZURE_WORK_ITEM = "Azure Boards work item"
    BITBUCKET_PR_COMMENT = "Bitbucket PR comment"
    BITBUCKET_COMMIT_STATUS = "Bitbucket commit status"
    BITBUCKET_CODE_INSIGHTS_REPORT = "Bitbucket Code Insights report"
    BITBUCKET_CODE_INSIGHTS_ANNOTATIONS = "Bitbucket Code Insights annotations"


@dataclass(frozen=True)
class HttpRequestConfig:
    """Parameters for a single outbound HTTP request.

    Bundles all variable parts of the request so that
    ``execute_http_request`` can centralise the try/except scaffolding.

    ``operation_label`` appears in error messages and logs — typed as
    ``OperationLabel`` to enforce that only static labels are used.
    """

    method: HttpMethod
    url: str
    operation_label: OperationLabel
    headers: dict[str, str] | None = None
    json_body: dict[str, Any] | list[Any] | None = None
    binary_body: bytes | None = None
    basic_auth_credentials: tuple[str, str] | None = None
    timeout_seconds: float = _HTTP_TIMEOUT_SECONDS


def _assemble_request_options(request_config: HttpRequestConfig) -> dict[str, Any]:
    request_options: dict[str, Any] = {"timeout": request_config.timeout_seconds}
    if request_config.headers is not None:
        request_options["headers"] = request_config.headers
    if request_config.json_body is not None:
        request_options["json"] = request_config.json_body
    if request_config.binary_body is not None:
        request_options["content"] = request_config.binary_body
    if request_config.basic_auth_credentials is not None:
        request_options["auth"] = request_config.basic_auth_credentials
    return request_options


def execute_http_request(request_config: HttpRequestConfig) -> httpx.Response:
    """Execute one HTTP request and translate httpx errors to CIIntegrationError.

    Args:
        request_config: All parameters for the HTTP call.

    Returns:
        The successful ``httpx.Response``.

    Raises:
        CIIntegrationError: On HTTP 4xx/5xx or any network error.
    """
    request_options = _assemble_request_options(request_config)
    try:
        response = httpx.request(request_config.method, request_config.url, **request_options)
        response.raise_for_status()
    except httpx.HTTPStatusError as status_error:
        raise CIIntegrationError(
            _HTTP_STATUS_ERROR_TEMPLATE.format(
                operation=request_config.operation_label,
                status_code=status_error.response.status_code,
            )
        ) from status_error
    except httpx.RequestError as request_error:
        raise CIIntegrationError(
            _NETWORK_ERROR_TEMPLATE.format(operation=request_config.operation_label)
        ) from request_error
    return response
