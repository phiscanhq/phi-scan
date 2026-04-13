"""SARIF upload to GitHub Code Scanning — extracted from ci_integration.py.

Owns the full SARIF upload path: PHI-safety verification (no code snippets
or contextRegions), gzip + base64 encoding, and the authenticated POST to
the GitHub Code Scanning API.

This module is imported by phi_scan.ci_integration for backward-compatible
re-export. Call sites continue to import from phi_scan.ci_integration.
"""

from __future__ import annotations

import base64
import gzip
import json
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
from phi_scan.exceptions import CIIntegrationError
from phi_scan.models import ScanResult
from phi_scan.output import format_sarif

_LOG: logging.Logger = logging.getLogger(__name__)

_ENV_GITHUB_TOKEN: str = "GITHUB_TOKEN"
_GITHUB_API_BASE_URL: str = "https://api.github.com"
_GITHUB_API_SARIF_UPLOAD_PATH: str = "/repos/{repository}/code-scanning/sarifs"
_SARIF_MAX_MESSAGE_TEXT_LENGTH: int = 1_500
_DEFAULT_GIT_REF: str = "refs/heads/main"
_SARIF_TOOL_NAME: str = "phi-scan"
_GITHUB_API_ACCEPT_HEADER: str = "application/vnd.github+json"
_GITHUB_API_VERSION_HEADER_VALUE: str = "2022-11-28"
_AUTHORIZATION_BEARER_PREFIX: str = "Bearer "
_SHA_LOG_PREFIX_LENGTH: int = 8


def _verify_sarif_location_excludes_snippet(location: dict[str, Any]) -> None:
    """Raise CIIntegrationError if a single SARIF location carries a code snippet."""
    physical_location = location.get("physicalLocation", {})
    region = physical_location.get("region", {})
    if "snippet" in region:
        raise CIIntegrationError(
            "SARIF upload aborted: code snippet detected in SARIF output — "
            "uploading would expose raw source content to GitHub Code Scanning API"
        )
    if "contextRegion" in physical_location:
        raise CIIntegrationError(
            "SARIF upload aborted: contextRegion detected in SARIF output — "
            "uploading would expose raw source content to GitHub Code Scanning API"
        )


def _verify_sarif_excludes_code_snippets(sarif_content: str) -> None:
    """Verify the SARIF output contains no code snippet or contextRegion fields."""
    sarif_doc: dict[str, Any] = json.loads(sarif_content)
    for sarif_run in sarif_doc.get("runs", []):
        for sarif_result in sarif_run.get("results", []):
            message_text = sarif_result.get("message", {}).get("text", "")
            if len(message_text) > _SARIF_MAX_MESSAGE_TEXT_LENGTH:
                raise CIIntegrationError(
                    f"SARIF upload aborted: message.text length {len(message_text)} "
                    f"exceeds limit of {_SARIF_MAX_MESSAGE_TEXT_LENGTH} — "
                    "unexpected content may be embedded"
                )
            for location in sarif_result.get("locations", []):
                _verify_sarif_location_excludes_snippet(location)


def _gzip_compress_sarif(sarif_content: str) -> bytes:
    return gzip.compress(sarif_content.encode("utf-8"))


def _base64_encode_bytes(raw_bytes: bytes) -> str:
    return base64.b64encode(raw_bytes).decode("ascii")


def upload_sarif_to_github(scan_result: ScanResult, pr_context: PullRequestContext) -> None:
    """Upload a SARIF report to the GitHub Code Scanning API for inline annotations."""
    repository = pr_context.repository
    sha = pr_context.sha
    if not repository or not sha:
        _LOG.debug("GitHub SARIF upload: missing repository or SHA — skipping")
        return

    token = fetch_environment_variable(_ENV_GITHUB_TOKEN)
    if not token:
        _LOG.warning("GitHub SARIF upload: GITHUB_TOKEN not set — skipping")
        return

    sarif_content = format_sarif(scan_result)
    _verify_sarif_excludes_code_snippets(sarif_content)
    sarif_base64_encoded = _base64_encode_bytes(_gzip_compress_sarif(sarif_content))

    url = _GITHUB_API_BASE_URL + _GITHUB_API_SARIF_UPLOAD_PATH.format(repository=repository)
    sarif_upload_payload = {
        "commit_sha": sha,
        "ref": pr_context.branch or _DEFAULT_GIT_REF,
        "sarif": sarif_base64_encoded,
        "tool_name": _SARIF_TOOL_NAME,
    }

    execute_http_request(
        HttpRequestConfig(
            method=HttpMethod.POST,
            url=url,
            operation_label=OperationLabel.GITHUB_SARIF_UPLOAD,
            headers={
                "Authorization": _AUTHORIZATION_BEARER_PREFIX + token,
                "Accept": _GITHUB_API_ACCEPT_HEADER,
                "X-GitHub-Api-Version": _GITHUB_API_VERSION_HEADER_VALUE,
            },
            json_body=sarif_upload_payload,
        )
    )

    _LOG.debug("GitHub: SARIF uploaded to Code Scanning for %s", sha[:_SHA_LOG_PREFIX_LENGTH])
