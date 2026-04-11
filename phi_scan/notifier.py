# phi-scan:ignore-next-line
"""Email and webhook notification delivery (Phase 5).

Implements two delivery channels:

  Email (5A) — ``send_email_notification``
    Sends a Rich-formatted HTML email via SMTP/STARTTLS when PHI is detected.
    TLS is required; plaintext SMTP connections are rejected at delivery time.
    Subject format: see NOTIFICATION_SUBJECT_FORMAT in constants.py.
    An HTML or PDF report may be attached when a report_path is provided.

  Webhooks (5B) — ``send_webhook_notification``
    POSTs a findings JSON payload to a configured URL. Supports Slack Block Kit,
    Microsoft Teams Adaptive Cards, and a generic JSON schema. Uses the ``httpx``
    sync client with configurable retry count and a 10-second per-attempt timeout.

Both functions are best-effort: they catch delivery failures and raise
``NotificationError`` so the caller can log a warning without aborting the scan.
Raw PHI values are never included in any notification payload — only hashed
findings metadata (entity_type, hipaa_category, severity, value_hash).

Design constraints:
- All notification delivery is synchronous — no background threads or tasks.
- Notification failures must never suppress audit log writes or scan output.
- SMTP credentials (username, password) are read from environment variables only
  (``PHI_SCAN_SMTP_USER``, ``PHI_SCAN_SMTP_PASSWORD``) — never from config files.
"""

from __future__ import annotations

import html
import ipaddress
import logging
import os
import smtplib
import socket
from dataclasses import dataclass
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import ParseResult, urlparse, urlunparse

import httpx

from phi_scan.constants import (
    ACTION_TAKEN_FAIL,
    ACTION_TAKEN_PASS,
    NOTIFICATION_SUBJECT_FORMAT,
    WEBHOOK_DEFAULT_TIMEOUT_SECONDS,
    WebhookType,
)
from phi_scan.exceptions import NotificationError
from phi_scan.hashing import compute_value_hash
from phi_scan.models import NotificationConfig, ScanFinding, ScanResult

__all__ = ["NotificationRequest", "send_email_notification", "send_webhook_notification"]

_logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment variable names for SMTP credentials
# ---------------------------------------------------------------------------

_SMTP_USER_ENV_VAR: str = "PHI_SCAN_SMTP_USER"
_SMTP_PASSWORD_ENV_VAR: str = "PHI_SCAN_SMTP_PASSWORD"

# ---------------------------------------------------------------------------
# Error message templates
# ---------------------------------------------------------------------------

_EMAIL_SEND_ERROR: str = "Email notification failed to {recipients}: {detail}"  # phi-scan:ignore
_WEBHOOK_SEND_ERROR: str = "Webhook notification failed to {url}: {detail}"
_WEBHOOK_HTTP_ERROR: str = "Webhook POST returned {status_code} after {attempts} attempt(s)"
_TLS_REQUIRED_ERROR: str = (
    "Plaintext SMTP is prohibited — all email delivery requires TLS. "
    "Set smtp_use_tls=True and use port 587 (STARTTLS) or 465 (SMTPS)."
)
_NO_RECIPIENTS_ERROR: str = "Email notification requires at least one recipient in smtp_recipients"
_NO_SMTP_HOST_ERROR: str = "Email notification requires smtp_host to be set"
_NO_SMTP_FROM_ERROR: str = "Email notification requires smtp_from to be set"
_NO_WEBHOOK_URL_ERROR: str = "Webhook notification requires webhook_url to be set"
_REQUIRED_WEBHOOK_SCHEME: str = "https"
# URL and hostname values in these messages are SHA-256 hashed before interpolation —
# webhook URLs may contain path segments with PHI-like content (e.g. /patient/123456789).
_WEBHOOK_SCHEME_ERROR: str = (
    "Webhook URL sha256:{url_hash} uses scheme {scheme!r} — only 'https' is permitted. "
    "Use an https:// endpoint to prevent credentials and findings metadata from "
    "being transmitted in plaintext."
)
_WEBHOOK_PRIVATE_IP_ERROR: str = (
    "Webhook URL sha256:{url_hash} resolves to a blocked IP range (sha256:{address_hash}). "
    "Requests to RFC1918, link-local, and cloud metadata ranges are blocked by default. "
    "Set is_private_webhook_url_allowed=True in NotificationConfig to allow self-hosted targets."
)
_WEBHOOK_MISSING_HOSTNAME_ERROR: str = (
    "Webhook URL sha256:{url_hash} contains no hostname — the URL is malformed or empty. "
    "Provide a valid https:// endpoint with a resolvable hostname."
)
_WEBHOOK_DNS_RESOLUTION_ERROR: str = (
    "Webhook hostname sha256:{hostname_hash} could not be resolved: {error}. "
    "Unresolvable hostnames are rejected to prevent DNS-based SSRF bypasses."
)
_WEBHOOK_DNS_BLOCKED_ADDRESS_ERROR: str = (
    "Webhook hostname sha256:{hostname_hash} resolves to a blocked IP range "
    "(sha256:{address_hash}). Requests to RFC1918, link-local, and cloud metadata "
    "ranges are blocked by default. "
    "Set is_private_webhook_url_allowed=True in NotificationConfig to allow self-hosted targets."
)
# Transport URL format used to pin the TCP connection to the IP resolved during
# SSRF validation, preventing DNS rebinding between validation and request.
_PINNED_HOST_HEADER: str = "Host"
_CONTENT_TYPE_HEADER: str = "Content-Type"
_WEBHOOK_BUILD_NO_HOSTNAME_ERROR: str = "cannot build pinned request: URL has no parseable hostname"
_IPV6_ADDRESS_COLON: str = ":"
_IPV6_NETLOC_BRACKET_TEMPLATE: str = "[{hostname}]"
_NETLOC_PORT_TEMPLATE: str = ":{port}"
_EMPTY_PORT_SEGMENT: str = ""

# IP networks blocked by SSRF protection when is_private_webhook_url_allowed=False.
# Covers RFC1918 private ranges, link-local, loopback, CGNAT, cloud metadata,
# and IPv6 equivalents. Addresses not in these ranges are permitted.
_BLOCKED_IP_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),  # phi-scan:ignore
    ipaddress.ip_network("172.16.0.0/12"),  # phi-scan:ignore
    ipaddress.ip_network("192.168.0.0/16"),  # phi-scan:ignore
    ipaddress.ip_network("127.0.0.0/8"),  # phi-scan:ignore
    ipaddress.ip_network("169.254.0.0/16"),  # phi-scan:ignore
    ipaddress.ip_network("100.64.0.0/10"),  # phi-scan:ignore
    ipaddress.ip_network("::1/128"),  # phi-scan:ignore
    ipaddress.ip_network("fc00::/7"),  # phi-scan:ignore
    ipaddress.ip_network("fe80::/10"),  # phi-scan:ignore
)

# ---------------------------------------------------------------------------
# Email template constants
# ---------------------------------------------------------------------------

_EMAIL_CONTENT_TYPE_HTML: str = "html"
_EMAIL_CONTENT_TYPE_PLAIN: str = "plain"
_EMAIL_CHARSET: str = "utf-8"
_ATTACHMENT_CONTENT_TYPE: str = "application/octet-stream"
_ATTACHMENT_SUBTYPE: str = "octet-stream"
# Inline CSS kept minimal — most email clients strip <style> blocks; inline is safer.
_HTML_EMAIL_TEMPLATE: str = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#333;">
  <h2 style="color:#c0392b;">\u26a0\ufe0f PHI Alert — {risk_level}</h2>
  <table style="border-collapse:collapse;width:100%;max-width:700px;">
    <tr style="background:#f2f2f2;">
      <th style="padding:8px;text-align:left;border:1px solid #ddd;">Field</th>
      <th style="padding:8px;text-align:left;border:1px solid #ddd;">Value</th>
    </tr>
    <tr>
      <td style="padding:8px;border:1px solid #ddd;"><strong>Risk Level</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{risk_level}</td>
    </tr>
    <tr style="background:#f9f9f9;">
      <td style="padding:8px;border:1px solid #ddd;"><strong>Findings Count</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{findings_count}</td>
    </tr>
    <tr>
      <td style="padding:8px;border:1px solid #ddd;"><strong>Repository</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{repository}</td>
    </tr>
    <tr style="background:#f9f9f9;">
      <td style="padding:8px;border:1px solid #ddd;"><strong>Branch</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{branch}</td>
    </tr>
    <tr>
      <td style="padding:8px;border:1px solid #ddd;"><strong>Scanner Version</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{scanner_version}</td>
    </tr>
    <tr style="background:#f9f9f9;">
      <td style="padding:8px;border:1px solid #ddd;"><strong>Files Scanned</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{files_scanned}</td>
    </tr>
    <tr>
      <td style="padding:8px;border:1px solid #ddd;"><strong>Scan Duration</strong></td>
      <td style="padding:8px;border:1px solid #ddd;">{scan_duration:.2f}s</td>
    </tr>
  </table>
  {findings_table}
  <hr style="margin-top:24px;">
  <p style="font-size:12px;color:#999;">
    Generated by phi-scan {scanner_version}. Raw PHI values are never included in
    notifications — only hashed metadata. Review findings in your terminal or report.
  </p>
</body>
</html>
"""

_HTML_FINDINGS_TABLE_HEADER: str = """\
  <h3 style="margin-top:24px;">Findings Summary</h3>
  <table style="border-collapse:collapse;width:100%;max-width:700px;">
    <tr style="background:#f2f2f2;">
      <th style="padding:8px;border:1px solid #ddd;">File</th>
      <th style="padding:8px;border:1px solid #ddd;">Line</th>
      <th style="padding:8px;border:1px solid #ddd;">Category</th>
      <th style="padding:8px;border:1px solid #ddd;">Severity</th>
    </tr>
"""
_HTML_FINDINGS_TABLE_ROW: str = """\
    <tr{style}>
      <td style="padding:8px;border:1px solid #ddd;">{file_path}</td>
      <td style="padding:8px;border:1px solid #ddd;">{line_number}</td>
      <td style="padding:8px;border:1px solid #ddd;">{category}</td>
      <td style="padding:8px;border:1px solid #ddd;">{severity}</td>
    </tr>
"""
_HTML_FINDINGS_TABLE_FOOTER: str = "  </table>\n"
_HTML_FINDINGS_ROW_ALT_STYLE: str = ' style="background:#f9f9f9;"'
_HTML_FINDINGS_ROW_STYLE: str = ""

# ---------------------------------------------------------------------------
# Webhook payload constants
# ---------------------------------------------------------------------------

_WEBHOOK_CONTENT_TYPE: str = "application/json"
_SLACK_COLOR_DANGER: str = "danger"
_SLACK_COLOR_GOOD: str = "good"
_TEAMS_THEME_COLOR_RED: str = "FF0000"
_TEAMS_THEME_COLOR_GREEN: str = "00AA00"
_MAX_FINDINGS_IN_NOTIFICATION: int = 20  # prevent oversized payloads
_WEBHOOK_EVENT_NAME: str = "phi_scan_complete"
_FINDING_KEY_FILE_PATH: str = "file_path"
_FINDING_KEY_LINE_NUMBER: str = "line_number"
_FINDING_KEY_ENTITY_TYPE: str = "entity_type"
_FINDING_KEY_HIPAA_CATEGORY: str = "hipaa_category"
_FINDING_KEY_SEVERITY: str = "severity"
_FINDING_KEY_CONFIDENCE: str = "confidence"
_FINDING_KEY_VALUE_HASH: str = "value_hash"

# ---------------------------------------------------------------------------
# Notification request model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NotificationRequest:
    """Scan context required by both email and webhook notification channels.

    Bundles the 4–5 scan-related inputs that are common to
    send_email_notification and send_webhook_notification, satisfying the
    ≤3 argument rule for those functions.
    """

    scan_result: ScanResult
    repository: str
    branch: str
    scanner_version: str
    report_path: Path | None = None


# ---------------------------------------------------------------------------
# Webhook scan summary model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _WebhookScanSummary:
    """Pre-computed scan metadata shared by all webhook payload builders.

    Constructed once by _derive_webhook_scan_summary and passed to each
    builder, eliminating duplicate derivation across Slack, Teams, and
    generic payload formats.
    """

    is_clean: bool
    risk_level_label: str
    risk_level_value: str
    findings_count: int
    files_scanned: int
    scan_duration: float
    action_taken: str
    repository: str
    branch: str
    scanner_version: str
    truncated_findings: tuple[MappingProxyType[str, Any], ...]


def _serialise_finding(finding: ScanFinding) -> MappingProxyType[str, Any]:
    """Serialise a single finding as a read-only metadata dict.

    Only hashed metadata is included — no raw PHI values or code_context.

    Args:
        finding: The scan finding to serialise.

    Returns:
        Immutable mapping of finding metadata safe for webhook payloads.
    """
    finding_dict: dict[str, Any] = {
        _FINDING_KEY_FILE_PATH: str(finding.file_path),
        _FINDING_KEY_LINE_NUMBER: finding.line_number,
        _FINDING_KEY_ENTITY_TYPE: finding.entity_type,
        _FINDING_KEY_HIPAA_CATEGORY: finding.hipaa_category.value,
        _FINDING_KEY_SEVERITY: finding.severity.value,
        _FINDING_KEY_CONFIDENCE: finding.confidence,
        _FINDING_KEY_VALUE_HASH: finding.value_hash,
    }
    return MappingProxyType(finding_dict)


def _truncate_findings_for_notification(
    scan_result: ScanResult,
) -> tuple[MappingProxyType[str, Any], ...]:
    """Serialise at most _MAX_FINDINGS_IN_NOTIFICATION findings as read-only dicts.

    Only hashed metadata is included — no raw PHI values or code_context.

    Args:
        scan_result: Completed scan result.

    Returns:
        Tuple of immutable finding mappings safe for inclusion in a webhook payload.
    """
    return tuple(
        _serialise_finding(finding)
        for finding in scan_result.findings[:_MAX_FINDINGS_IN_NOTIFICATION]
    )


def _derive_webhook_scan_summary(request: NotificationRequest) -> _WebhookScanSummary:
    """Derive all shared webhook metadata from a notification request.

    Args:
        request: Notification request bundling scan result and scan context.

    Returns:
        Immutable summary of scan metadata for use by payload builders.
    """
    scan_result = request.scan_result
    return _WebhookScanSummary(
        is_clean=scan_result.is_clean,
        risk_level_label=scan_result.risk_level.value.upper(),
        risk_level_value=scan_result.risk_level.value,
        findings_count=len(scan_result.findings),
        files_scanned=scan_result.files_scanned,
        scan_duration=scan_result.scan_duration,
        action_taken=ACTION_TAKEN_PASS if scan_result.is_clean else ACTION_TAKEN_FAIL,
        repository=request.repository,
        branch=request.branch,
        scanner_version=request.scanner_version,
        truncated_findings=_truncate_findings_for_notification(scan_result),
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_smtp_credentials() -> tuple[str, str]:
    """Return (username, password) from environment variables, or ('', '') if absent.

    Credentials are sourced exclusively from the process environment —
    never from config files — so they cannot be accidentally committed.

    Returns:
        Tuple of (SMTP username, SMTP password). Either may be empty string.
    """
    return (
        os.environ.get(_SMTP_USER_ENV_VAR, ""),
        os.environ.get(_SMTP_PASSWORD_ENV_VAR, ""),
    )


def _build_findings_table_html(scan_result: ScanResult) -> str:
    """Build an HTML table summarising scan findings for the email body.

    Only file_path, line_number, hipaa_category, and severity are included —
    no raw PHI values or code_context (HIPAA constraint).

    Args:
        scan_result: Completed scan result.

    Returns:
        HTML string containing the findings table, or empty string if no findings.
    """
    if not scan_result.findings:
        return ""
    rows = [_HTML_FINDINGS_TABLE_HEADER]
    for index, finding in enumerate(scan_result.findings[:_MAX_FINDINGS_IN_NOTIFICATION]):
        row_style = _HTML_FINDINGS_ROW_ALT_STYLE if index % 2 else _HTML_FINDINGS_ROW_STYLE
        rows.append(
            _HTML_FINDINGS_TABLE_ROW.format(
                style=row_style,
                file_path=html.escape(str(finding.file_path)),
                line_number=finding.line_number,
                category=html.escape(finding.hipaa_category.value),
                severity=html.escape(finding.severity.value),
            )
        )
    rows.append(_HTML_FINDINGS_TABLE_FOOTER)
    return "".join(rows)


def _build_email_subject(request: NotificationRequest) -> str:
    """Return the formatted email subject line.

    Args:
        request: Notification request bundling scan result and scan context.

    Returns:
        Subject string formatted per NOTIFICATION_SUBJECT_FORMAT.
    """
    return NOTIFICATION_SUBJECT_FORMAT.format(
        risk_level=request.scan_result.risk_level.value.upper(),
        findings_count=len(request.scan_result.findings),
        repository=request.repository,
        branch=request.branch,
    )


def _build_email_html_body(request: NotificationRequest) -> str:
    """Render the HTML email body.

    Args:
        request: Notification request bundling scan result and scan context.

    Returns:
        Complete HTML document string for the email body.
    """
    scan_result = request.scan_result
    findings_table = _build_findings_table_html(scan_result)
    return _HTML_EMAIL_TEMPLATE.format(
        risk_level=html.escape(scan_result.risk_level.value.upper()),
        findings_count=len(scan_result.findings),
        repository=html.escape(request.repository),
        branch=html.escape(request.branch),
        scanner_version=html.escape(request.scanner_version),
        files_scanned=scan_result.files_scanned,
        scan_duration=scan_result.scan_duration,
        findings_table=findings_table,
    )


def _attach_report_file(message: MIMEMultipart, report_path: Path) -> None:
    """Attach a report file to a MIME multipart message.

    Only attaches if the file exists and is readable. Silently skips on any
    I/O error so a missing report never blocks email delivery.

    Args:
        message: The MIME message to attach the file to.
        report_path: Path to the PDF or HTML report file.
    """
    try:
        report_bytes = report_path.read_bytes()
    except OSError as read_error:
        _logger.warning(
            "Could not attach report file %r to email: %s", str(report_path), read_error
        )
        return
    attachment = MIMEApplication(report_bytes, _subtype=_ATTACHMENT_SUBTYPE)
    # phi-scan:ignore-next-line
    attachment.add_header("Content-Disposition", "attachment", filename=report_path.name)
    message.attach(attachment)


def _build_mime_message(
    config: NotificationConfig,
    subject: str,
    html_body: str,
    report_path: Path | None,
) -> MIMEMultipart:
    """Construct the MIME message with HTML body and optional attachment.

    Args:
        config: Notification configuration supplying smtp_from and smtp_recipients.
        subject: The email subject line.
        html_body: The rendered HTML email body.
        report_path: Optional path to a report file to attach.

    Returns:
        Fully assembled MIMEMultipart message ready for SMTP delivery.
    """
    message = MIMEMultipart("mixed")
    message["Subject"] = subject
    message["From"] = config.smtp_from
    message["To"] = ", ".join(config.smtp_recipients)
    message.attach(MIMEText(html_body, _EMAIL_CONTENT_TYPE_HTML, _EMAIL_CHARSET))
    if report_path is not None and report_path.exists():
        _attach_report_file(message, report_path)
    return message


def _deliver_via_smtp(
    config: NotificationConfig,
    message: MIMEMultipart,
) -> None:
    """Connect to the SMTP server and deliver the message.

    Uses STARTTLS on the configured port. SMTPS (port 465) is not supported
    directly — use port 587 with STARTTLS. Credentials are read from environment
    variables via _get_smtp_credentials.

    Args:
        config: Notification configuration (smtp_host, smtp_port, smtp_use_tls).
        message: The assembled MIME message to send.

    Raises:
        NotificationError: If connection, TLS negotiation, or message delivery fails.
    """
    if not config.smtp_use_tls:
        raise NotificationError(_TLS_REQUIRED_ERROR)
    smtp_user, smtp_password = _get_smtp_credentials()
    recipients = list(config.smtp_recipients)
    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as smtp_connection:
            smtp_connection.ehlo()
            smtp_connection.starttls()
            smtp_connection.ehlo()
            if smtp_user:
                smtp_connection.login(smtp_user, smtp_password)
            smtp_connection.sendmail(config.smtp_from, recipients, message.as_string())
    except smtplib.SMTPException as smtp_error:
        raise NotificationError(
            _EMAIL_SEND_ERROR.format(recipients=recipients, detail=smtp_error)
        ) from smtp_error
    except OSError as conn_error:
        raise NotificationError(
            _EMAIL_SEND_ERROR.format(recipients=recipients, detail=conn_error)
        ) from conn_error


# ---------------------------------------------------------------------------
# Webhook payload builders
# ---------------------------------------------------------------------------


def _build_slack_payload(scan_summary: _WebhookScanSummary) -> dict[str, Any]:
    """Build a Slack Block Kit message payload.

    Args:
        scan_summary: Pre-computed scan metadata from _derive_webhook_scan_summary.

    Returns:
        Slack Block Kit payload dict ready for JSON serialisation.
    """
    color = _SLACK_COLOR_GOOD if scan_summary.is_clean else _SLACK_COLOR_DANGER
    status_text = (
        "*CLEAN* — no PHI detected"
        if scan_summary.is_clean
        else (
            f"*{scan_summary.risk_level_label}* — {scan_summary.findings_count} finding(s) detected"
        )
    )
    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f":shield: *phi-scan Alert* | "
                                f"{scan_summary.repository}/{scan_summary.branch}\n"
                                f"{status_text}\n"
                                f"Files scanned: {scan_summary.files_scanned} | "
                                f"Scanner: {scan_summary.scanner_version}"
                            ),
                        },
                    }
                ],
            }
        ]
    }


def _build_teams_payload(scan_summary: _WebhookScanSummary) -> dict[str, Any]:
    """Build a Microsoft Teams Adaptive Card payload.

    Args:
        scan_summary: Pre-computed scan metadata from _derive_webhook_scan_summary.

    Returns:
        Teams connector card payload dict ready for JSON serialisation.
    """
    theme_color = _TEAMS_THEME_COLOR_GREEN if scan_summary.is_clean else _TEAMS_THEME_COLOR_RED
    status_text = (
        "CLEAN — no PHI detected"
        if scan_summary.is_clean
        else f"{scan_summary.risk_level_label} — {scan_summary.findings_count} finding(s) detected"
    )
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"phi-scan {status_text}",
        "sections": [
            {
                "activityTitle": (
                    f"phi-scan Alert — {scan_summary.repository}/{scan_summary.branch}"
                ),
                "activitySubtitle": status_text,
                "facts": [
                    {"name": "Risk Level", "value": scan_summary.risk_level_value},
                    # phi-scan:ignore-next-line
                    {"name": "Findings", "value": str(scan_summary.findings_count)},
                    {"name": "Files Scanned", "value": str(scan_summary.files_scanned)},
                    {"name": "Scanner Version", "value": scan_summary.scanner_version},
                ],
            }
        ],
    }


def _build_generic_payload(scan_summary: _WebhookScanSummary) -> dict[str, Any]:
    """Build a generic JSON webhook payload.

    The payload includes only hashed metadata — no raw PHI values or
    code_context are ever serialised. finding.value_hash is the SHA-256
    digest of the detected value; it cannot be reversed to recover the PHI.

    Args:
        scan_summary: Pre-computed scan metadata from _derive_webhook_scan_summary.

    Returns:
        Generic JSON payload dict.
    """
    return {
        "event": _WEBHOOK_EVENT_NAME,
        "scanner_version": scan_summary.scanner_version,
        "repository": scan_summary.repository,
        "branch": scan_summary.branch,
        "risk_level": scan_summary.risk_level_value,
        "is_clean": scan_summary.is_clean,
        "findings_count": scan_summary.findings_count,
        "files_scanned": scan_summary.files_scanned,
        "scan_duration": scan_summary.scan_duration,
        "action_taken": scan_summary.action_taken,
        "findings": [dict(finding) for finding in scan_summary.truncated_findings],
    }


def _build_webhook_payload(
    webhook_type: WebhookType,
    request: NotificationRequest,
) -> dict[str, Any]:
    """Dispatch to the appropriate payload builder for the given webhook_type.

    Args:
        webhook_type: The target webhook format.
        request: Notification request bundling scan result and scan context.

    Returns:
        Payload dict appropriate for the webhook_type.
    """
    scan_summary = _derive_webhook_scan_summary(request)
    if webhook_type is WebhookType.SLACK:
        return _build_slack_payload(scan_summary)
    if webhook_type is WebhookType.TEAMS:
        return _build_teams_payload(scan_summary)
    return _build_generic_payload(scan_summary)


def _resolve_hostname_addresses(  # phi-scan:ignore
    dns_host: str,  # phi-scan:ignore
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:  # phi-scan:ignore
    """Resolve a hostname to all of its IP addresses.

    Args:
        dns_host: The DNS hostname to resolve.

    Returns:
        List of resolved IPv4Address or IPv6Address objects.

    Raises:
        NotificationError: If the hostname cannot be resolved.
    """
    try:
        address_infos = socket.getaddrinfo(dns_host, None)  # phi-scan:ignore
    except socket.gaierror as error:
        raise NotificationError(
            _WEBHOOK_DNS_RESOLUTION_ERROR.format(
                hostname_hash=compute_value_hash(dns_host),  # phi-scan:ignore
                error=error,
            )
        ) from error
    return [  # phi-scan:ignore
        ipaddress.ip_address(sockaddr[0])  # phi-scan:ignore
        for _, _, _, _, sockaddr in address_infos
    ]


def _reject_ssrf_resolved_addresses(  # phi-scan:ignore
    dns_host: str,  # phi-scan:ignore
    candidate_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address],  # phi-scan:ignore
) -> None:
    """Raise NotificationError if any resolved address falls in a blocked IP range.

    Args:
        dns_host: The DNS hostname that was resolved (used only for hashing in the error).
        candidate_ips: Resolved IP addresses to validate against blocked ranges.

    Raises:
        NotificationError: If any address falls in a blocked range.
    """
    for ip in candidate_ips:  # phi-scan:ignore
        if any(ip in network for network in _BLOCKED_IP_NETWORKS):  # phi-scan:ignore
            raise NotificationError(
                _WEBHOOK_DNS_BLOCKED_ADDRESS_ERROR.format(
                    hostname_hash=compute_value_hash(dns_host),  # phi-scan:ignore
                    address_hash=compute_value_hash(str(ip)),  # phi-scan:ignore
                )
            )


def _validate_webhook_url(
    url: str,
    is_private_webhook_url_allowed: bool,
) -> str | None:
    """Validate the webhook URL against SSRF safety checks and return a pinned IP.

    Enforces four guards (1–2 always, 3–4 when is_private_webhook_url_allowed is False):
    1. Scheme must be 'https' — plaintext http is rejected.
    2. Hostname must be present — a URL with no hostname (e.g. 'https://') is always rejected.
    3. Hostname, if a literal IP address, must not fall in a private, loopback,
       link-local, CGNAT, or cloud metadata range.
    4. Hostname, if a domain name, is resolved via DNS and every returned address
       is validated against the same blocked ranges (closes DNS-rebinding bypass).

    Returns the first resolved IP address as a string so the caller can pin the
    TCP connection to it, preventing DNS rebinding between validation and delivery.
    Returns None when the hostname is already a literal IP (no resolution needed).

    Args:
        url: The webhook endpoint URL to validate.
        is_private_webhook_url_allowed: When True, skip both the literal-IP check
            and the DNS resolution check (opt-out for self-hosted targets on private
            networks).

    Returns:
        Pinned IP string to connect to, or None when is_private_webhook_url_allowed
        is True or the hostname is already a literal IP address (public or private —
        literal IPs require no DNS resolution and therefore no pinning).

    Raises:
        NotificationError: If the URL fails any enabled check.
    """
    parsed = urlparse(url)
    if parsed.scheme != _REQUIRED_WEBHOOK_SCHEME:
        raise NotificationError(
            _WEBHOOK_SCHEME_ERROR.format(url_hash=compute_value_hash(url), scheme=parsed.scheme)
        )
    hostname = parsed.hostname  # phi-scan:ignore
    if not hostname:  # phi-scan:ignore
        raise NotificationError(
            # phi-scan:ignore-next-line
            _WEBHOOK_MISSING_HOSTNAME_ERROR.format(url_hash=compute_value_hash(url))
        )
    if is_private_webhook_url_allowed:
        return None
    try:
        address = ipaddress.ip_address(hostname)  # phi-scan:ignore
    except ValueError:
        resolved_addresses = _resolve_hostname_addresses(hostname)  # phi-scan:ignore
        _reject_ssrf_resolved_addresses(hostname, resolved_addresses)
        return str(resolved_addresses[0])  # phi-scan:ignore
    if any(address in network for network in _BLOCKED_IP_NETWORKS):  # phi-scan:ignore
        raise NotificationError(
            _WEBHOOK_PRIVATE_IP_ERROR.format(
                url_hash=compute_value_hash(url), address_hash=compute_value_hash(str(address))
            )
        )
    return None


@dataclass(frozen=True)
class _PinnedWebhookRequest:
    """Pre-computed URL and headers for a TOCTOU-safe webhook POST.

    Produced by ``_build_pinned_webhook_request`` and consumed by ``_post_with_retry``
    so that URL rewriting and header construction are isolated from the retry loop.
    """

    target_url: str
    headers: MappingProxyType[str, str]


@dataclass(frozen=True)
class _WebhookPostRequest:
    """Input bundle for _post_with_retry.

    Groups the four delivery parameters so the function signature stays within
    the three-argument limit.
    """

    url: str
    payload: dict[str, Any]
    retry_count: int
    pinned_ip: str | None


def _format_netloc_host_segment(hostname: str) -> str:
    """Return hostname formatted for insertion into a URL netloc string.

    IPv6 addresses must be bracketed in netloc (e.g. ``[2001:db8::1]``);
    IPv4 addresses and DNS names are used as-is.

    Args:
        hostname: Bare hostname or IP address string (no brackets).

    Returns:
        Hostname ready for insertion into a netloc string.
    """
    if _IPV6_ADDRESS_COLON in hostname:
        return _IPV6_NETLOC_BRACKET_TEMPLATE.format(hostname=hostname)
    return hostname


def _rewrite_url_hostname_to_ip(parsed_webhook_url: ParseResult, pinned_ip: str) -> str:
    """Return a rewritten URL with its hostname replaced by ``pinned_ip``.

    Reconstructs the netloc from parsed parts (host + port) rather than
    string-substituting the original netloc, which is fragile when the
    hostname appears as a substring of the port or other netloc components.
    The original hostname travels in the Host header (see
    ``_build_pinned_webhook_request``) so TLS SNI and server routing are preserved.
    Both IPv4 and IPv6 pinned addresses are handled: IPv6 addresses are
    bracketed in the netloc (e.g. ``[2001:db8::1]``).

    Args:
        parsed_webhook_url: Pre-parsed webhook URL from the caller (avoids a
            redundant ``urlparse`` call when the caller already holds this value).
        pinned_ip: IP address string returned by ``_validate_webhook_url``.

    Returns:
        URL with hostname replaced by ``pinned_ip``.
    """
    pinned_netloc_host = _format_netloc_host_segment(pinned_ip)
    port_segment = (
        _NETLOC_PORT_TEMPLATE.format(port=parsed_webhook_url.port)
        if parsed_webhook_url.port
        else _EMPTY_PORT_SEGMENT
    )
    return urlunparse(parsed_webhook_url._replace(netloc=f"{pinned_netloc_host}{port_segment}"))


def _build_pinned_webhook_request(url: str, pinned_ip: str | None) -> _PinnedWebhookRequest:
    """Build the target URL and headers for a webhook POST.

    When ``pinned_ip`` is provided, rewrites the URL to connect to the
    pre-resolved IP and adds a Host header with the original hostname (TOCTOU
    mitigation). When None, the URL and headers are used as-is.

    Args:
        url: Webhook endpoint URL.
        pinned_ip: IP returned by ``_validate_webhook_url``, or None.

    Returns:
        ``_PinnedWebhookRequest`` with target_url and headers ready for httpx.

    Raises:
        NotificationError: If pinned_ip is set but the URL has no parseable hostname.
    """
    if pinned_ip is None:
        return _PinnedWebhookRequest(
            target_url=url,
            headers=MappingProxyType({_CONTENT_TYPE_HEADER: _WEBHOOK_CONTENT_TYPE}),
        )
    parsed_webhook_url = urlparse(url)
    original_hostname = parsed_webhook_url.hostname
    if not original_hostname:
        raise NotificationError(_WEBHOOK_BUILD_NO_HOSTNAME_ERROR)
    return _PinnedWebhookRequest(
        target_url=_rewrite_url_hostname_to_ip(parsed_webhook_url, pinned_ip),
        headers=MappingProxyType(
            {
                _CONTENT_TYPE_HEADER: _WEBHOOK_CONTENT_TYPE,
                _PINNED_HOST_HEADER: original_hostname,
            }
        ),
    )


def _post_with_retry(post_request: _WebhookPostRequest) -> None:
    """POST a JSON payload to a URL with linear retry on failure.

    Uses ``httpx`` sync client. Retries on HTTP 4xx/5xx and on network errors.
    The final attempt raises ``NotificationError`` if still failing.

    Args:
        post_request: Delivery parameters bundled as a ``_WebhookPostRequest``.

    Raises:
        NotificationError: If all attempts fail.
    """
    pinned_request = _build_pinned_webhook_request(post_request.url, post_request.pinned_ip)
    last_error: Exception | None = None
    for attempt in range(1, post_request.retry_count + 1):
        try:
            response = httpx.post(
                pinned_request.target_url,
                json=post_request.payload,
                headers=pinned_request.headers,
                timeout=WEBHOOK_DEFAULT_TIMEOUT_SECONDS,
            )
            if response.is_success:
                return
            last_error = NotificationError(
                _WEBHOOK_HTTP_ERROR.format(status_code=response.status_code, attempts=attempt)
            )
            _logger.warning(
                "Webhook POST to %r returned %d (attempt %d/%d)",
                post_request.url,
                response.status_code,
                attempt,
                post_request.retry_count,
            )
        except httpx.RequestError as request_error:
            last_error = request_error
            _logger.warning(
                "Webhook POST to %r failed (attempt %d/%d): %s",
                post_request.url,
                attempt,
                post_request.retry_count,
                request_error,
            )
    raise NotificationError(
        _WEBHOOK_SEND_ERROR.format(url=post_request.url, detail=last_error)
    ) from last_error


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def send_email_notification(
    config: NotificationConfig,
    request: NotificationRequest,
) -> None:
    """Send an email notification for a completed scan.

    Builds an HTML email summarising the scan result and delivers it via
    SMTP/STARTTLS. When ``request.report_path`` is provided and the file exists,
    it is attached to the email.

    This function is best-effort: callers must catch ``NotificationError`` and
    log a warning rather than aborting the scan workflow.

    Args:
        config: Notification configuration (smtp_host, smtp_port, smtp_from,
            smtp_recipients, smtp_use_tls).
        request: Notification request bundling scan result and scan context.

    Raises:
        NotificationError: If email delivery fails for any reason.
        NotificationError: If smtp_host, smtp_from, or smtp_recipients is empty,
            or if smtp_use_tls is False.
    """
    if not config.smtp_host:
        raise NotificationError(_NO_SMTP_HOST_ERROR)
    if not config.smtp_from:
        raise NotificationError(_NO_SMTP_FROM_ERROR)
    if not config.smtp_recipients:
        raise NotificationError(_NO_RECIPIENTS_ERROR)
    subject = _build_email_subject(request)
    html_body = _build_email_html_body(request)
    message = _build_mime_message(config, subject, html_body, request.report_path)
    _deliver_via_smtp(config, message)
    _logger.info(
        "Email notification sent to %d recipient(s) for %s/%s",
        len(config.smtp_recipients),
        request.repository,
        request.branch,
    )


def send_webhook_notification(
    config: NotificationConfig,
    request: NotificationRequest,
) -> None:
    """POST a findings notification to the configured webhook URL.

    Builds a payload appropriate for the webhook_type (Slack Block Kit,
    Teams Adaptive Card, or generic JSON) and delivers it via ``httpx`` with
    linear retry. Raw PHI values are never included in the payload.

    This function is best-effort: callers must catch ``NotificationError`` and
    log a warning rather than aborting the scan workflow.

    Args:
        config: Notification configuration (webhook_url, webhook_type,
            webhook_retry_count).
        request: Notification request bundling scan result and scan context.

    Raises:
        NotificationError: If webhook_url is empty or delivery fails after all
            retry attempts.
    """
    if not config.webhook_url:
        raise NotificationError(_NO_WEBHOOK_URL_ERROR)
    pinned_ip = _validate_webhook_url(config.webhook_url, config.is_private_webhook_url_allowed)
    payload = _build_webhook_payload(config.webhook_type, request)
    _post_with_retry(
        _WebhookPostRequest(
            url=config.webhook_url,
            payload=payload,
            retry_count=config.webhook_retry_count,
            pinned_ip=pinned_ip,
        )
    )
    _logger.info(
        "Webhook notification delivered to %r (%s) for %s/%s",
        config.webhook_url,
        config.webhook_type.value,
        request.repository,
        request.branch,
    )
