"""Email and webhook notification delivery (Phase 5).  # phi-scan:ignore

Implements two delivery channels:

  Email (5A) — ``send_email_notification``
    Sends a Rich-formatted HTML email via SMTP/STARTTLS when PHI is detected.
    TLS is required; plaintext SMTP connections are rejected at delivery time.
    Subject format: ``[PHI ALERT] {risk_level} — {findings_count} findings in {repo}/{branch}``.
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
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
from phi_scan.models import NotificationConfig, ScanResult

__all__ = ["send_email_notification", "send_webhook_notification"]

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
      <td style="padding:8px;border:1px solid #ddd;">{repo}</td>
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


def _build_email_subject(scan_result: ScanResult, repo: str, branch: str) -> str:
    """Return the formatted email subject line.

    Args:
        scan_result: Completed scan result.
        repo: Repository name or path hash (never raw PHI).
        branch: Branch name or hash (never raw PHI).

    Returns:
        Subject string formatted per NOTIFICATION_SUBJECT_FORMAT.
    """
    return NOTIFICATION_SUBJECT_FORMAT.format(
        risk_level=scan_result.risk_level.value.upper(),
        findings_count=len(scan_result.findings),
        repo=repo,
        branch=branch,
    )


def _build_email_html_body(
    scan_result: ScanResult, repo: str, branch: str, scanner_version: str
) -> str:
    """Render the HTML email body.

    Args:
        scan_result: Completed scan result.
        repo: Repository identifier string.
        branch: Branch name string.
        scanner_version: phi-scan version string from phi_scan.__version__.

    Returns:
        Complete HTML document string for the email body.
    """
    findings_table = _build_findings_table_html(scan_result)
    return _HTML_EMAIL_TEMPLATE.format(
        risk_level=html.escape(scan_result.risk_level.value.upper()),
        findings_count=len(scan_result.findings),
        repo=html.escape(repo),
        branch=html.escape(branch),
        scanner_version=html.escape(scanner_version),
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


def _build_slack_payload(
    scan_result: ScanResult, repo: str, branch: str, scanner_version: str
) -> dict[str, Any]:
    """Build a Slack Block Kit message payload.

    Args:
        scan_result: Completed scan result.
        repo: Repository identifier.
        branch: Branch name.
        scanner_version: phi-scan version string.

    Returns:
        Slack Block Kit payload dict ready for JSON serialisation.
    """
    is_clean = scan_result.is_clean
    color = _SLACK_COLOR_GOOD if is_clean else _SLACK_COLOR_DANGER
    status_text = (
        "*CLEAN* — no PHI detected"
        if is_clean
        else f"*{scan_result.risk_level.value.upper()}* — "
        f"{len(scan_result.findings)} finding(s) detected"
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
                                f":shield: *phi-scan Alert* | {repo}/{branch}\n"
                                f"{status_text}\n"
                                f"Files scanned: {scan_result.files_scanned} | "
                                f"Scanner: {scanner_version}"
                            ),
                        },
                    }
                ],
            }
        ]
    }


def _build_teams_payload(
    scan_result: ScanResult, repo: str, branch: str, scanner_version: str
) -> dict[str, Any]:
    """Build a Microsoft Teams Adaptive Card payload.

    Args:
        scan_result: Completed scan result.
        repo: Repository identifier.
        branch: Branch name.
        scanner_version: phi-scan version string.

    Returns:
        Teams connector card payload dict ready for JSON serialisation.
    """
    is_clean = scan_result.is_clean
    theme_color = _TEAMS_THEME_COLOR_GREEN if is_clean else _TEAMS_THEME_COLOR_RED
    status_text = (
        "CLEAN — no PHI detected"
        if is_clean
        else f"{scan_result.risk_level.value.upper()} — "
        f"{len(scan_result.findings)} finding(s) detected"
    )
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"phi-scan {status_text}",
        "sections": [
            {
                "activityTitle": f"phi-scan Alert — {repo}/{branch}",
                "activitySubtitle": status_text,
                "facts": [
                    {"name": "Risk Level", "value": scan_result.risk_level.value},
                    # phi-scan:ignore-next-line
                    {"name": "Findings", "value": str(len(scan_result.findings))},
                    {"name": "Files Scanned", "value": str(scan_result.files_scanned)},
                    {"name": "Scanner Version", "value": scanner_version},
                ],
            }
        ],
    }


def _build_generic_payload(
    scan_result: ScanResult, repo: str, branch: str, scanner_version: str
) -> dict[str, Any]:
    """Build a generic JSON webhook payload.

    The payload includes only hashed metadata — no raw PHI values or
    code_context are ever serialised. finding.value_hash is the SHA-256
    digest of the detected value; it cannot be reversed to recover the PHI.

    Args:
        scan_result: Completed scan result.
        repo: Repository identifier.
        branch: Branch name.
        scanner_version: phi-scan version string.

    Returns:
        Generic JSON payload dict.
    """
    findings_payload = [
        {
            "file_path": str(f.file_path),
            "line_number": f.line_number,
            "entity_type": f.entity_type,
            "hipaa_category": f.hipaa_category.value,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "value_hash": f.value_hash,
        }
        for f in scan_result.findings[:_MAX_FINDINGS_IN_NOTIFICATION]
    ]
    return {
        "event": "phi_scan_complete",
        "scanner_version": scanner_version,
        "repository": repo,
        "branch": branch,
        "risk_level": scan_result.risk_level.value,
        "is_clean": scan_result.is_clean,
        "findings_count": len(scan_result.findings),
        "files_scanned": scan_result.files_scanned,
        "scan_duration": scan_result.scan_duration,
        "action_taken": ACTION_TAKEN_PASS if scan_result.is_clean else ACTION_TAKEN_FAIL,
        "findings": findings_payload,
    }


def _build_webhook_payload(
    webhook_type: WebhookType,
    scan_result: ScanResult,
    repo: str,
    branch: str,
    scanner_version: str,
) -> dict[str, Any]:
    """Dispatch to the appropriate payload builder for the given webhook_type.

    Args:
        webhook_type: The target webhook format.
        scan_result: Completed scan result.
        repo: Repository identifier.
        branch: Branch name.
        scanner_version: phi-scan version string.

    Returns:
        Payload dict appropriate for the webhook_type.
    """
    if webhook_type is WebhookType.SLACK:
        return _build_slack_payload(scan_result, repo, branch, scanner_version)
    if webhook_type is WebhookType.TEAMS:
        return _build_teams_payload(scan_result, repo, branch, scanner_version)
    return _build_generic_payload(scan_result, repo, branch, scanner_version)


def _resolve_hostname_addresses(  # phi-scan:ignore
    hostname: str,  # phi-scan:ignore
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:  # phi-scan:ignore
    """Resolve a hostname to all of its IP addresses.

    Args:
        hostname: The hostname to resolve.  # phi-scan:ignore

    Returns:
        List of resolved IPv4Address or IPv6Address objects.

    Raises:
        NotificationError: If the hostname cannot be resolved.
    """
    try:
        address_infos = socket.getaddrinfo(hostname, None)  # phi-scan:ignore
    except socket.gaierror as error:
        raise NotificationError(
            _WEBHOOK_DNS_RESOLUTION_ERROR.format(
                hostname_hash=compute_value_hash(hostname),  # phi-scan:ignore
                error=error,  # phi-scan:ignore
            )
        ) from error
    resolved = []
    for _, _, _, _, sockaddr in address_infos:  # phi-scan:ignore
        if not sockaddr:
            continue
        try:
            resolved.append(ipaddress.ip_address(sockaddr[0]))  # phi-scan:ignore
        except (IndexError, ValueError):
            continue
    return resolved


def _reject_ssrf_resolved_addresses(  # phi-scan:ignore
    hostname: str,  # phi-scan:ignore
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],  # phi-scan:ignore
) -> None:
    """Raise NotificationError if any resolved address falls in a blocked IP range.

    Args:
        # phi-scan:ignore-next-line
        hostname: The hostname that was resolved (used only for hashing in the error).
        # phi-scan:ignore-next-line
        addresses: Resolved IP addresses to validate.

    Raises:
        NotificationError: If any address falls in a blocked range.
    """
    for address in addresses:  # phi-scan:ignore
        if any(address in network for network in _BLOCKED_IP_NETWORKS):  # phi-scan:ignore
            raise NotificationError(
                _WEBHOOK_DNS_BLOCKED_ADDRESS_ERROR.format(
                    hostname_hash=compute_value_hash(hostname),  # phi-scan:ignore
                    address_hash=compute_value_hash(str(address)),  # phi-scan:ignore
                )
            )


def _validate_webhook_url(url: str, is_private_webhook_url_allowed: bool) -> None:
    """Raise NotificationError if the webhook URL fails SSRF safety checks.

    Enforces four guards (1–2 always, 3–4 when is_private_webhook_url_allowed is False):
    1. Scheme must be 'https' — plaintext http is rejected.
    2. Hostname must be present — a URL with no hostname (e.g. 'https://') is always rejected.
    3. Hostname, if a literal IP address, must not fall in a private, loopback,
       link-local, CGNAT, or cloud metadata range.
    4. Hostname, if a domain name, is resolved via DNS and every returned address
       is validated against the same blocked ranges (closes DNS-rebinding bypass).

    Args:
        url: The webhook endpoint URL to validate.
        is_private_webhook_url_allowed: When True, skip both the literal-IP check
            and the DNS resolution check (opt-out for self-hosted targets on private
            networks).

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
        return
    try:
        address = ipaddress.ip_address(hostname)  # phi-scan:ignore
    except ValueError:
        resolved_addresses = _resolve_hostname_addresses(hostname)  # phi-scan:ignore
        _reject_ssrf_resolved_addresses(hostname, resolved_addresses)
        return
    if any(address in network for network in _BLOCKED_IP_NETWORKS):  # phi-scan:ignore
        raise NotificationError(
            _WEBHOOK_PRIVATE_IP_ERROR.format(
                url_hash=compute_value_hash(url), address_hash=compute_value_hash(str(address))
            )
        )


def _post_with_retry(
    url: str,
    payload: dict[str, Any],
    retry_count: int,
) -> None:
    """POST a JSON payload to a URL with linear retry on failure.

    Uses ``httpx`` sync client. Retries on HTTP 4xx/5xx and on network errors.
    The final attempt raises ``NotificationError`` if still failing.

    Args:
        url: The webhook endpoint URL.
        payload: JSON-serialisable payload dict.
        retry_count: Total number of attempts (1 = no retry).

    Raises:
        NotificationError: If all attempts fail.
    """
    last_error: Exception | None = None
    for attempt in range(1, retry_count + 1):
        try:
            response = httpx.post(
                url,
                json=payload,
                headers={"Content-Type": _WEBHOOK_CONTENT_TYPE},
                timeout=WEBHOOK_DEFAULT_TIMEOUT_SECONDS,
            )
            if response.is_success:
                return
            last_error = NotificationError(
                _WEBHOOK_HTTP_ERROR.format(status_code=response.status_code, attempts=attempt)
            )
            _logger.warning(
                "Webhook POST to %r returned %d (attempt %d/%d)",
                url,
                response.status_code,
                attempt,
                retry_count,
            )
        except httpx.RequestError as request_error:
            last_error = request_error
            _logger.warning(
                "Webhook POST to %r failed (attempt %d/%d): %s",
                url,
                attempt,
                retry_count,
                request_error,
            )
    raise NotificationError(_WEBHOOK_SEND_ERROR.format(url=url, detail=last_error)) from last_error


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def send_email_notification(
    config: NotificationConfig,
    scan_result: ScanResult,
    repo: str,
    branch: str,
    scanner_version: str,
    report_path: Path | None = None,
) -> None:
    """Send an email notification for a completed scan.

    Builds an HTML email summarising the scan result and delivers it via
    SMTP/STARTTLS. When ``report_path`` is provided and the file exists, it is
    attached to the email.

    This function is best-effort: callers must catch ``NotificationError`` and
    log a warning rather than aborting the scan workflow.

    Args:
        config: Notification configuration (smtp_host, smtp_port, smtp_from,
            smtp_recipients, smtp_use_tls).
        scan_result: Completed scan result to summarise in the email.
        repo: Repository name or identifier (used in subject and body).
        branch: Branch name (used in subject and body).
        scanner_version: phi-scan version string (e.g. "0.5.0").
        report_path: Optional path to a PDF or HTML report to attach.

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
    subject = _build_email_subject(scan_result, repo, branch)
    html_body = _build_email_html_body(scan_result, repo, branch, scanner_version)
    message = _build_mime_message(config, subject, html_body, report_path)
    _deliver_via_smtp(config, message)
    _logger.info(
        "Email notification sent to %d recipient(s) for %s/%s",
        len(config.smtp_recipients),
        repo,
        branch,
    )


def send_webhook_notification(
    config: NotificationConfig,
    scan_result: ScanResult,
    repo: str,
    branch: str,
    scanner_version: str,
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
        scan_result: Completed scan result to include in the payload.
        repo: Repository name or identifier.
        branch: Branch name.
        scanner_version: phi-scan version string.

    Raises:
        NotificationError: If webhook_url is empty or delivery fails after all
            retry attempts.
    """
    if not config.webhook_url:
        raise NotificationError(_NO_WEBHOOK_URL_ERROR)
    _validate_webhook_url(config.webhook_url, config.is_private_webhook_url_allowed)
    payload = _build_webhook_payload(
        config.webhook_type, scan_result, repo, branch, scanner_version
    )
    _post_with_retry(config.webhook_url, payload, config.webhook_retry_count)
    _logger.info(
        "Webhook notification delivered to %r (%s) for %s/%s",
        config.webhook_url,
        config.webhook_type.value,
        repo,
        branch,
    )
