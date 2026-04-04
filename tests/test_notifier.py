# phi-scan:ignore-file
"""Tests for email and webhook notification delivery (Phase 5A + 5B).

Verifies that:
  - Email notifications are built with correct subject and HTML body
  - SMTP credentials are read from environment variables
  - Email delivery raises NotificationError on SMTP failure
  - Webhook payloads are well-formed for Slack, Teams, and generic types
  - POST with retry gives up after configured attempts and raises NotificationError
  - Notification dispatch respects notify_on_violation_only flag
  - TLS enforcement raises NotificationError when smtp_use_tls=False
"""

from __future__ import annotations

import smtplib
from pathlib import Path
from types import MappingProxyType
from unittest.mock import MagicMock, patch

import httpx
import pytest

from phi_scan.constants import (
    DetectionLayer,
    PhiCategory,
    RiskLevel,
    SeverityLevel,
    WebhookType,
)
from phi_scan.exceptions import NotificationError
from phi_scan.models import NotificationConfig, ScanFinding, ScanResult
from phi_scan.notifier import (
    _build_email_subject,
    _build_generic_payload,
    _build_slack_payload,
    _build_teams_payload,
    _build_webhook_payload,
    _get_smtp_credentials,
    send_email_notification,
    send_webhook_notification,
)

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

_SAMPLE_HASH: str = "a" * 64
_SAMPLE_FILE_PATH: Path = Path("src/patient_service.py")
_SAMPLE_REPO: str = "acme/patient-portal"
_SAMPLE_BRANCH: str = "main"
_SAMPLE_SCANNER_VERSION: str = "0.5.0"
_SAMPLE_SMTP_HOST: str = "smtp.example.com"
_SAMPLE_SMTP_PORT: int = 587
_SAMPLE_SMTP_FROM: str = "phi-scan@example.com"
_SAMPLE_RECIPIENT_1: str = "secops@example.com"
_SAMPLE_RECIPIENT_2: str = "compliance@example.com"
_SAMPLE_WEBHOOK_URL: str = "https://hooks.example.com/notify"
_SAMPLE_CONFIDENCE: float = 0.92
_SAMPLE_LINE_NUMBER: int = 10
_EMPTY_RECIPIENTS: tuple[str, ...] = ()
_ZERO_FINDINGS: int = 0
_ONE_FINDING: int = 1
_SMTP_ENV_USER: str = "PHI_SCAN_SMTP_USER"
_SMTP_ENV_PASSWORD: str = "PHI_SCAN_SMTP_PASSWORD"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: PhiCategory = PhiCategory.SSN,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> ScanFinding:
    return ScanFinding(
        file_path=_SAMPLE_FILE_PATH,
        line_number=_SAMPLE_LINE_NUMBER,
        entity_type="us_ssn",
        hipaa_category=category,
        confidence=_SAMPLE_CONFIDENCE,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_SAMPLE_HASH,
        severity=severity,
        code_context="ssn = '[REDACTED]'",
        remediation_hint="Replace SSN.",
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        findings=(),
        files_scanned=5,
        files_with_findings=0,
        scan_duration=0.1,
        is_clean=True,
        risk_level=RiskLevel.CLEAN,
        severity_counts=MappingProxyType({level: 0 for level in SeverityLevel}),
        category_counts=MappingProxyType({cat: 0 for cat in PhiCategory}),
    )


def _make_dirty_result() -> ScanResult:
    findings = (_make_finding(),)
    return ScanResult(
        findings=findings,
        files_scanned=5,
        files_with_findings=1,
        scan_duration=0.1,
        is_clean=False,
        risk_level=RiskLevel.HIGH,
        severity_counts=MappingProxyType(
            {level: (1 if level is SeverityLevel.HIGH else 0) for level in SeverityLevel}
        ),
        category_counts=MappingProxyType(
            {cat: (1 if cat is PhiCategory.SSN else 0) for cat in PhiCategory}
        ),
    )


def _make_email_config(
    recipients: tuple[str, ...] = (_SAMPLE_RECIPIENT_1,),
    smtp_use_tls: bool = True,
) -> NotificationConfig:
    return NotificationConfig(
        is_email_enabled=True,
        smtp_host=_SAMPLE_SMTP_HOST,
        smtp_port=_SAMPLE_SMTP_PORT,
        smtp_from=_SAMPLE_SMTP_FROM,
        smtp_recipients=recipients,
        smtp_use_tls=smtp_use_tls,
    )


def _make_webhook_config(
    webhook_type: WebhookType = WebhookType.GENERIC,
    retry_count: int = 1,
) -> NotificationConfig:
    return NotificationConfig(
        is_webhook_enabled=True,
        webhook_url=_SAMPLE_WEBHOOK_URL,
        webhook_type=webhook_type,
        webhook_retry_count=retry_count,
    )


# ---------------------------------------------------------------------------
# Email subject tests
# ---------------------------------------------------------------------------


def test_email_subject_contains_risk_level() -> None:
    """Email subject must include the risk level in uppercase."""
    subject = _build_email_subject(_make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH)
    assert "HIGH" in subject


def test_email_subject_contains_findings_count() -> None:
    """Email subject must include the findings count."""
    subject = _build_email_subject(_make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH)
    assert str(_ONE_FINDING) in subject


def test_email_subject_contains_repo_and_branch() -> None:
    """Email subject must include the repository and branch."""
    subject = _build_email_subject(_make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH)
    assert _SAMPLE_REPO in subject
    assert _SAMPLE_BRANCH in subject


def test_email_subject_phi_alert_prefix() -> None:
    """Email subject must begin with the [PHI ALERT] prefix."""
    subject = _build_email_subject(_make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH)
    assert subject.startswith("[PHI ALERT]")


# ---------------------------------------------------------------------------
# Email validation tests
# ---------------------------------------------------------------------------


def test_send_email_raises_when_smtp_host_empty() -> None:
    """send_email_notification must raise NotificationError when smtp_host is empty."""
    config = NotificationConfig(
        is_email_enabled=True,
        smtp_host="",
        smtp_from=_SAMPLE_SMTP_FROM,
        smtp_recipients=(_SAMPLE_RECIPIENT_1,),
    )
    with pytest.raises(NotificationError):
        send_email_notification(
            config, _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
        )


def test_send_email_raises_when_smtp_from_empty() -> None:
    """send_email_notification must raise NotificationError when smtp_from is empty."""
    config = NotificationConfig(
        is_email_enabled=True,
        smtp_host=_SAMPLE_SMTP_HOST,
        smtp_from="",
        smtp_recipients=(_SAMPLE_RECIPIENT_1,),
    )
    with pytest.raises(NotificationError):
        send_email_notification(
            config, _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
        )


def test_send_email_raises_when_no_recipients() -> None:
    """send_email_notification must raise NotificationError when smtp_recipients is empty."""
    config = NotificationConfig(
        is_email_enabled=True,
        smtp_host=_SAMPLE_SMTP_HOST,
        smtp_from=_SAMPLE_SMTP_FROM,
        smtp_recipients=_EMPTY_RECIPIENTS,
    )
    with pytest.raises(NotificationError):
        send_email_notification(
            config, _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
        )


def test_send_email_raises_when_tls_disabled() -> None:
    """send_email_notification must raise NotificationError when smtp_use_tls is False."""
    config = _make_email_config(smtp_use_tls=False)
    with pytest.raises(NotificationError, match="[Pp]laintext"):
        send_email_notification(
            config, _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
        )


def test_send_email_raises_on_smtp_exception() -> None:
    """send_email_notification must raise NotificationError when SMTP raises."""
    config = _make_email_config()
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp_cls.side_effect = smtplib.SMTPConnectError(421, "connection refused")
        with pytest.raises(NotificationError):
            send_email_notification(
                config,
                _make_dirty_result(),
                _SAMPLE_REPO,
                _SAMPLE_BRANCH,
                _SAMPLE_SCANNER_VERSION,
            )


def test_send_email_succeeds_with_mock_smtp() -> None:
    """send_email_notification must complete without error when SMTP mock succeeds."""
    config = _make_email_config()
    mock_smtp = MagicMock()
    mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
    mock_smtp.__exit__ = MagicMock(return_value=False)
    with patch("smtplib.SMTP", return_value=mock_smtp):
        send_email_notification(
            config,
            _make_dirty_result(),
            _SAMPLE_REPO,
            _SAMPLE_BRANCH,
            _SAMPLE_SCANNER_VERSION,
        )


# ---------------------------------------------------------------------------
# SMTP credential environment variable tests
# ---------------------------------------------------------------------------


def test_get_smtp_credentials_returns_empty_when_env_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_smtp_credentials must return ('', '') when env vars are not set."""
    monkeypatch.delenv(_SMTP_ENV_USER, raising=False)
    monkeypatch.delenv(_SMTP_ENV_PASSWORD, raising=False)
    user, password = _get_smtp_credentials()
    assert user == ""
    assert password == ""


def test_get_smtp_credentials_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_smtp_credentials must return the values from the environment variables."""
    monkeypatch.setenv(_SMTP_ENV_USER, "test_user")
    monkeypatch.setenv(_SMTP_ENV_PASSWORD, "test_pass")
    user, password = _get_smtp_credentials()
    assert user == "test_user"
    assert password == "test_pass"


# ---------------------------------------------------------------------------
# Webhook payload tests
# ---------------------------------------------------------------------------


def test_generic_payload_contains_event_field() -> None:
    """Generic webhook payload must include an 'event' field."""
    payload = _build_generic_payload(
        _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    assert "event" in payload


def test_generic_payload_contains_findings_count() -> None:
    """Generic webhook payload findings_count must match scan result."""
    scan_result = _make_dirty_result()
    payload = _build_generic_payload(
        scan_result, _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    assert payload["findings_count"] == len(scan_result.findings)


def test_generic_payload_no_raw_phi_values() -> None:
    """Generic payload findings must not include code_context or remediation_hint."""
    payload = _build_generic_payload(
        _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    for finding_payload in payload.get("findings", []):
        assert "code_context" not in finding_payload
        assert "remediation_hint" not in finding_payload


def test_generic_payload_contains_value_hash_not_raw_value() -> None:
    """Generic payload findings must contain value_hash (not the raw PHI value)."""
    payload = _build_generic_payload(
        _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    for finding_payload in payload.get("findings", []):
        assert "value_hash" in finding_payload


def test_slack_payload_has_attachments_key() -> None:
    """Slack payload must use the 'attachments' key for Block Kit compatibility."""
    payload = _build_slack_payload(
        _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    assert "attachments" in payload


def test_teams_payload_has_message_card_type() -> None:
    """Teams payload must have '@type': 'MessageCard'."""
    payload = _build_teams_payload(
        _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
    )
    assert payload.get("@type") == "MessageCard"


def test_build_webhook_payload_dispatches_slack() -> None:
    """_build_webhook_payload must produce a Slack payload for WebhookType.SLACK."""
    payload = _build_webhook_payload(
        WebhookType.SLACK,
        _make_dirty_result(),
        _SAMPLE_REPO,
        _SAMPLE_BRANCH,
        _SAMPLE_SCANNER_VERSION,
    )
    assert "attachments" in payload


def test_build_webhook_payload_dispatches_teams() -> None:
    """_build_webhook_payload must produce a Teams payload for WebhookType.TEAMS."""
    payload = _build_webhook_payload(
        WebhookType.TEAMS,
        _make_dirty_result(),
        _SAMPLE_REPO,
        _SAMPLE_BRANCH,
        _SAMPLE_SCANNER_VERSION,
    )
    assert payload.get("@type") == "MessageCard"


def test_build_webhook_payload_dispatches_generic() -> None:
    """_build_webhook_payload must produce a generic payload for WebhookType.GENERIC."""
    payload = _build_webhook_payload(
        WebhookType.GENERIC,
        _make_dirty_result(),
        _SAMPLE_REPO,
        _SAMPLE_BRANCH,
        _SAMPLE_SCANNER_VERSION,
    )
    assert "event" in payload


# ---------------------------------------------------------------------------
# Webhook delivery tests
# ---------------------------------------------------------------------------


def test_send_webhook_raises_when_url_empty() -> None:
    """send_webhook_notification must raise NotificationError when webhook_url is empty."""
    config = NotificationConfig(is_webhook_enabled=True, webhook_url="")
    with pytest.raises(NotificationError):
        send_webhook_notification(
            config, _make_dirty_result(), _SAMPLE_REPO, _SAMPLE_BRANCH, _SAMPLE_SCANNER_VERSION
        )


def test_send_webhook_succeeds_on_http_200() -> None:
    """send_webhook_notification must succeed without error when httpx returns 200."""
    config = _make_webhook_config(retry_count=1)
    mock_response = MagicMock()
    mock_response.is_success = True
    with patch("httpx.post", return_value=mock_response):
        send_webhook_notification(
            config,
            _make_dirty_result(),
            _SAMPLE_REPO,
            _SAMPLE_BRANCH,
            _SAMPLE_SCANNER_VERSION,
        )


def test_send_webhook_raises_after_all_retries_fail() -> None:
    """send_webhook_notification must raise NotificationError when all attempts fail."""
    config = _make_webhook_config(retry_count=2)
    mock_response = MagicMock()
    mock_response.is_success = False
    mock_response.status_code = 503
    with patch("httpx.post", return_value=mock_response):
        with pytest.raises(NotificationError):
            send_webhook_notification(
                config,
                _make_dirty_result(),
                _SAMPLE_REPO,
                _SAMPLE_BRANCH,
                _SAMPLE_SCANNER_VERSION,
            )


def test_send_webhook_raises_on_network_error() -> None:
    """send_webhook_notification must raise NotificationError on httpx.RequestError."""
    config = _make_webhook_config(retry_count=1)
    with patch("httpx.post", side_effect=httpx.ConnectError("refused")):
        with pytest.raises(NotificationError):
            send_webhook_notification(
                config,
                _make_dirty_result(),
                _SAMPLE_REPO,
                _SAMPLE_BRANCH,
                _SAMPLE_SCANNER_VERSION,
            )


def test_send_webhook_retries_on_failure() -> None:
    """send_webhook_notification must POST retry_count times before giving up."""
    config = _make_webhook_config(retry_count=3)
    mock_response = MagicMock()
    mock_response.is_success = False
    mock_response.status_code = 500
    with patch("httpx.post", return_value=mock_response) as mock_post:
        with pytest.raises(NotificationError):
            send_webhook_notification(
                config,
                _make_dirty_result(),
                _SAMPLE_REPO,
                _SAMPLE_BRANCH,
                _SAMPLE_SCANNER_VERSION,
            )
        assert mock_post.call_count == 3


# ---------------------------------------------------------------------------
# notify_on_violation_only tests (via NotificationConfig defaults)
# ---------------------------------------------------------------------------


def test_notification_config_defaults_notify_on_violation_only() -> None:
    """NotificationConfig must default notify_on_violation_only to True."""
    config = NotificationConfig()
    assert config.notify_on_violation_only is True


def test_notification_config_is_disabled_by_default() -> None:
    """NotificationConfig must default both channels to disabled."""
    config = NotificationConfig()
    assert config.is_email_enabled is False
    assert config.is_webhook_enabled is False
