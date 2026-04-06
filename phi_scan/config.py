"""YAML configuration loading and validation for PhiScan (.phi-scanner.yml)."""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import yaml

from phi_scan.ai_review import AIReviewConfig
from phi_scan.constants import (
    AI_DEFAULT_MODEL,
    AUDIT_RETENTION_DAYS,
    CONFIDENCE_SCORE_MAXIMUM,
    CONFIDENCE_SCORE_MINIMUM,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_DATABASE_PATH,
    IMPLEMENTED_OUTPUT_FORMATS,
    MAX_FILE_SIZE_MB,
    SMTP_DEFAULT_PORT,
    WEBHOOK_DEFAULT_RETRY_COUNT,
    OutputFormat,
    SeverityLevel,
    WebhookType,
)
from phi_scan.exceptions import ConfigurationError
from phi_scan.models import NotificationConfig, ScanConfig

__all__ = ["create_default_config", "load_config"]

# ---------------------------------------------------------------------------
# YAML structure keys — no string literals in logic
# ---------------------------------------------------------------------------

_YAML_SECTION_SCAN: str = "scan"
_YAML_SECTION_OUTPUT: str = "output"
_YAML_SECTION_AUDIT: str = "audit"
_YAML_KEY_VERSION: str = "version"
_YAML_KEY_CONFIDENCE_THRESHOLD: str = "confidence_threshold"
_YAML_KEY_SEVERITY_THRESHOLD: str = "severity_threshold"
_YAML_KEY_MAX_FILE_SIZE_MB: str = "max_file_size_mb"
_YAML_KEY_FOLLOW_SYMLINKS: str = "follow_symlinks"
_YAML_KEY_INCLUDE_EXTENSIONS: str = "include_extensions"
_YAML_KEY_EXCLUDE_PATHS: str = "exclude_paths"
_YAML_KEY_OUTPUT_FORMAT: str = "format"
_YAML_KEY_DATABASE_PATH: str = "database_path"
_YAML_SECTION_NOTIFICATIONS: str = "notifications"
_YAML_KEY_EMAIL_ENABLED: str = "email_enabled"
_YAML_KEY_SMTP_HOST: str = "smtp_host"
_YAML_KEY_SMTP_PORT: str = "smtp_port"
_YAML_KEY_SMTP_FROM: str = "smtp_from"
_YAML_KEY_SMTP_RECIPIENTS: str = "smtp_recipients"
_YAML_KEY_WEBHOOK_ENABLED: str = "webhook_enabled"
_YAML_KEY_WEBHOOK_URL: str = "webhook_url"
_YAML_KEY_WEBHOOK_TYPE: str = "webhook_type"
_YAML_KEY_WEBHOOK_RETRY_COUNT: str = "webhook_retry_count"
_YAML_KEY_NOTIFY_ON_VIOLATION_ONLY: str = "notify_on_violation_only"
_YAML_KEY_PRIVATE_WEBHOOK_ALLOWED: str = "is_private_webhook_url_allowed"
_DEFAULT_PRIVATE_WEBHOOK_ALLOWED: bool = False
_YAML_SECTION_AI: str = "ai"
_YAML_KEY_ENABLE_AI_REVIEW: str = "enable_ai_review"
_YAML_KEY_AI_MODEL: str = "model"
# Deprecated key — accepted with a warning and mapped to enable_ai_review.
_YAML_KEY_ENABLE_CLAUDE_REVIEW_DEPRECATED: str = "enable_claude_review"
# Banned key — api keys must come from env vars; in-config keys are rejected.
_YAML_KEY_ANTHROPIC_API_KEY_BANNED: str = "anthropic_api_key"

# ---------------------------------------------------------------------------
# Config defaults and constraints
# ---------------------------------------------------------------------------

_SUPPORTED_CONFIG_VERSION: int = 1
_CONFIG_FILE_ENCODING: str = "utf-8"

# ---------------------------------------------------------------------------
# Error message templates
# ---------------------------------------------------------------------------

_CONFIG_READ_ERROR: str = "Cannot read config file {path!r}: {error}"
_CONFIG_PARSE_ERROR: str = "Failed to parse config file {path!r}: {error}"
_CONFIG_NOT_MAPPING_ERROR: str = "Config file {path!r} must be a YAML mapping, got {type}"
_CONFIG_WRITE_ERROR: str = "Cannot write config file {path!r}: {error}"
_UNSUPPORTED_VERSION_ERROR: str = "Unsupported config version {version!r} — expected {expected}"
_FOLLOW_SYMLINKS_ERROR: str = (
    "follow_symlinks must be false — symlink traversal is a security violation "
    "that can cause infinite loops in CI/CD environments"
)
_INVALID_OUTPUT_FORMAT_ERROR: str = "output.format {value!r} is not valid. Accepted values: {valid}"
_UNIMPLEMENTED_OUTPUT_FORMAT_ERROR: str = (
    "output.format {value!r} is not yet implemented. "
    "Currently supported: {supported}. "
    "Remove this setting or choose a supported format."
)
_INVALID_SEVERITY_ERROR: str = (
    "scan.severity_threshold {value!r} is not valid. Accepted values: {valid}"
)
_INVALID_DATABASE_PATH_ERROR: str = "audit.database_path must be a string, got {value!r}"
_INVALID_CONFIDENCE_THRESHOLD_ERROR: str = "scan.confidence_threshold {value!r} must be a number"
_CONFIDENCE_THRESHOLD_RANGE_ERROR: str = (
    "scan.confidence_threshold {value!r} is outside the valid range [{minimum}, {maximum}]"
)
_INVALID_MAX_FILE_SIZE_MB_ERROR: str = "scan.max_file_size_mb {value!r} must be an integer"
_INVALID_SMTP_PORT_ERROR: str = "notifications.smtp_port {value!r} must be an integer"
_INVALID_WEBHOOK_RETRY_COUNT_ERROR: str = (
    "notifications.webhook_retry_count {value!r} must be an integer"
)
_INVALID_WEBHOOK_TYPE_ERROR: str = (
    "notifications.webhook_type {value!r} is not valid. Accepted values: {valid}"
)
_INVALID_SMTP_RECIPIENTS_ERROR: str = (
    "notifications.smtp_recipients must be a list of strings, got {value!r}"
)
_DEPRECATED_ENABLE_CLAUDE_REVIEW_WARNING: str = (
    "ai.enable_claude_review is deprecated — use ai.enable_ai_review instead. "
    "Support for enable_claude_review will be removed in a future release."
)
_BANNED_ANTHROPIC_API_KEY_IN_CONFIG_ERROR: str = (
    "ai.anthropic_api_key must not be set in .phi-scanner.yml — "
    "API keys must be supplied via environment variables to avoid committing secrets. "
    "Set ANTHROPIC_API_KEY in your environment instead."
)

# ---------------------------------------------------------------------------
# Default config template — written by create_default_config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_CONTENT: str = """\
# PhiScan configuration — {filename}
# Run `phi-scan explain config` for full documentation.

version: 1

scan:
  # Minimum confidence score to report a finding (0.0–1.0).
  confidence_threshold: {confidence_threshold}

  # Minimum severity: low, medium, or high.
  severity_threshold: low

  # Skip files larger than this limit (megabytes).
  max_file_size_mb: {max_file_size_mb}

  # SECURITY: must remain false. Setting true raises ConfigurationError.
  follow_symlinks: false

  # Allowlist of extensions to scan. null = scan all non-binary text files.
  include_extensions: null

  # Gitignore-style exclusion patterns evaluated at every directory depth.
  exclude_paths:
    - .git/
    - .venv/
    - node_modules/
    - dist/
    - build/
    - "*.egg-info/"
    - __pycache__/
    - .mypy_cache/
    - .ruff_cache/
    - .pytest_cache/
    - htmlcov/
    - "*.pyc"

output:
  # table, json, sarif, csv, pdf, html, junit, codequality, gitlab-sast
  format: table
  # quiet is a CLI-only flag (--quiet); it is not read from this file.

audit:
  # ~ is expanded via Path.expanduser() at runtime, not by the YAML parser.
  database_path: "{default_db}"

  # HIPAA 45 CFR §164.530(j): minimum 6-year retention = {retention_days} days.
  retention_days: {retention_days}

notifications:
  # Email notifications (requires SMTP server access).
  # Set PHI_SCAN_SMTP_USER and PHI_SCAN_SMTP_PASSWORD env vars for authentication.
  email_enabled: false
  smtp_host: ""
  smtp_port: {smtp_port}
  smtp_from: ""
  smtp_recipients: []

  # Webhook notifications (Slack, Teams, or generic HTTP POST).
  webhook_enabled: false
  webhook_url: ""
  webhook_type: "generic"  # "slack", "teams", or "generic"
  webhook_retry_count: {webhook_retry_count}

  # When true (default), only notify when scan finds violations.
  notify_on_violation_only: true

  # When false (default), webhook URLs pointing to RFC1918/link-local/metadata IPs
  # are rejected to prevent SSRF. Set true only for self-hosted private targets.
  # Note: DNS-based SSRF (domains resolving to blocked ranges) is not covered.
  is_private_webhook_url_allowed: false

ai:
  # Set true to send medium-confidence findings to an AI provider for re-scoring.
  # This reduces false positives by having the AI evaluate code structure context.
  # PHI values are always replaced with [REDACTED] before any API call.
  #
  # Supported providers (install the matching extra):
  #   Anthropic (default): pip install phi-scan[ai-anthropic]  → set ANTHROPIC_API_KEY
  #   OpenAI:              pip install phi-scan[ai-openai]     → set OPENAI_API_KEY
  #   Google:              pip install phi-scan[ai-google]     → set GOOGLE_API_KEY
  #
  # The provider is inferred automatically from the model name.
  enable_ai_review: false
  # model: claude-sonnet-4-6   # default — change to gpt-4o or gemini-1.5-flash to switch
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> ScanConfig:
    """Load and validate a .phi-scanner.yml configuration file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        A ScanConfig populated from the file, with defaults for omitted fields.

    Raises:
        ConfigurationError: If the file cannot be read, cannot be parsed as
            YAML, contains an unsupported version, or any field value is invalid.
    """
    parsed_yaml = _read_config_file(config_path)
    _reject_unsupported_version(parsed_yaml)
    scan_section: dict[str, Any] = parsed_yaml.get(_YAML_SECTION_SCAN, {})
    output_section: dict[str, Any] = parsed_yaml.get(_YAML_SECTION_OUTPUT, {})
    audit_section: dict[str, Any] = parsed_yaml.get(_YAML_SECTION_AUDIT, {})
    notifications_section: dict[str, Any] = parsed_yaml.get(_YAML_SECTION_NOTIFICATIONS, {})
    ai_section: dict[str, Any] = parsed_yaml.get(_YAML_SECTION_AI, {})
    _reject_follow_symlinks_enabled(scan_section)
    output_format = _parse_output_format(output_section)
    database_path = _parse_database_path(audit_section)
    notification_config = _parse_notification_config(notifications_section)
    ai_review_config = _parse_ai_review_config(ai_section)
    return _build_scan_config(
        scan_section,
        output_format,
        database_path,
        notification_config,
        ai_review_config,
    )


def create_default_config(output_path: Path) -> None:
    """Write a default .phi-scanner.yml configuration file to output_path.

    Args:
        output_path: Destination path for the generated config file.

    Raises:
        ConfigurationError: If the file cannot be written.
    """
    content = _DEFAULT_CONFIG_CONTENT.format(
        filename=DEFAULT_CONFIG_FILENAME,
        confidence_threshold=DEFAULT_CONFIDENCE_THRESHOLD,
        max_file_size_mb=MAX_FILE_SIZE_MB,
        default_db=DEFAULT_DATABASE_PATH,
        retention_days=AUDIT_RETENTION_DAYS,
        smtp_port=SMTP_DEFAULT_PORT,
        webhook_retry_count=WEBHOOK_DEFAULT_RETRY_COUNT,
    )
    try:
        output_path.write_text(content, encoding=_CONFIG_FILE_ENCODING)
    except OSError as error:
        raise ConfigurationError(
            _CONFIG_WRITE_ERROR.format(path=output_path, error=error)
        ) from error


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _read_config_file(config_path: Path) -> dict[str, Any]:
    """Read and parse a YAML config file into a raw dict.

    Args:
        config_path: Path to the YAML file.

    Returns:
        The top-level parsed mapping.

    Raises:
        ConfigurationError: If the file cannot be read or is not valid YAML.
    """
    try:
        content = config_path.read_text(encoding=_CONFIG_FILE_ENCODING)
    except OSError as error:
        raise ConfigurationError(
            _CONFIG_READ_ERROR.format(path=config_path, error=error)
        ) from error
    try:
        loaded_yaml = yaml.safe_load(content)
    except yaml.YAMLError as error:
        raise ConfigurationError(
            _CONFIG_PARSE_ERROR.format(path=config_path, error=error)
        ) from error
    if not isinstance(loaded_yaml, dict):
        raise ConfigurationError(
            _CONFIG_NOT_MAPPING_ERROR.format(path=config_path, type=type(loaded_yaml).__name__)
        )
    return loaded_yaml


def _reject_unsupported_version(raw_config: dict[str, Any]) -> None:
    """Raise ConfigurationError if the config version is not supported.

    Args:
        raw_config: The top-level parsed config dict.

    Raises:
        ConfigurationError: If version is missing or not the supported value.
    """
    version = raw_config.get(_YAML_KEY_VERSION)
    if version != _SUPPORTED_CONFIG_VERSION:
        raise ConfigurationError(
            _UNSUPPORTED_VERSION_ERROR.format(version=version, expected=_SUPPORTED_CONFIG_VERSION)
        )


def _reject_follow_symlinks_enabled(scan_section: dict[str, Any]) -> None:
    """Raise ConfigurationError if follow_symlinks is set to true.

    Args:
        scan_section: The scan: section of the parsed config.

    Raises:
        ConfigurationError: If follow_symlinks is True.
    """
    if scan_section.get(_YAML_KEY_FOLLOW_SYMLINKS) is True:
        raise ConfigurationError(_FOLLOW_SYMLINKS_ERROR)


def _parse_output_format(output_section: dict[str, Any]) -> OutputFormat:
    """Parse and validate the output format, defaulting to TABLE.

    Maps "gitlab-sast" to OutputFormat.GITLAB_SAST via value-based enum
    lookup — never via string transformation such as replace() or upper().

    Args:
        output_section: The output: section of the parsed config.

    Returns:
        The resolved OutputFormat member.

    Raises:
        ConfigurationError: If the format string is not a valid OutputFormat value.
    """
    format_value = output_section.get(_YAML_KEY_OUTPUT_FORMAT, OutputFormat.TABLE.value)
    try:
        output_format_member = OutputFormat(format_value)
    except ValueError as error:
        valid = ", ".join(member.value for member in OutputFormat)
        raise ConfigurationError(
            _INVALID_OUTPUT_FORMAT_ERROR.format(value=format_value, valid=valid)
        ) from error
    if output_format_member not in IMPLEMENTED_OUTPUT_FORMATS:
        supported = ", ".join(sorted(fmt.value for fmt in IMPLEMENTED_OUTPUT_FORMATS))
        raise ConfigurationError(
            _UNIMPLEMENTED_OUTPUT_FORMAT_ERROR.format(value=format_value, supported=supported)
        )
    return output_format_member


def _parse_database_path(audit_section: dict[str, Any]) -> Path:
    """Parse and validate the audit database path, expanding tilde to the home directory.

    Args:
        audit_section: The audit: section of the parsed config.

    Returns:
        The fully expanded Path to the audit database.

    Raises:
        ConfigurationError: If database_path is present but not a string.
    """
    raw_path = audit_section.get(_YAML_KEY_DATABASE_PATH, DEFAULT_DATABASE_PATH)
    if not isinstance(raw_path, str):
        raise ConfigurationError(_INVALID_DATABASE_PATH_ERROR.format(value=raw_path))
    return Path(raw_path).expanduser()


def _parse_confidence_threshold(scan_section: dict[str, Any]) -> float:
    """Parse and validate confidence_threshold from the scan section.

    Args:
        scan_section: The scan: section of the parsed config.

    Returns:
        The confidence threshold as a float.

    Raises:
        ConfigurationError: If the value cannot be coerced to float or is outside [0.0, 1.0].
    """
    raw_confidence_threshold = scan_section.get(
        _YAML_KEY_CONFIDENCE_THRESHOLD, DEFAULT_CONFIDENCE_THRESHOLD
    )
    try:
        confidence_threshold = float(raw_confidence_threshold)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(
            _INVALID_CONFIDENCE_THRESHOLD_ERROR.format(value=raw_confidence_threshold)
        ) from error
    if not CONFIDENCE_SCORE_MINIMUM <= confidence_threshold <= CONFIDENCE_SCORE_MAXIMUM:
        raise ConfigurationError(
            _CONFIDENCE_THRESHOLD_RANGE_ERROR.format(
                value=confidence_threshold,
                minimum=CONFIDENCE_SCORE_MINIMUM,
                maximum=CONFIDENCE_SCORE_MAXIMUM,
            )
        )
    return confidence_threshold


def _parse_severity_level(scan_section: dict[str, Any]) -> SeverityLevel:
    """Parse and validate severity_threshold from the scan section.

    Args:
        scan_section: The scan: section of the parsed config.

    Returns:
        The resolved SeverityLevel member.

    Raises:
        ConfigurationError: If the value is not a valid SeverityLevel.
    """
    raw_severity_threshold = scan_section.get(_YAML_KEY_SEVERITY_THRESHOLD, SeverityLevel.LOW.value)
    try:
        return SeverityLevel(raw_severity_threshold)
    except ValueError as error:
        valid = ", ".join(member.value for member in SeverityLevel)
        raise ConfigurationError(
            _INVALID_SEVERITY_ERROR.format(value=raw_severity_threshold, valid=valid)
        ) from error


def _parse_max_file_size_mb(scan_section: dict[str, Any]) -> int:
    """Parse and validate max_file_size_mb from the scan section.

    Args:
        scan_section: The scan: section of the parsed config.

    Returns:
        The maximum file size as an integer number of megabytes.

    Raises:
        ConfigurationError: If the value cannot be coerced to int.
    """
    raw_max_file_size_mb = scan_section.get(_YAML_KEY_MAX_FILE_SIZE_MB, MAX_FILE_SIZE_MB)
    try:
        return int(raw_max_file_size_mb)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(
            _INVALID_MAX_FILE_SIZE_MB_ERROR.format(value=raw_max_file_size_mb)
        ) from error


def _parse_notification_config(notifications_section: dict[str, Any]) -> NotificationConfig:
    """Parse and validate the notifications section into a NotificationConfig.

    All fields are optional — an empty section yields a default disabled config.

    Args:
        notifications_section: The notifications: section of the parsed config.

    Returns:
        A populated NotificationConfig instance.

    Raises:
        ConfigurationError: If any field value is invalid.
    """
    raw_smtp_port = notifications_section.get(_YAML_KEY_SMTP_PORT, SMTP_DEFAULT_PORT)
    try:
        smtp_port = int(raw_smtp_port)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(_INVALID_SMTP_PORT_ERROR.format(value=raw_smtp_port)) from error

    raw_retry_count = notifications_section.get(
        _YAML_KEY_WEBHOOK_RETRY_COUNT, WEBHOOK_DEFAULT_RETRY_COUNT
    )
    try:
        webhook_retry_count = int(raw_retry_count)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(
            _INVALID_WEBHOOK_RETRY_COUNT_ERROR.format(value=raw_retry_count)
        ) from error

    raw_webhook_type = notifications_section.get(_YAML_KEY_WEBHOOK_TYPE, WebhookType.GENERIC.value)
    try:
        webhook_type = WebhookType(raw_webhook_type)
    except ValueError as error:
        valid = ", ".join(member.value for member in WebhookType)
        raise ConfigurationError(
            _INVALID_WEBHOOK_TYPE_ERROR.format(value=raw_webhook_type, valid=valid)
        ) from error

    raw_recipients = notifications_section.get(_YAML_KEY_SMTP_RECIPIENTS, [])
    if not isinstance(raw_recipients, list) or not all(isinstance(r, str) for r in raw_recipients):
        raise ConfigurationError(_INVALID_SMTP_RECIPIENTS_ERROR.format(value=raw_recipients))

    return NotificationConfig(
        is_email_enabled=bool(notifications_section.get(_YAML_KEY_EMAIL_ENABLED, False)),
        smtp_host=str(notifications_section.get(_YAML_KEY_SMTP_HOST, "")),
        smtp_port=smtp_port,
        smtp_from=str(notifications_section.get(_YAML_KEY_SMTP_FROM, "")),
        smtp_recipients=tuple(raw_recipients),
        is_webhook_enabled=bool(notifications_section.get(_YAML_KEY_WEBHOOK_ENABLED, False)),
        webhook_url=str(notifications_section.get(_YAML_KEY_WEBHOOK_URL, "")),
        webhook_type=webhook_type,
        webhook_retry_count=webhook_retry_count,
        notify_on_violation_only=bool(
            notifications_section.get(_YAML_KEY_NOTIFY_ON_VIOLATION_ONLY, True)
        ),
        is_private_webhook_url_allowed=bool(
            notifications_section.get(
                _YAML_KEY_PRIVATE_WEBHOOK_ALLOWED, _DEFAULT_PRIVATE_WEBHOOK_ALLOWED
            )
        ),
    )


def _parse_ai_review_config(ai_section: dict[str, Any]) -> AIReviewConfig:
    """Parse the ai: section into an AIReviewConfig.

    An empty or absent ai: section yields a disabled AIReviewConfig.
    The API key is never read from the config file — it must come from the
    environment variable matching the chosen provider (e.g. ANTHROPIC_API_KEY).

    Backward compatibility:
    - ``enable_claude_review: true`` is accepted with a DeprecationWarning and
      treated identically to ``enable_ai_review: true``.
    - ``anthropic_api_key: <value>`` raises ``ConfigurationError`` — API keys
      must not be stored in config files.

    Args:
        ai_section: The ai: section of the parsed config (may be empty).

    Returns:
        An AIReviewConfig with is_enabled and model populated.

    Raises:
        ConfigurationError: If ``anthropic_api_key`` is present in the config.
    """
    if _YAML_KEY_ANTHROPIC_API_KEY_BANNED in ai_section:
        raise ConfigurationError(_BANNED_ANTHROPIC_API_KEY_IN_CONFIG_ERROR)

    is_enabled = bool(ai_section.get(_YAML_KEY_ENABLE_AI_REVIEW, False))

    if not is_enabled and _YAML_KEY_ENABLE_CLAUDE_REVIEW_DEPRECATED in ai_section:
        warnings.warn(_DEPRECATED_ENABLE_CLAUDE_REVIEW_WARNING, DeprecationWarning, stacklevel=2)
        is_enabled = bool(ai_section.get(_YAML_KEY_ENABLE_CLAUDE_REVIEW_DEPRECATED, False))

    model = str(ai_section.get(_YAML_KEY_AI_MODEL, "")) or AI_DEFAULT_MODEL
    return AIReviewConfig(is_enabled=is_enabled, model=model)


def _build_scan_config(
    scan_section: dict[str, Any],
    output_format: OutputFormat,
    database_path: Path,
    notification_config: NotificationConfig | None = None,
    ai_review_config: AIReviewConfig | None = None,
) -> ScanConfig:
    """Build a ScanConfig from all parsed config sections.

    Args:
        scan_section: The scan: section dict. Missing keys fall back to ScanConfig defaults.
        output_format: The validated output format parsed from the output: section.
        database_path: The validated and tilde-expanded database path from the audit: section.
        notification_config: Parsed notification config, or None for defaults.
        ai_review_config: Parsed AI review config, or None for disabled defaults.

    Returns:
        A validated ScanConfig instance.

    Raises:
        ConfigurationError: If any field value is invalid.
    """
    return ScanConfig(
        confidence_threshold=_parse_confidence_threshold(scan_section),
        severity_threshold=_parse_severity_level(scan_section),
        max_file_size_mb=_parse_max_file_size_mb(scan_section),
        # Hardcoded False — YAML true is rejected above by _reject_follow_symlinks_enabled.
        # Explicit here so a future change to ScanConfig's default cannot silently break
        # the security guarantee without failing tests.
        should_follow_symlinks=False,
        include_extensions=scan_section.get(_YAML_KEY_INCLUDE_EXTENSIONS),
        exclude_paths=list(scan_section.get(_YAML_KEY_EXCLUDE_PATHS, [])),
        output_format=output_format,
        database_path=database_path,
        notification_config=notification_config
        if notification_config is not None
        else NotificationConfig(),
        ai_review_config=ai_review_config if ai_review_config is not None else AIReviewConfig(),
    )
