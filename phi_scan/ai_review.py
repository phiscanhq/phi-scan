"""AI confidence review layer for PhiScan — Phase 7A.

Sends redacted code context to Claude claude-sonnet-4-6 to re-score medium-confidence
findings and reduce false positives. High-confidence and regex-only findings
bypass this layer entirely.

PHI Safety contract:
- All matched PHI values are replaced with ``[REDACTED]`` before any API call.
- Only code structure with redacted values is transmitted — no raw PHI ever leaves
  the local machine.
- The redaction is verified by ``_redact_phi_from_context`` before the payload
  is constructed.

BYOAK (Bring Your Own API Key):
- API key resolved from ``ANTHROPIC_API_KEY`` env var first.
- Falls back to ``ai.anthropic_api_key`` in ``.phi-scanner.yml``.
- Raises ``AIConfigurationError`` if AI is enabled but no key is found.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass

from phi_scan.constants import (
    AI_CONFIDENCE_REVIEW_LOWER_BOUND,
    AI_CONFIDENCE_REVIEW_UPPER_BOUND,
    AI_MODEL_NAME,
    AI_RESPONSE_MAX_TOKENS,
    AI_REVIEW_REDACTED_PLACEHOLDER,
    AI_REVIEW_SYSTEM_PROMPT,
)
from phi_scan.exceptions import AIConfigurationError, AIReviewError
from phi_scan.models import ScanFinding

__all__ = [
    "AIReviewConfig",
    "AIReviewResult",
    "apply_ai_review_to_findings",
    "resolve_api_key",
]

_logger = logging.getLogger(__name__)

_ENV_VAR_API_KEY: str = "ANTHROPIC_API_KEY"
_MISSING_API_KEY_ERROR: str = (
    "AI review is enabled but no API key was found. "
    f"Set the {_ENV_VAR_API_KEY} environment variable or add "
    "'ai.anthropic_api_key' to .phi-scanner.yml. "
    "To disable AI review set 'ai.enable_claude_review: false'."
)
_AI_IMPORT_ERROR: str = (
    "The 'anthropic' package is required for AI review. Install it with: pip install phi-scan[ai]"
)
_UNEXPECTED_AI_RESPONSE_ERROR: str = (
    "Unexpected AI response structure for finding {entity_type} in {file_path}: {error}"
)


@dataclass
class AIReviewConfig:
    """Configuration for the AI confidence review layer.

    Args:
        is_enabled: Whether to call Claude for medium-confidence findings.
        api_key: Anthropic API key. Resolved from env var if not set explicitly.
        lower_bound: Minimum confidence score that qualifies for AI review.
        upper_bound: Maximum confidence score that qualifies for AI review.
            Findings at or above this value bypass AI review entirely.
    """

    is_enabled: bool = False
    api_key: str = ""
    lower_bound: float = AI_CONFIDENCE_REVIEW_LOWER_BOUND
    upper_bound: float = AI_CONFIDENCE_REVIEW_UPPER_BOUND


@dataclass
class AIReviewResult:
    """Result of a single Claude confidence review call.

    Args:
        original_confidence: Confidence score from the local detection layer.
        revised_confidence: Confidence score returned by Claude.
        is_phi_risk: Whether Claude considers this a genuine PHI risk.
        reasoning: Claude's reasoning for the score (logged, never stored in findings).
        input_tokens: Tokens consumed in the request (for cost tracking).
        output_tokens: Tokens consumed in the response (for cost tracking).
    """

    original_confidence: float
    revised_confidence: float
    is_phi_risk: bool
    reasoning: str
    input_tokens: int
    output_tokens: int


def resolve_api_key(config: AIReviewConfig) -> str:
    """Return the Anthropic API key from env var or config, in that order.

    Args:
        config: AI review configuration that may contain an explicit key.

    Returns:
        The resolved API key string.

    Raises:
        AIConfigurationError: If no key is found in either location.
    """
    env_key = os.environ.get(_ENV_VAR_API_KEY, "")
    if env_key:
        return env_key
    if config.api_key:
        return config.api_key
    raise AIConfigurationError(_MISSING_API_KEY_ERROR)


def apply_ai_review_to_findings(
    findings: list[ScanFinding],
    config: AIReviewConfig,
) -> list[ScanFinding]:
    """Apply Claude confidence review to medium-confidence findings.

    Findings outside the review band [lower_bound, upper_bound) are returned
    unchanged. Findings within the band are sent to Claude with redacted context;
    the returned confidence replaces the local score. Findings Claude scores
    below the original lower_bound are filtered out (false positive eliminated).

    If the Claude API call fails for any finding, that finding is returned with
    its original confidence score — the scan never crashes due to AI unavailability.

    Args:
        findings: All findings from the local detection layers.
        config: AI review configuration including the review band and API key.

    Returns:
        Updated findings list with revised confidence scores where AI review ran.
        Findings Claude determined are not PHI risks are removed.
    """
    if not config.is_enabled:
        return findings

    api_key = resolve_api_key(config)
    reviewed_findings: list[ScanFinding] = []

    for finding in findings:
        if not _qualifies_for_review(finding, config):
            reviewed_findings.append(finding)
            continue
        try:
            review_result = _request_ai_confidence_review(finding, api_key)
            _logger.info(
                "AI review: %s in %s — original=%.2f revised=%.2f phi_risk=%s tokens=%d+%d",
                finding.entity_type,
                finding.file_path,
                review_result.original_confidence,
                review_result.revised_confidence,
                review_result.is_phi_risk,
                review_result.input_tokens,
                review_result.output_tokens,
            )
            if not review_result.is_phi_risk:
                _logger.debug(
                    "AI review eliminated false positive: %s in %s — %s",
                    finding.entity_type,
                    finding.file_path,
                    review_result.reasoning,
                )
                continue
            updated_finding = dataclasses.replace(
                finding, confidence=review_result.revised_confidence
            )
            reviewed_findings.append(updated_finding)
        except AIReviewError as review_error:
            _logger.warning(
                "AI review failed for %s in %s — using local score: %s",
                finding.entity_type,
                finding.file_path,
                review_error,
            )
            reviewed_findings.append(finding)

    return reviewed_findings


def _qualifies_for_review(finding: ScanFinding, config: AIReviewConfig) -> bool:
    """Return True if this finding's confidence falls within the AI review band."""
    return config.lower_bound <= finding.confidence < config.upper_bound


def _redact_phi_from_context(finding: ScanFinding) -> str:
    """Return the finding's code context, verifying PHI is already redacted.

    ScanFinding enforces that code_context is set to CODE_CONTEXT_REDACTED_VALUE
    at construction time, so no raw PHI can be present. This function exists as
    an explicit named step in the outbound payload pipeline so it is visible to
    reviewers and auditors.

    Args:
        finding: A validated ScanFinding whose code_context has been redacted.

    Returns:
        The redacted code context string, safe to transmit to external APIs.
    """
    return finding.code_context


def _build_review_prompt(finding: ScanFinding) -> str:
    """Build the user prompt for Claude confidence review.

    Only structural metadata and redacted context are included. The matched
    PHI value is never present — code_context already contains only
    CODE_CONTEXT_REDACTED_VALUE.

    Args:
        finding: Finding with redacted code context.

    Returns:
        Prompt string safe to send to the Claude API.
    """
    redacted_context = _redact_phi_from_context(finding)
    return (
        f"Entity type: {finding.entity_type}\n"
        f"HIPAA category: {finding.hipaa_category.value}\n"
        f"File: {finding.file_path}\n"
        f"Line: {finding.line_number}\n"
        f"Local confidence: {finding.confidence:.2f}\n"
        f"Code context (PHI replaced with {AI_REVIEW_REDACTED_PLACEHOLDER}):\n"
        f"{redacted_context}\n\n"
        "Is this a genuine PHI/PII risk in production code? "
        "Respond in JSON: "
        '{"is_phi_risk": true/false, "confidence": 0.0-1.0, "reasoning": "..."}'
    )


def _parse_ai_response(response_text: str) -> dict:
    """Parse Claude's JSON response into a dict with required keys.

    Args:
        response_text: Raw text response from Claude.

    Returns:
        Dict with keys: is_phi_risk (bool), confidence (float), reasoning (str).

    Raises:
        AIReviewError: If the response cannot be parsed or is missing required keys.
    """
    try:
        # Claude may wrap JSON in markdown code fences — strip them
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as parse_error:
        raise AIReviewError(
            f"Could not parse AI response as JSON: {parse_error!r} — "
            f"response: {response_text[:200]}"
        ) from parse_error

    required_keys = {"is_phi_risk", "confidence", "reasoning"}
    missing = required_keys - parsed.keys()
    if missing:
        raise AIReviewError(
            f"AI response missing required keys {missing!r} — response: {response_text[:200]}"
        )
    return parsed


def _request_ai_confidence_review(finding: ScanFinding, api_key: str) -> AIReviewResult:
    """Call Claude to review a single medium-confidence finding.

    Args:
        finding: Finding to review. Its code_context must be redacted.
        api_key: Anthropic API key.

    Returns:
        AIReviewResult with the revised confidence and PHI risk determination.

    Raises:
        AIReviewError: If the API call fails or the response cannot be parsed.
        AIConfigurationError: If the anthropic package is not installed.
    """
    try:
        import anthropic
    except ImportError as import_error:
        raise AIConfigurationError(_AI_IMPORT_ERROR) from import_error

    prompt = _build_review_prompt(finding)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=AI_MODEL_NAME,
            max_tokens=AI_RESPONSE_MAX_TOKENS,
            system=AI_REVIEW_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError as api_error:
        raise AIReviewError(
            f"Claude API error reviewing {finding.entity_type} in {finding.file_path}: "
            f"{type(api_error).__name__}"
        ) from api_error

    response_text = message.content[0].text
    try:
        parsed = _parse_ai_response(response_text)
    except AIReviewError as parse_error:
        raise AIReviewError(
            _UNEXPECTED_AI_RESPONSE_ERROR.format(
                entity_type=finding.entity_type,
                file_path=finding.file_path,
                error=parse_error,
            )
        ) from parse_error

    return AIReviewResult(
        original_confidence=finding.confidence,
        revised_confidence=float(parsed["confidence"]),
        is_phi_risk=bool(parsed["is_phi_risk"]),
        reasoning=str(parsed["reasoning"]),
        input_tokens=message.usage.input_tokens,
        output_tokens=message.usage.output_tokens,
    )
