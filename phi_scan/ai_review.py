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
from dataclasses import dataclass, field
from typing import Any, TypedDict

from phi_scan.constants import (
    AI_CONFIDENCE_REVIEW_LOWER_BOUND,
    AI_CONFIDENCE_REVIEW_UPPER_BOUND,
    AI_COST_PER_MILLION_INPUT_TOKENS,
    AI_COST_PER_MILLION_OUTPUT_TOKENS,
    AI_MESSAGE_CONTENT_KEY,
    AI_MESSAGE_ROLE_KEY,
    AI_MESSAGE_ROLE_USER,
    AI_MODEL_NAME,
    AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX,
    AI_RESPONSE_MAX_TOKENS,
    AI_RESPONSE_REQUIRED_KEYS,
    AI_RESPONSE_TRUNCATION_LENGTH,
    AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES,
    AI_REVIEW_REDACTED_PLACEHOLDER,
    AI_REVIEW_SYSTEM_PROMPT,
    AI_TOKENS_PER_MILLION,
    ANTHROPIC_API_KEY_ENV_VAR,
)
from phi_scan.exceptions import AIConfigurationError, AIReviewError
from phi_scan.models import ScanFinding

__all__ = [
    "AIReviewConfig",
    "AIReviewResult",
    "AIUsageSummary",
    "apply_ai_review_to_findings",
    "resolve_api_key",
]

_logger = logging.getLogger(__name__)

_MARKDOWN_CODE_FENCE: str = "```"
_MISSING_API_KEY_ERROR: str = (
    "AI review is enabled but no API key was found. "
    f"Set the {ANTHROPIC_API_KEY_ENV_VAR} environment variable or add "
    "'ai.anthropic_api_key' to .phi-scanner.yml. "
    "To disable AI review set 'ai.enable_claude_review: false'."
)
_AI_IMPORT_ERROR: str = (
    "The 'anthropic' package is required for AI review. Install it with: pip install phi-scan[ai]"
)
_UNEXPECTED_AI_RESPONSE_ERROR_TEMPLATE: str = (
    "Unexpected AI response structure for finding {entity_type} in {file_path}: {error}"
)
_UNEXPECTED_CONTENT_BLOCK_ERROR: str = (
    "Claude returned a non-text content block ({block_type!r}) — expected TextBlock"
)
_PHI_SAFETY_VIOLATION_ERROR: str = (
    "PHI safety violation: code_context for {entity_type} does not contain "
    f"the required redaction marker '{AI_REVIEW_REDACTED_PLACEHOLDER}' — "
    "this finding must not be sent to any external API"
)
_EMPTY_CODE_CONTEXT_NOT_PERMITTED_ERROR: str = (
    "PHI safety violation: code_context for {entity_type!r} is empty and "
    "{entity_type!r} is not in AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES — "
    "add the entity type to the allowlist only if it is proven to carry no source line"
)


class _AIResponsePayload(TypedDict):
    """Typed structure of the JSON Claude returns, containing only the fields we act on.

    reasoning is intentionally excluded: Claude's explanation may paraphrase PHI
    context. It is present in the decoded_response dict inside _parse_ai_response
    (json.loads includes all keys), but it is never accessed or extracted from that
    dict — only is_phi_risk and confidence are read. Excluding it from this TypedDict
    ensures no caller can accidentally reference, store, or log it.
    """

    is_phi_risk: bool
    confidence: float


@dataclass
class AIUsageSummary:
    """Aggregated token usage and cost across all AI review calls in one scan.

    Args:
        findings_reviewed: Number of findings sent to Claude for re-scoring.
        false_positives_removed: Findings Claude determined were not PHI risks.
        input_tokens: Total prompt tokens consumed across all API calls.
        output_tokens: Total completion tokens consumed across all API calls.
        estimated_cost_usd: Estimated API cost in USD based on published token rates.
    """

    findings_reviewed: int
    false_positives_removed: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float


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
    api_key: str = field(default="", repr=False)
    lower_bound: float = AI_CONFIDENCE_REVIEW_LOWER_BOUND
    upper_bound: float = AI_CONFIDENCE_REVIEW_UPPER_BOUND


@dataclass
class AIReviewResult:
    """Result of a single Claude confidence review call.

    reasoning is intentionally absent — Claude's explanation may paraphrase PHI
    context. It is parsed inside _request_ai_confidence_review and immediately
    discarded without logging or storage. Logging was considered but ruled out
    because log aggregation systems (CI, Datadog, CloudWatch) may retain the
    text, creating a HIPAA risk if the reasoning echoes patient context.

    Args:
        original_confidence: Confidence score from the local detection layer.
        revised_confidence: Confidence score returned by Claude.
        is_phi_risk: Whether Claude considers this a genuine PHI risk.
        input_tokens: Tokens consumed in the request (for cost tracking).
        output_tokens: Tokens consumed in the response (for cost tracking).
    """

    original_confidence: float
    revised_confidence: float
    is_phi_risk: bool
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
    env_key = os.environ.get(ANTHROPIC_API_KEY_ENV_VAR, "")
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
    the returned confidence replaces the local score. Findings Claude scores as
    not PHI risks are removed (false positives eliminated).

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
    reviewed_findings, usage_summary = _review_qualifying_findings(findings, api_key, config)
    _log_ai_usage_summary(usage_summary)
    return reviewed_findings


def _review_qualifying_findings(
    findings: list[ScanFinding],
    api_key: str,
    config: AIReviewConfig,
) -> tuple[list[ScanFinding], AIUsageSummary]:
    """Dispatch AI review for each qualifying finding and accumulate usage stats.

    Args:
        findings: All findings from the local detection layers.
        api_key: Resolved Anthropic API key.
        config: AI review configuration for band filtering.

    Returns:
        Tuple of (reviewed_findings, usage_summary) where reviewed_findings has
        false positives removed and confidence scores updated, and usage_summary
        aggregates token counts and cost for the scan.
    """
    reviewed_findings: list[ScanFinding] = []
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    findings_reviewed: int = 0
    false_positives_removed: int = 0

    for finding in findings:
        if not _qualifies_for_review(finding, config):
            reviewed_findings.append(finding)
            continue
        updated_finding, review_result = _apply_review_to_single_finding(finding, api_key)
        if review_result is not None:
            findings_reviewed += 1
            total_input_tokens += review_result.input_tokens
            total_output_tokens += review_result.output_tokens
            if updated_finding is None:
                false_positives_removed += 1
        if updated_finding is not None:
            reviewed_findings.append(updated_finding)

    return reviewed_findings, AIUsageSummary(
        findings_reviewed=findings_reviewed,
        false_positives_removed=false_positives_removed,
        input_tokens=total_input_tokens,
        output_tokens=total_output_tokens,
        estimated_cost_usd=_calculate_cost_usd(total_input_tokens, total_output_tokens),
    )


def _apply_review_to_single_finding(
    finding: ScanFinding, api_key: str
) -> tuple[ScanFinding | None, AIReviewResult | None]:
    """Call Claude for one finding and return the result alongside the updated finding.

    The second tuple element is None when the API call fails — callers use this to
    distinguish a skipped review from a completed review that eliminated the finding.

    Args:
        finding: A medium-confidence finding whose code_context is already redacted.
        api_key: Resolved Anthropic API key.

    Returns:
        (updated_finding, review_result): updated_finding is None when Claude
        determines the finding is not a PHI risk, or the original finding on API
        failure. review_result is None on API failure, populated otherwise.
    """
    try:
        review_result = _request_ai_confidence_review(finding, api_key)
    except AIReviewError as review_error:
        _logger.warning(
            "AI review failed for %s in %s — using local score: %s",
            finding.entity_type,
            finding.file_path,
            type(review_error).__name__,
        )
        return finding, None

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
            "AI review eliminated false positive: %s in %s",
            finding.entity_type,
            finding.file_path,
        )
        return None, review_result

    return dataclasses.replace(finding, confidence=review_result.revised_confidence), review_result


def _qualifies_for_review(finding: ScanFinding, config: AIReviewConfig) -> bool:
    """Return True if this finding's confidence falls within the AI review band."""
    return config.lower_bound <= finding.confidence < config.upper_bound


def _redact_phi_from_context(finding: ScanFinding) -> str:
    """Return the finding's code context after verifying the redaction marker is present.

    ScanFinding enforces CODE_CONTEXT_REDACTED_VALUE at construction time, making
    this check redundant under normal operation. It exists as a defence-in-depth
    gate — if the ScanFinding contract were ever weakened, this explicit check at
    the outbound API boundary prevents raw PHI from escaping to Claude.

    Empty code_context is only permitted for entity types listed in
    AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES. All current detection layers
    produce at least a labelled segment/field context containing the redaction
    marker, so that allowlist is currently empty. Any future finding type that
    legitimately carries no source line must be added to the allowlist explicitly.

    Args:
        finding: A validated ScanFinding whose code_context has been redacted.

    Returns:
        The verified code context string, safe to transmit to external APIs.

    Raises:
        AIReviewError: If code_context is empty and entity_type is not in the
            permitted-empty allowlist, or if code_context is non-empty and lacks
            the redaction marker.
    """
    if not finding.code_context:
        if finding.entity_type not in AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES:
            raise AIReviewError(
                _EMPTY_CODE_CONTEXT_NOT_PERMITTED_ERROR.format(entity_type=finding.entity_type)
            )
        return finding.code_context
    if AI_REVIEW_REDACTED_PLACEHOLDER not in finding.code_context:
        raise AIReviewError(_PHI_SAFETY_VIOLATION_ERROR.format(entity_type=finding.entity_type))
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
        f"Line: {finding.line_number}\n"
        f"Local confidence: {finding.confidence:.2f}\n"
        f"Code context (PHI replaced with {AI_REVIEW_REDACTED_PLACEHOLDER}):\n"
        f"{redacted_context}\n\n"
        "Is this a genuine PHI/PII risk in production code? "
        "Respond in JSON: "
        '{"is_phi_risk": true/false, "confidence": 0.0-1.0, "reasoning": "..."}'
    )


def _strip_markdown_fence(response_text: str) -> str:
    """Remove markdown code fence wrappers from a Claude response string.

    Claude sometimes wraps JSON in ```json ... ``` fences. This strips the
    opening fence line and, when present, the closing fence line.

    Args:
        response_text: Raw response text that may contain markdown fences.

    Returns:
        The response text with fence lines removed, or the original if no fence found.
    """
    stripped = response_text.strip()
    if not stripped.startswith(_MARKDOWN_CODE_FENCE):
        return stripped
    lines = stripped.split("\n")
    if lines[-1].strip() == _MARKDOWN_CODE_FENCE:
        return "\n".join(lines[1:-1])
    return "\n".join(lines[1:])


def _parse_ai_response(response_text: str) -> _AIResponsePayload:
    """Parse Claude's JSON response into a typed payload.

    Args:
        response_text: Raw text response from Claude.

    Returns:
        _AIResponsePayload with is_phi_risk, confidence, and reasoning fields.

    Raises:
        AIReviewError: If the response cannot be parsed or is missing required keys.
    """
    fence_stripped_response = _strip_markdown_fence(response_text)
    try:
        decoded_response = json.loads(fence_stripped_response)
    except (json.JSONDecodeError, ValueError) as parse_error:
        raise AIReviewError(
            f"Could not parse AI response as JSON: {parse_error!r} — "
            f"response: {response_text[:AI_RESPONSE_TRUNCATION_LENGTH]}"
        ) from parse_error

    missing_keys = AI_RESPONSE_REQUIRED_KEYS - decoded_response.keys()
    if missing_keys:
        raise AIReviewError(
            f"AI response missing required keys {missing_keys!r} — "
            f"response: {response_text[:AI_RESPONSE_TRUNCATION_LENGTH]}"
        )
    # reasoning is validated (present in decoded_response per AI_RESPONSE_REQUIRED_KEYS)
    # but never accessed or extracted — only is_phi_risk and confidence are read out.
    return _AIResponsePayload(
        is_phi_risk=bool(decoded_response["is_phi_risk"]),
        confidence=float(decoded_response["confidence"]),
    )


def _calculate_cost_usd(input_tokens: int, output_tokens: int) -> float:
    """Calculate estimated API cost in USD from token counts.

    Args:
        input_tokens: Total prompt tokens consumed.
        output_tokens: Total completion tokens consumed.

    Returns:
        Estimated cost in USD based on published claude-sonnet-4-6 rates.
    """
    input_cost = (input_tokens / AI_TOKENS_PER_MILLION) * AI_COST_PER_MILLION_INPUT_TOKENS
    output_cost = (output_tokens / AI_TOKENS_PER_MILLION) * AI_COST_PER_MILLION_OUTPUT_TOKENS
    return input_cost + output_cost


def _log_ai_usage_summary(summary: AIUsageSummary) -> None:
    """Emit a structured INFO log line with per-scan AI token usage and cost.

    Args:
        summary: Aggregated token usage for the completed scan.
    """
    if summary.findings_reviewed == 0:
        return
    _logger.info(
        "AI review scan summary: reviewed=%d eliminated=%d "
        "input_tokens=%d output_tokens=%d estimated_cost_usd=$%.4f",
        summary.findings_reviewed,
        summary.false_positives_removed,
        summary.input_tokens,
        summary.output_tokens,
        summary.estimated_cost_usd,
    )


def _extract_text_from_message(claude_message_response: Any) -> str:
    """Extract the text content from a Claude API message response.

    claude_message_response is typed as Any because anthropic is an optional
    dependency loaded at runtime — its types are not available at module import time.

    Args:
        claude_message_response: A response object from anthropic.Anthropic().messages.create().

    Returns:
        The text content of the first content block.

    Raises:
        AIReviewError: If the first content block does not have a text attribute.
    """
    first_block = claude_message_response.content[AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX]
    if not hasattr(first_block, "text"):
        raise AIReviewError(
            _UNEXPECTED_CONTENT_BLOCK_ERROR.format(block_type=type(first_block).__name__)
        )
    return str(first_block.text)


def _call_claude_api(anthropic_client: Any, review_prompt: str) -> Any:
    """Invoke the Claude messages API with the given prompt.

    Separating the raw API call from error handling and response parsing keeps
    _request_ai_confidence_review under 30 lines.

    Args:
        anthropic_client: An instantiated anthropic.Anthropic client.
        review_prompt: The user-turn prompt text to send to Claude.

    Returns:
        The raw message response object from the Anthropic SDK.
    """
    return anthropic_client.messages.create(
        model=AI_MODEL_NAME,
        max_tokens=AI_RESPONSE_MAX_TOKENS,
        system=AI_REVIEW_SYSTEM_PROMPT,
        messages=[  # type: ignore[misc, unused-ignore]
            {AI_MESSAGE_ROLE_KEY: AI_MESSAGE_ROLE_USER, AI_MESSAGE_CONTENT_KEY: review_prompt}
        ],
    )


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

    review_prompt = _build_review_prompt(finding)
    try:
        claude_response = _call_claude_api(anthropic.Anthropic(api_key=api_key), review_prompt)
    except anthropic.APIError as api_error:
        raise AIReviewError(
            f"Claude API error reviewing {finding.entity_type} in {finding.file_path}: "
            f"{type(api_error).__name__}"
        ) from api_error

    response_text = _extract_text_from_message(claude_response)
    try:
        ai_response_payload = _parse_ai_response(response_text)
    except AIReviewError as parse_error:
        raise AIReviewError(
            _UNEXPECTED_AI_RESPONSE_ERROR_TEMPLATE.format(
                entity_type=finding.entity_type,
                file_path=finding.file_path,
                error=parse_error,
            )
        ) from parse_error

    return AIReviewResult(
        original_confidence=finding.confidence,
        revised_confidence=ai_response_payload["confidence"],
        is_phi_risk=ai_response_payload["is_phi_risk"],
        input_tokens=claude_response.usage.input_tokens,
        output_tokens=claude_response.usage.output_tokens,
    )
