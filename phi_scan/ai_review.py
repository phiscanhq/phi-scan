"""AI confidence review layer for PhiScan — Phase 7A/7D.

Sends redacted code context to an AI provider to re-score medium-confidence
findings and reduce false positives. High-confidence and regex-only findings
bypass this layer entirely.

PHI Safety contract:
- All matched PHI values are replaced with ``[REDACTED]`` before any API call.
- Only code structure with redacted values is transmitted — no raw PHI ever leaves
  the local machine.
- The redaction is verified by ``_redact_phi_from_context`` before the payload
  is constructed.

BYOAK (Bring Your Own API Key):
- API key is resolved from an environment variable based on the model name:
    - ``claude-*``                    → ``ANTHROPIC_API_KEY``
    - ``gpt-*``, ``o1``/``o3``/``o4``→ ``OPENAI_API_KEY``
    - ``gemini-*``                    → ``GOOGLE_API_KEY``
- Raises ``AIConfigurationError`` if AI is enabled but no key is found.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, TypedDict

from phi_scan.constants import (
    AI_ANTHROPIC_COST_PER_MILLION_INPUT_TOKENS,
    AI_ANTHROPIC_COST_PER_MILLION_OUTPUT_TOKENS,
    AI_CONFIDENCE_REVIEW_LOWER_BOUND,
    AI_CONFIDENCE_REVIEW_UPPER_BOUND,
    AI_DEFAULT_MODEL,
    AI_GOOGLE_COST_PER_MILLION_INPUT_TOKENS,
    AI_GOOGLE_COST_PER_MILLION_OUTPUT_TOKENS,
    AI_MESSAGE_CONTENT_KEY,
    AI_MESSAGE_ROLE_KEY,
    AI_MESSAGE_ROLE_USER,
    AI_OPENAI_COST_PER_MILLION_INPUT_TOKENS,
    AI_OPENAI_COST_PER_MILLION_OUTPUT_TOKENS,
    AI_PROVIDER_ANTHROPIC,
    AI_PROVIDER_GOOGLE,
    AI_PROVIDER_OPENAI,
    AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX,
    AI_RESPONSE_MAX_TOKENS,
    AI_RESPONSE_REQUIRED_KEYS,
    AI_RESPONSE_TRUNCATION_LENGTH,
    AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES,
    AI_REVIEW_REDACTED_PLACEHOLDER,
    AI_REVIEW_SYSTEM_PROMPT,
    AI_TOKENS_PER_MILLION,
    ANTHROPIC_API_KEY_ENV_VAR,
    GOOGLE_API_KEY_ENV_VAR,
    OPENAI_API_KEY_ENV_VAR,
)
from phi_scan.exceptions import AIConfigurationError, AIReviewError
from phi_scan.models import ScanFinding

__all__ = [
    "AIProvider",
    "AIReviewConfig",
    "AIReviewResult",
    "AIUsageSummary",
    "apply_ai_review_to_findings",
    "resolve_api_key",
]

_logger = logging.getLogger(__name__)

_MARKDOWN_CODE_FENCE: str = "```"

_MISSING_API_KEY_ERROR_TEMPLATE: str = (
    "AI review is enabled but no API key was found for provider '{provider}'. "
    "Set the {env_var} environment variable. "
    "To disable AI review set 'ai.enable_ai_review: false'."
)
_UNKNOWN_MODEL_ERROR_TEMPLATE: str = (
    "Cannot determine AI provider from model name {model!r}. "
    "Model names must start with 'claude-' (Anthropic), 'gpt-' or 'o1'/'o3'/'o4' (OpenAI), "
    "or 'gemini-' (Google)."
)
_AI_ANTHROPIC_IMPORT_ERROR: str = (
    "The 'anthropic' package is required to use Anthropic models. "
    "Install it with: pip install phi-scan[ai-anthropic]"
)
_AI_OPENAI_IMPORT_ERROR: str = (
    "The 'openai' package is required to use OpenAI models. "
    "Install it with: pip install phi-scan[ai-openai]"
)
_AI_GOOGLE_IMPORT_ERROR: str = (
    "The 'google-generativeai' package is required to use Google AI models. "
    "Install it with: pip install phi-scan[ai-google]"
)
_UNEXPECTED_AI_RESPONSE_ERROR_TEMPLATE: str = (
    "Unexpected AI response structure for finding {entity_type} in {file_path}: {error}"
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
_UNEXPECTED_CONTENT_BLOCK_ERROR: str = (
    "AI provider returned a non-text content block ({block_type!r}) — expected text"
)

# Model name prefixes used to detect which provider to route to.
_ANTHROPIC_MODEL_PREFIX: str = "claude-"
_GOOGLE_MODEL_PREFIX: str = "gemini-"
# OpenAI o-series model base names (matched with or without a hyphen suffix).
_OPENAI_O_SERIES_BASES: tuple[str, ...] = ("o1", "o3", "o4")

# Maps provider name → env var name (used to build the missing-key error message).
_PROVIDER_ENV_VARS: dict[str, str] = {
    AI_PROVIDER_ANTHROPIC: ANTHROPIC_API_KEY_ENV_VAR,
    AI_PROVIDER_OPENAI: OPENAI_API_KEY_ENV_VAR,
    AI_PROVIDER_GOOGLE: GOOGLE_API_KEY_ENV_VAR,
}

# Maps provider name → (input_rate, output_rate) per million tokens.
_PROVIDER_COST_RATES: dict[str, tuple[float, float]] = {
    AI_PROVIDER_ANTHROPIC: (
        AI_ANTHROPIC_COST_PER_MILLION_INPUT_TOKENS,
        AI_ANTHROPIC_COST_PER_MILLION_OUTPUT_TOKENS,
    ),
    AI_PROVIDER_OPENAI: (
        AI_OPENAI_COST_PER_MILLION_INPUT_TOKENS,
        AI_OPENAI_COST_PER_MILLION_OUTPUT_TOKENS,
    ),
    AI_PROVIDER_GOOGLE: (
        AI_GOOGLE_COST_PER_MILLION_INPUT_TOKENS,
        AI_GOOGLE_COST_PER_MILLION_OUTPUT_TOKENS,
    ),
}


class _AIResponsePayload(TypedDict):
    """Typed structure of the JSON the AI provider returns.

    reasoning is intentionally excluded from AI_RESPONSE_REQUIRED_KEYS and from
    this TypedDict. The explanation may paraphrase PHI context — we never want to
    store, access, or log it. Not requiring it also means the contract does not
    break if a future model version omits the field.
    """

    is_phi_risk: bool
    confidence: float


class AIProvider(Protocol):
    """Protocol satisfied by each per-provider adapter.

    Implementations must perform a lazy import of their SDK inside
    ``call_review_api`` so that the SDK is only required at runtime when
    the provider is actually used, not at module import time.
    """

    def call_review_api(self, prompt: str, model: str) -> tuple[str, int, int]:
        """Call the provider API and return (response_text, input_tokens, output_tokens).

        Args:
            prompt: The user-turn prompt text (PHI already redacted).
            model: The model name to invoke (e.g. ``claude-sonnet-4-6``).

        Returns:
            Three-tuple of (response_text, input_token_count, output_token_count).

        Raises:
            AIConfigurationError: If the provider SDK is not installed.
            AIReviewError: If the API call fails.
        """
        ...


@dataclass
class AIUsageSummary:
    """Aggregated token usage and cost across all AI review calls in one scan.

    Args:
        findings_reviewed: Number of findings sent to the AI provider for re-scoring.
        false_positives_removed: Findings the AI determined were not PHI risks.
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
        is_enabled: Whether to call an AI provider for medium-confidence findings.
        model: Model name to use for confidence review. The provider is inferred
            from the model prefix: ``claude-*`` → Anthropic, ``gpt-*``/``o1``/
            ``o3``/``o4`` → OpenAI, ``gemini-*`` → Google. Defaults to the
            Anthropic claude-sonnet-4-6 model.
        lower_bound: Minimum confidence score that qualifies for AI review.
        upper_bound: Maximum confidence score that qualifies for AI review.
            Findings at or above this value bypass AI review entirely.
    """

    is_enabled: bool = False
    model: str = field(default=AI_DEFAULT_MODEL)
    lower_bound: float = AI_CONFIDENCE_REVIEW_LOWER_BOUND
    upper_bound: float = AI_CONFIDENCE_REVIEW_UPPER_BOUND


@dataclass
class AIReviewResult:
    """Result of a single AI provider confidence review call.

    reasoning is intentionally absent — the AI explanation may paraphrase PHI
    context. It is parsed inside _request_ai_confidence_review and immediately
    discarded without logging or storage.

    Args:
        original_confidence: Confidence score from the local detection layer.
        revised_confidence: Confidence score returned by the AI provider.
        is_phi_risk: Whether the AI considers this a genuine PHI risk.
        input_tokens: Tokens consumed in the request (for cost tracking).
        output_tokens: Tokens consumed in the response (for cost tracking).
    """

    original_confidence: float
    revised_confidence: float
    is_phi_risk: bool
    input_tokens: int
    output_tokens: int


def resolve_api_key(model: str) -> str:
    """Return the API key for the provider inferred from the model name.

    Reads the appropriate environment variable based on the model prefix:
    - ``claude-*``                    → ``ANTHROPIC_API_KEY``
    - ``gpt-*``, ``o1``/``o3``/``o4``→ ``OPENAI_API_KEY``
    - ``gemini-*``                    → ``GOOGLE_API_KEY``

    Args:
        model: The model name used to detect the provider.

    Returns:
        The resolved API key string.

    Raises:
        AIConfigurationError: If the model prefix is unrecognised or no key is found.
    """
    provider = _detect_provider_name(model)
    env_var = _PROVIDER_ENV_VARS[provider]
    key = os.environ.get(env_var, "")
    if not key:
        raise AIConfigurationError(
            _MISSING_API_KEY_ERROR_TEMPLATE.format(provider=provider, env_var=env_var)
        )
    return key


def apply_ai_review_to_findings(
    findings: list[ScanFinding],
    config: AIReviewConfig,
) -> tuple[list[ScanFinding], AIUsageSummary | None]:
    """Apply AI provider confidence review to medium-confidence findings.

    Findings outside the review band [lower_bound, upper_bound) are returned
    unchanged. Findings within the band are sent to the AI provider with redacted
    context; the returned confidence replaces the local score. Findings the AI
    scores as not PHI risks are removed (false positives eliminated).

    If the API call fails for any finding, that finding is returned with its
    original confidence score — the scan never crashes due to AI unavailability.

    Args:
        findings: All findings from the local detection layers.
        config: AI review configuration including the review band and model name.

    Returns:
        Tuple of (updated findings list, AI usage summary). Usage summary is None
        when AI review is disabled. Findings the AI determined are not PHI risks
        are removed from the list.
    """
    if not config.is_enabled:
        return findings, None
    api_key = resolve_api_key(config.model)
    provider = _get_provider(config.model, api_key)
    reviewed_findings, usage_summary = _review_qualifying_findings(findings, provider, config)
    _log_ai_usage_summary(usage_summary)
    return reviewed_findings, usage_summary


def _detect_provider_name(model: str) -> str:
    """Return the provider name for the given model name.

    Args:
        model: A model name string such as ``claude-sonnet-4-6`` or ``gpt-4o``.

    Returns:
        One of ``AI_PROVIDER_ANTHROPIC``, ``AI_PROVIDER_OPENAI``, ``AI_PROVIDER_GOOGLE``.

    Raises:
        AIConfigurationError: If the model name does not match any known provider prefix.
    """
    if model.startswith(_ANTHROPIC_MODEL_PREFIX):
        return AI_PROVIDER_ANTHROPIC
    if _is_openai_model(model):
        return AI_PROVIDER_OPENAI
    if model.startswith(_GOOGLE_MODEL_PREFIX):
        return AI_PROVIDER_GOOGLE
    raise AIConfigurationError(_UNKNOWN_MODEL_ERROR_TEMPLATE.format(model=model))


def _is_openai_model(model: str) -> bool:
    """Return True if the model name identifies an OpenAI model.

    Covers:
    - ``gpt-*`` (e.g. ``gpt-4o``, ``gpt-4o-mini``, ``gpt-3.5-turbo``)
    - ``o1``, ``o1-mini``, ``o1-preview``, ``o3``, ``o3-mini``, ``o4-mini``, etc.
    """
    if model.startswith("gpt-"):
        return True
    return any(model == base or model.startswith(f"{base}-") for base in _OPENAI_O_SERIES_BASES)


def _get_provider(model: str, api_key: str) -> AIProvider:
    """Instantiate and return the provider adapter for the given model.

    Args:
        model: A model name string used to select the provider.
        api_key: The resolved API key for the provider.

    Returns:
        A concrete AIProvider adapter instance.
    """
    provider_name = _detect_provider_name(model)
    if provider_name == AI_PROVIDER_ANTHROPIC:
        return _AnthropicProvider(api_key)
    if provider_name == AI_PROVIDER_OPENAI:
        return _OpenAIProvider(api_key)
    return _GoogleProvider(api_key)


class _AnthropicProvider:
    """AI provider adapter for Anthropic (Claude) models.

    The ``anthropic`` SDK is imported lazily inside ``call_review_api`` so that
    the package is not required unless an Anthropic model is actually selected.
    Install with: ``pip install phi-scan[ai-anthropic]``
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def call_review_api(self, prompt: str, model: str) -> tuple[str, int, int]:
        """Call the Anthropic messages API and return (text, input_tokens, output_tokens)."""
        try:
            import anthropic
        except ImportError as import_error:
            raise AIConfigurationError(_AI_ANTHROPIC_IMPORT_ERROR) from import_error
        user_message: Any = {
            AI_MESSAGE_ROLE_KEY: AI_MESSAGE_ROLE_USER,
            AI_MESSAGE_CONTENT_KEY: prompt,
        }
        try:
            client = anthropic.Anthropic(api_key=self._api_key)
            response = client.messages.create(
                model=model,
                max_tokens=AI_RESPONSE_MAX_TOKENS,
                system=AI_REVIEW_SYSTEM_PROMPT,
                messages=[user_message],
            )
        except anthropic.APIError as api_error:
            raise AIReviewError(f"Anthropic API error: {type(api_error).__name__}") from api_error
        first_block = response.content[AI_RESPONSE_FIRST_CONTENT_BLOCK_INDEX]
        if not hasattr(first_block, "text"):
            raise AIReviewError(
                _UNEXPECTED_CONTENT_BLOCK_ERROR.format(block_type=type(first_block).__name__)
            )
        return str(first_block.text), response.usage.input_tokens, response.usage.output_tokens


class _OpenAIProvider:
    """AI provider adapter for OpenAI (GPT / o-series) models.

    The ``openai`` SDK is imported lazily inside ``call_review_api`` so that
    the package is not required unless an OpenAI model is actually selected.
    Install with: ``pip install phi-scan[ai-openai]``
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def call_review_api(self, prompt: str, model: str) -> tuple[str, int, int]:
        """Call the OpenAI chat completions API and return (text, input_tokens, output_tokens)."""
        try:
            import openai
        except ImportError as import_error:
            raise AIConfigurationError(_AI_OPENAI_IMPORT_ERROR) from import_error
        try:
            client = openai.OpenAI(api_key=self._api_key)
            response = client.chat.completions.create(
                model=model,
                max_tokens=AI_RESPONSE_MAX_TOKENS,
                messages=[  # type: ignore[misc, unused-ignore]
                    {"role": "system", "content": AI_REVIEW_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
        except openai.APIError as api_error:
            raise AIReviewError(f"OpenAI API error: {type(api_error).__name__}") from api_error
        choice = response.choices[0]
        if choice.message.content is None:
            raise AIReviewError(f"OpenAI returned null content for model {model!r}")
        usage = response.usage
        input_tokens = usage.prompt_tokens if usage is not None else 0
        output_tokens = usage.completion_tokens if usage is not None else 0
        return choice.message.content, input_tokens, output_tokens


class _GoogleProvider:
    """AI provider adapter for Google AI (Gemini) models.

    The ``google-generativeai`` SDK is imported lazily inside ``call_review_api``
    so that the package is not required unless a Google model is selected.
    Install with: ``pip install phi-scan[ai-google]``
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def call_review_api(self, prompt: str, model: str) -> tuple[str, int, int]:
        """Call the Google Generative AI API and return (text, input_tokens, output_tokens)."""
        try:
            import google.generativeai as genai
        except ImportError as import_error:
            raise AIConfigurationError(_AI_GOOGLE_IMPORT_ERROR) from import_error
        try:
            genai.configure(api_key=self._api_key)
            model_instance = genai.GenerativeModel(
                model_name=model,
                system_instruction=AI_REVIEW_SYSTEM_PROMPT,
            )
            response = model_instance.generate_content(prompt)
        except Exception as api_error:
            raise AIReviewError(f"Google AI API error: {type(api_error).__name__}") from api_error
        response_text = response.text
        usage = response.usage_metadata
        input_tokens = usage.prompt_token_count if usage is not None else 0
        output_tokens = usage.candidates_token_count if usage is not None else 0
        return response_text, input_tokens, output_tokens


def _review_qualifying_findings(
    findings: list[ScanFinding],
    provider: AIProvider,
    config: AIReviewConfig,
) -> tuple[list[ScanFinding], AIUsageSummary]:
    """Dispatch AI review for each qualifying finding and accumulate usage stats.

    Args:
        findings: All findings from the local detection layers.
        provider: The instantiated AI provider adapter.
        config: AI review configuration for band filtering and model name.

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
        updated_finding, review_result = _apply_review_to_single_finding(
            finding, provider, config.model
        )
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
        estimated_cost_usd=_calculate_cost_usd(
            config.model, total_input_tokens, total_output_tokens
        ),
    )


def _apply_review_to_single_finding(
    finding: ScanFinding,
    provider: AIProvider,
    model: str,
) -> tuple[ScanFinding | None, AIReviewResult | None]:
    """Call the AI provider for one finding and return the result.

    The second tuple element is None when the API call fails — callers use this to
    distinguish a skipped review from a completed review that eliminated the finding.

    Args:
        finding: A medium-confidence finding whose code_context is already redacted.
        provider: The instantiated AI provider adapter.
        model: The model name used for log messages.

    Returns:
        (updated_finding, review_result): updated_finding is None when the AI
        determines the finding is not a PHI risk, or the original finding on API
        failure. review_result is None on API failure, populated otherwise.
    """
    try:
        review_result = _request_ai_confidence_review(finding, provider, model)
    except AIReviewError as review_error:
        # Log only the exception type, not str(review_error). AIReviewError messages
        # embed entity_type and file_path (never raw PHI), but at this outbound log
        # boundary we are conservative — type name is sufficient to triage failures.
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
    the outbound API boundary prevents raw PHI from escaping to any external service.

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
    """Build the user prompt for AI confidence review.

    Only structural metadata and redacted context are included. The matched
    PHI value is never present — code_context already contains only
    CODE_CONTEXT_REDACTED_VALUE.

    Args:
        finding: Finding with redacted code context.

    Returns:
        Prompt string safe to send to any AI provider.
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
    """Remove markdown code fence wrappers from an AI response string.

    AI providers sometimes wrap JSON in ```json ... ``` fences. This strips the
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
    """Parse the AI provider's JSON response into a typed payload.

    Args:
        response_text: Raw text response from the AI provider.

    Returns:
        _AIResponsePayload with is_phi_risk and confidence fields. reasoning is
        not required and not extracted — see _AIResponsePayload for the rationale.

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
    return _AIResponsePayload(
        is_phi_risk=bool(decoded_response["is_phi_risk"]),
        confidence=float(decoded_response["confidence"]),
    )


def _calculate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate estimated API cost in USD from token counts.

    Selects cost rates based on the provider inferred from the model name.
    Falls back to Anthropic rates for unrecognised models so the function
    never raises during scan teardown.

    Args:
        model: Model name used to select provider cost rates.
        input_tokens: Total prompt tokens consumed.
        output_tokens: Total completion tokens consumed.

    Returns:
        Estimated cost in USD.
    """
    try:
        provider = _detect_provider_name(model)
    except AIConfigurationError:
        provider = AI_PROVIDER_ANTHROPIC
    input_rate, output_rate = _PROVIDER_COST_RATES[provider]
    input_cost = (input_tokens / AI_TOKENS_PER_MILLION) * input_rate
    output_cost = (output_tokens / AI_TOKENS_PER_MILLION) * output_rate
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


def _request_ai_confidence_review(
    finding: ScanFinding,
    provider: AIProvider,
    model: str,
) -> AIReviewResult:
    """Call the AI provider to review a single medium-confidence finding.

    Args:
        finding: Finding to review. Its code_context must be redacted.
        provider: The instantiated AI provider adapter.
        model: Model name (used in error messages).

    Returns:
        AIReviewResult with the revised confidence and PHI risk determination.

    Raises:
        AIReviewError: If the API call fails or the response cannot be parsed.
        AIConfigurationError: If the provider SDK is not installed.
    """
    review_prompt = _build_review_prompt(finding)
    try:
        response_text, input_tokens, output_tokens = provider.call_review_api(review_prompt, model)
    except (AIReviewError, AIConfigurationError):
        raise
    except Exception as unexpected_error:
        raise AIReviewError(
            f"Unexpected error reviewing {finding.entity_type} in {finding.file_path}: "
            f"{type(unexpected_error).__name__}"
        ) from unexpected_error

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
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


# Retained for backward compatibility — callers that imported _extract_text_from_message
# directly should migrate to _AnthropicProvider.call_review_api.
def _extract_text_from_message(claude_message_response: Any) -> str:
    """Extract text from a Claude API response (legacy — use _AnthropicProvider).

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
