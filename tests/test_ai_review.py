"""Tests for phi_scan.ai_review — AI confidence review layer (Phase 7A).

PHI safety sentinels verify that no raw PHI value can reach the Claude API.
Functional tests verify the review band, fallback behavior, and token logging.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phi_scan.ai_review import (
    AIReviewConfig,
    AIReviewResult,
    apply_ai_review_to_findings,
    resolve_api_key,
)
from phi_scan.constants import (
    AI_CONFIDENCE_REVIEW_LOWER_BOUND,
    AI_CONFIDENCE_REVIEW_UPPER_BOUND,
    CODE_CONTEXT_REDACTED_VALUE,
    SHA256_HEX_DIGEST_LENGTH,
    DetectionLayer,
    PhiCategory,
    SeverityLevel,
)
from phi_scan.exceptions import AIConfigurationError, AIReviewError
from phi_scan.models import ScanFinding

# ---------------------------------------------------------------------------
# Constants — no string literals in logic
# ---------------------------------------------------------------------------

_FINDING_FILE_PATH: Path = Path("src/patient_handler.py")
_FINDING_LINE_NUMBER: int = 10
_FINDING_ENTITY_TYPE: str = "us_ssn"
_FINDING_VALUE_HASH: str = "a" * SHA256_HEX_DIGEST_LENGTH
_FINDING_REMEDIATION_HINT: str = "Replace SSN with a synthetic value."
_FINDING_CODE_CONTEXT: str = f"ssn = '{CODE_CONTEXT_REDACTED_VALUE}'"

# Confidence values inside and outside the review band
_CONFIDENCE_BELOW_BAND: float = AI_CONFIDENCE_REVIEW_LOWER_BOUND - 0.10
_CONFIDENCE_IN_BAND: float = (
    AI_CONFIDENCE_REVIEW_LOWER_BOUND + AI_CONFIDENCE_REVIEW_UPPER_BOUND
) / 2
_CONFIDENCE_AT_LOWER_BOUND: float = AI_CONFIDENCE_REVIEW_LOWER_BOUND
_CONFIDENCE_AT_UPPER_BOUND: float = AI_CONFIDENCE_REVIEW_UPPER_BOUND
_CONFIDENCE_ABOVE_BAND: float = AI_CONFIDENCE_REVIEW_UPPER_BOUND + 0.05

_VALID_API_KEY: str = "sk-ant-test-key"
_ENV_VAR_NAME: str = "ANTHROPIC_API_KEY"

_AI_REVISED_CONFIDENCE: float = 0.72
_AI_REVISED_CONFIDENCE_LOW: float = 0.20
_AI_REASONING: str = "The pattern matches a real SSN format in production code."
_AI_INPUT_TOKENS: int = 150
_AI_OUTPUT_TOKENS: int = 48


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_finding(confidence: float = _CONFIDENCE_IN_BAND) -> ScanFinding:
    """Return a ScanFinding with a given confidence score for testing."""
    return ScanFinding(
        file_path=_FINDING_FILE_PATH,
        line_number=_FINDING_LINE_NUMBER,
        entity_type=_FINDING_ENTITY_TYPE,
        hipaa_category=PhiCategory.SSN,
        confidence=confidence,
        detection_layer=DetectionLayer.REGEX,
        value_hash=_FINDING_VALUE_HASH,
        severity=SeverityLevel.HIGH,
        code_context=_FINDING_CODE_CONTEXT,
        remediation_hint=_FINDING_REMEDIATION_HINT,
    )


def _build_mock_anthropic_response(
    is_phi_risk: bool,
    confidence: float,
    reasoning: str,
    input_tokens: int = _AI_INPUT_TOKENS,
    output_tokens: int = _AI_OUTPUT_TOKENS,
) -> MagicMock:
    """Build a mock Anthropic message response."""
    response_body = json.dumps(
        {"is_phi_risk": is_phi_risk, "confidence": confidence, "reasoning": reasoning}
    )
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=response_body)]
    mock_message.usage.input_tokens = input_tokens
    mock_message.usage.output_tokens = output_tokens
    return mock_message


# ---------------------------------------------------------------------------
# PHI safety sentinels
# ---------------------------------------------------------------------------


class TestPhiSafety:
    """PHI safety invariants — no raw PHI must ever reach the AI layer."""

    def test_code_context_is_redacted_at_construction(self) -> None:
        """ScanFinding enforces CODE_CONTEXT_REDACTED_VALUE before construction."""
        finding = _build_finding()
        assert CODE_CONTEXT_REDACTED_VALUE in finding.code_context

    def test_value_hash_not_in_code_context(self) -> None:
        """The SHA-256 hash stored in value_hash must not appear in code_context."""
        finding = _build_finding()
        assert finding.value_hash not in finding.code_context

    def test_raw_phi_construction_rejected(self) -> None:
        """ScanFinding raises PhiDetectionError when code_context lacks the redaction marker."""
        from phi_scan.exceptions import PhiDetectionError

        with pytest.raises(PhiDetectionError):
            ScanFinding(
                file_path=_FINDING_FILE_PATH,
                line_number=_FINDING_LINE_NUMBER,
                entity_type=_FINDING_ENTITY_TYPE,
                hipaa_category=PhiCategory.SSN,
                confidence=_CONFIDENCE_IN_BAND,
                detection_layer=DetectionLayer.REGEX,
                value_hash=_FINDING_VALUE_HASH,
                severity=SeverityLevel.HIGH,
                code_context="ssn = '123-45-6789'",  # raw PHI — must be rejected
                remediation_hint=_FINDING_REMEDIATION_HINT,
            )


# ---------------------------------------------------------------------------
# resolve_api_key
# ---------------------------------------------------------------------------


class TestResolveApiKey:
    """API key resolution order: env var > config field > error."""

    def test_env_var_takes_precedence_over_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        config = AIReviewConfig(is_enabled=True, api_key="config-key")
        assert resolve_api_key(config) == _VALID_API_KEY

    def test_config_key_used_when_env_var_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_ENV_VAR_NAME, raising=False)
        config = AIReviewConfig(is_enabled=True, api_key=_VALID_API_KEY)
        assert resolve_api_key(config) == _VALID_API_KEY

    def test_missing_key_raises_ai_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(_ENV_VAR_NAME, raising=False)
        config = AIReviewConfig(is_enabled=True, api_key="")
        with pytest.raises(AIConfigurationError):
            resolve_api_key(config)


# ---------------------------------------------------------------------------
# apply_ai_review_to_findings — review band filtering
# ---------------------------------------------------------------------------


class TestReviewBandFiltering:
    """Findings outside the band bypass Claude entirely."""

    def test_disabled_config_returns_findings_unchanged(self) -> None:
        findings = [_build_finding(_CONFIDENCE_IN_BAND)]
        config = AIReviewConfig(is_enabled=False)
        result = apply_ai_review_to_findings(findings, config)
        assert result == findings

    def test_finding_below_lower_bound_bypasses_review(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_BELOW_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result == [finding]

    def test_finding_at_upper_bound_bypasses_review(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_AT_UPPER_BOUND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result == [finding]

    def test_finding_above_upper_bound_bypasses_review(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_ABOVE_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result == [finding]

    def test_finding_at_lower_bound_enters_review(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_AT_LOWER_BOUND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_AT_LOWER_BOUND,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            reasoning=_AI_REASONING,
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch(
            "phi_scan.ai_review._request_ai_confidence_review", return_value=review_result
        ) as mock_review:
            result = apply_ai_review_to_findings([finding], config)
        mock_review.assert_called_once()
        assert result[0].confidence == _AI_REVISED_CONFIDENCE


# ---------------------------------------------------------------------------
# apply_ai_review_to_findings — confidence update and false positive filtering
# ---------------------------------------------------------------------------


class TestConfidenceUpdateAndFalsePositive:
    """Confidence is updated when is_phi_risk=True; finding removed when False."""

    def test_confidence_updated_on_phi_risk_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_IN_BAND,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            reasoning=_AI_REASONING,
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result = apply_ai_review_to_findings([finding], config)
        assert len(result) == 1
        assert result[0].confidence == _AI_REVISED_CONFIDENCE

    def test_false_positive_eliminated_when_phi_risk_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_IN_BAND,
            revised_confidence=_AI_REVISED_CONFIDENCE_LOW,
            is_phi_risk=False,
            reasoning="This is a test fixture, not production code.",
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result = apply_ai_review_to_findings([finding], config)
        assert result == []

    def test_out_of_band_findings_preserved_alongside_reviewed_findings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        high_confidence_finding = _build_finding(_CONFIDENCE_ABOVE_BAND)
        in_band_finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_IN_BAND,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            reasoning=_AI_REASONING,
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result = apply_ai_review_to_findings([high_confidence_finding, in_band_finding], config)
        assert len(result) == 2
        assert result[0] is high_confidence_finding
        assert result[1].confidence == _AI_REVISED_CONFIDENCE


# ---------------------------------------------------------------------------
# Graceful fallback on AIReviewError
# ---------------------------------------------------------------------------


class TestGracefulFallback:
    """APIError must not crash the scan — original score returned instead."""

    def test_api_failure_falls_back_to_original_confidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch(
            "phi_scan.ai_review._request_ai_confidence_review",
            side_effect=AIReviewError("Claude API timeout"),
        ):
            result = apply_ai_review_to_findings([finding], config)
        assert len(result) == 1
        assert result[0].confidence == _CONFIDENCE_IN_BAND

    def test_single_finding_failure_does_not_affect_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        failing_finding = _build_finding(_CONFIDENCE_IN_BAND)
        passing_finding = _build_finding(AI_CONFIDENCE_REVIEW_LOWER_BOUND + 0.05)
        config = AIReviewConfig(is_enabled=True)
        success_result = AIReviewResult(
            original_confidence=passing_finding.confidence,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            reasoning=_AI_REASONING,
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )

        def _side_effect(finding: ScanFinding, api_key: str) -> AIReviewResult:
            if finding is failing_finding:
                raise AIReviewError("transient timeout")
            return success_result

        with patch("phi_scan.ai_review._request_ai_confidence_review", side_effect=_side_effect):
            result = apply_ai_review_to_findings([failing_finding, passing_finding], config)
        assert len(result) == 2
        assert result[0].confidence == _CONFIDENCE_IN_BAND
        assert result[1].confidence == _AI_REVISED_CONFIDENCE


# ---------------------------------------------------------------------------
# _parse_ai_response
# ---------------------------------------------------------------------------


class TestParseAiResponse:
    """JSON parsing and validation of Claude's response."""

    def test_valid_json_parsed_correctly(self) -> None:
        from phi_scan.ai_review import _parse_ai_response

        response = json.dumps(
            {"is_phi_risk": True, "confidence": 0.85, "reasoning": "Looks like real data."}
        )
        parsed = _parse_ai_response(response)
        assert parsed["is_phi_risk"] is True
        assert parsed["confidence"] == pytest.approx(0.85)

    def test_markdown_fenced_json_parsed(self) -> None:
        from phi_scan.ai_review import _parse_ai_response

        response = '```json\n{"is_phi_risk": false, "confidence": 0.1, "reasoning": "test"}\n```'
        parsed = _parse_ai_response(response)
        assert parsed["is_phi_risk"] is False

    def test_invalid_json_raises_ai_review_error(self) -> None:
        from phi_scan.ai_review import _parse_ai_response

        with pytest.raises(AIReviewError, match="Could not parse"):
            _parse_ai_response("not valid json {")

    def test_missing_required_key_raises_ai_review_error(self) -> None:
        from phi_scan.ai_review import _parse_ai_response

        response = json.dumps({"is_phi_risk": True, "confidence": 0.8})
        with pytest.raises(AIReviewError, match="missing required keys"):
            _parse_ai_response(response)


# ---------------------------------------------------------------------------
# Missing anthropic package
# ---------------------------------------------------------------------------


class TestMissingAnthropic:
    """AIConfigurationError raised when anthropic package is not installed."""

    def test_missing_anthropic_package_raises_ai_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)

        import builtins

        original_import = builtins.__import__

        def _mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_mock_import):
            with pytest.raises(AIConfigurationError, match="anthropic"):
                from phi_scan.ai_review import _request_ai_confidence_review

                _request_ai_confidence_review(finding, _VALID_API_KEY)
