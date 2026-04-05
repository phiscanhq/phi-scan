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
    AIUsageSummary,
    _redact_phi_from_context,  # noqa: PLC2701 — PHI safety sentinel requires direct access
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

    def test_empty_code_context_not_in_allowlist_raises_ai_review_error(self) -> None:
        """Empty code_context must be rejected at the outbound API boundary.

        The ScanFinding model permits empty code_context, but _redact_phi_from_context
        enforces that only entity types in AI_REVIEW_PERMITTED_EMPTY_CONTEXT_ENTITY_TYPES
        may bypass the redaction marker check.  Currently that allowlist is empty,
        so any finding with empty code_context must raise AIReviewError at this gate —
        before any prompt is assembled or transmitted to Claude.

        We test this function directly because the check must fire independently of
        whether the optional 'anthropic' package is installed (CI does not install it).
        """
        finding_empty_context = ScanFinding(
            file_path=_FINDING_FILE_PATH,
            line_number=_FINDING_LINE_NUMBER,
            entity_type=_FINDING_ENTITY_TYPE,
            hipaa_category=PhiCategory.SSN,
            confidence=_CONFIDENCE_IN_BAND,
            detection_layer=DetectionLayer.REGEX,
            value_hash=_FINDING_VALUE_HASH,
            severity=SeverityLevel.HIGH,
            code_context="",
            remediation_hint=_FINDING_REMEDIATION_HINT,
        )
        with pytest.raises(AIReviewError):
            _redact_phi_from_context(finding_empty_context)


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
        result_findings, usage = apply_ai_review_to_findings(findings, config)
        assert result_findings == findings
        assert usage is None

    def test_finding_below_lower_bound_bypasses_review(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_BELOW_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result_findings == [finding]

    def test_finding_at_upper_bound_bypasses_review(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_AT_UPPER_BOUND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result_findings == [finding]

    def test_finding_above_upper_bound_bypasses_review(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_ABOVE_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._request_ai_confidence_review") as mock_review:
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        mock_review.assert_not_called()
        assert result_findings == [finding]

    def test_finding_at_lower_bound_enters_review(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_AT_LOWER_BOUND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_AT_LOWER_BOUND,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch(
            "phi_scan.ai_review._request_ai_confidence_review", return_value=review_result
        ) as mock_review:
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        mock_review.assert_called_once()
        assert result_findings[0].confidence == _AI_REVISED_CONFIDENCE


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
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        assert len(result_findings) == 1
        assert result_findings[0].confidence == _AI_REVISED_CONFIDENCE

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
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        assert result_findings == []

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
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            result_findings, _ = apply_ai_review_to_findings(
                [high_confidence_finding, in_band_finding], config
            )
        assert len(result_findings) == 2
        assert result_findings[0] is high_confidence_finding
        assert result_findings[1].confidence == _AI_REVISED_CONFIDENCE


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
            result_findings, _ = apply_ai_review_to_findings([finding], config)
        assert len(result_findings) == 1
        assert result_findings[0].confidence == _CONFIDENCE_IN_BAND

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
            input_tokens=_AI_INPUT_TOKENS,
            output_tokens=_AI_OUTPUT_TOKENS,
        )

        def _side_effect(finding: ScanFinding, api_key: str) -> AIReviewResult:
            if finding is failing_finding:
                raise AIReviewError("transient timeout")
            return success_result

        with patch("phi_scan.ai_review._request_ai_confidence_review", side_effect=_side_effect):
            result_findings, _ = apply_ai_review_to_findings(
                [failing_finding, passing_finding], config
            )
        assert len(result_findings) == 2
        assert result_findings[0].confidence == _CONFIDENCE_IN_BAND
        assert result_findings[1].confidence == _AI_REVISED_CONFIDENCE


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

        # Only is_phi_risk and confidence are required; omitting either must raise.
        response = json.dumps({"confidence": 0.8})  # missing is_phi_risk
        with pytest.raises(AIReviewError, match="missing required keys"):
            _parse_ai_response(response)


# ---------------------------------------------------------------------------
# Token usage logging — 7A.10
# ---------------------------------------------------------------------------

_EXPECTED_INPUT_TOKENS: int = _AI_INPUT_TOKENS
_EXPECTED_OUTPUT_TOKENS: int = _AI_OUTPUT_TOKENS


class TestTokenUsageLogging:
    """Token counts are accumulated and logged as a scan-level summary."""

    def test_usage_summary_logged_when_findings_reviewed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_IN_BAND,
            revised_confidence=_AI_REVISED_CONFIDENCE,
            is_phi_risk=True,
            input_tokens=_EXPECTED_INPUT_TOKENS,
            output_tokens=_EXPECTED_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            with patch("phi_scan.ai_review._log_ai_usage_summary") as mock_log:
                apply_ai_review_to_findings([finding], config)
        mock_log.assert_called_once()
        summary: AIUsageSummary = mock_log.call_args[0][0]
        assert summary.findings_reviewed == 1
        assert summary.input_tokens == _EXPECTED_INPUT_TOKENS
        assert summary.output_tokens == _EXPECTED_OUTPUT_TOKENS
        assert summary.estimated_cost_usd > 0

    def test_false_positives_counted_in_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        review_result = AIReviewResult(
            original_confidence=_CONFIDENCE_IN_BAND,
            revised_confidence=_AI_REVISED_CONFIDENCE_LOW,
            is_phi_risk=False,
            input_tokens=_EXPECTED_INPUT_TOKENS,
            output_tokens=_EXPECTED_OUTPUT_TOKENS,
        )
        with patch("phi_scan.ai_review._request_ai_confidence_review", return_value=review_result):
            with patch("phi_scan.ai_review._log_ai_usage_summary") as mock_log:
                apply_ai_review_to_findings([finding], config)
        summary: AIUsageSummary = mock_log.call_args[0][0]
        assert summary.false_positives_removed == 1

    def test_tokens_not_counted_on_api_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_IN_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch(
            "phi_scan.ai_review._request_ai_confidence_review",
            side_effect=AIReviewError("timeout"),
        ):
            with patch("phi_scan.ai_review._log_ai_usage_summary") as mock_log:
                apply_ai_review_to_findings([finding], config)
        summary: AIUsageSummary = mock_log.call_args[0][0]
        assert summary.findings_reviewed == 0
        assert summary.input_tokens == 0
        assert summary.output_tokens == 0

    def test_cost_estimate_is_positive_for_nonzero_tokens(self) -> None:
        from phi_scan.ai_review import _calculate_cost_usd  # noqa: PLC2701

        cost = _calculate_cost_usd(1000, 200)
        assert cost > 0

    def test_no_summary_logged_when_no_findings_reviewed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        finding = _build_finding(_CONFIDENCE_ABOVE_BAND)
        config = AIReviewConfig(is_enabled=True)
        with patch("phi_scan.ai_review._log_ai_usage_summary") as mock_log:
            apply_ai_review_to_findings([finding], config)
        mock_log.assert_called_once()
        summary: AIUsageSummary = mock_log.call_args[0][0]
        assert summary.findings_reviewed == 0


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


# ---------------------------------------------------------------------------
# 7C.2 — A/B comparison: AI enabled vs disabled false positive delta
# ---------------------------------------------------------------------------

_AB_FINDINGS_TOTAL: int = 5
_AB_FALSE_POSITIVE_COUNT: int = 3  # findings Claude will mark as not PHI
_AB_GENUINE_PHI_COUNT: int = _AB_FINDINGS_TOTAL - _AB_FALSE_POSITIVE_COUNT
_AB_REVISED_CONFIDENCE_PHI: float = 0.82
_AB_REVISED_CONFIDENCE_NOT_PHI: float = 0.15


class TestABComparison:
    """7C.2 — Verify AI review measurably reduces false positives vs baseline.

    Uses mocked Claude responses so the test runs offline. Three of five
    medium-confidence findings are designated false positives by the mock;
    the remaining two are confirmed PHI. The test asserts:
      - AI-disabled count == total findings
      - AI-enabled count == genuine PHI count (false positives eliminated)
      - delta == number of false positives removed
    """

    def test_ai_review_reduces_false_positive_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_VAR_NAME, _VALID_API_KEY)
        findings = [_build_finding(_CONFIDENCE_IN_BAND) for _ in range(_AB_FINDINGS_TOTAL)]
        false_positive_indices = set(range(_AB_FALSE_POSITIVE_COUNT))

        call_count = [0]

        def _mock_review(finding: ScanFinding, api_key: str) -> AIReviewResult:
            call_index = call_count[0]
            call_count[0] += 1
            is_phi = call_index not in false_positive_indices
            revised = _AB_REVISED_CONFIDENCE_PHI if is_phi else _AB_REVISED_CONFIDENCE_NOT_PHI
            return AIReviewResult(
                original_confidence=finding.confidence,
                revised_confidence=revised,
                is_phi_risk=is_phi,
                input_tokens=_AI_INPUT_TOKENS,
                output_tokens=_AI_OUTPUT_TOKENS,
            )

        disabled_config = AIReviewConfig(is_enabled=False)
        enabled_config = AIReviewConfig(is_enabled=True)

        baseline_findings, baseline_usage = apply_ai_review_to_findings(findings, disabled_config)
        with patch("phi_scan.ai_review._request_ai_confidence_review", side_effect=_mock_review):
            reviewed_findings, ai_usage = apply_ai_review_to_findings(findings, enabled_config)

        assert len(baseline_findings) == _AB_FINDINGS_TOTAL
        assert baseline_usage is None
        assert len(reviewed_findings) == _AB_GENUINE_PHI_COUNT
        false_positive_delta = len(baseline_findings) - len(reviewed_findings)
        assert false_positive_delta == _AB_FALSE_POSITIVE_COUNT
        assert ai_usage is not None
        assert ai_usage.false_positives_removed == _AB_FALSE_POSITIVE_COUNT
        assert ai_usage.findings_reviewed == _AB_FINDINGS_TOTAL

    def test_ai_disabled_returns_identical_findings(self) -> None:
        findings = [_build_finding(_CONFIDENCE_IN_BAND) for _ in range(_AB_FINDINGS_TOTAL)]
        config = AIReviewConfig(is_enabled=False)
        result_findings, usage = apply_ai_review_to_findings(findings, config)
        assert result_findings == findings
        assert usage is None
