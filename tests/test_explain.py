# phi-scan:ignore-file
"""Tests for the explain command group — all 9 topics render without error.

Each explain sub-command must:
  - Exit with code 0 (EXIT_CODE_CLEAN).
  - Produce non-empty output.
  - Contain at least one expected keyword that confirms the correct topic rendered.

The 9 topics: confidence, severity, risk-levels, hipaa, detection, config, ignore,
reports, remediation.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner  # phi-scan:ignore

from phi_scan.cli import app
from phi_scan.constants import EXIT_CODE_CLEAN

# ---------------------------------------------------------------------------
# Test constants — no magic values
# ---------------------------------------------------------------------------

# (topic_name, expected_keyword_in_output)
# Keywords are stable identifiers from each topic's help text that are unlikely
# to change between versions. Each keyword is chosen to be topic-specific so
# that rendering the wrong topic would not satisfy the assertion.
_EXPLAIN_TOPIC_KEYWORDS: list[tuple[str, str]] = [
    ("confidence", "confidence"),
    ("severity", "severity"),
    ("risk-levels", "risk"),
    ("hipaa", "hipaa"),
    ("detection", "detection"),
    ("config", "phi-scanner"),
    ("ignore", "ignore"),
    ("reports", "sarif"),
    ("remediation", "remediation"),
]

_EXPLAIN_TOPIC_NAMES: list[str] = [topic for topic, _ in _EXPLAIN_TOPIC_KEYWORDS]


# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------

_runner = CliRunner()


# ---------------------------------------------------------------------------
# Each topic exits cleanly
# ---------------------------------------------------------------------------


class TestExplainTopicsExitCleanly:
    @pytest.mark.parametrize("topic", _EXPLAIN_TOPIC_NAMES)
    def test_explain_topic_exits_with_code_zero(self, topic: str) -> None:
        result = _runner.invoke(app, ["explain", topic])

        assert result.exit_code == EXIT_CODE_CLEAN, (
            f"explain {topic!r} exited {result.exit_code} — output: {result.output[:200]!r}"
        )


# ---------------------------------------------------------------------------
# Each topic produces non-empty output
# ---------------------------------------------------------------------------


class TestExplainTopicsProduceOutput:
    @pytest.mark.parametrize("topic", _EXPLAIN_TOPIC_NAMES)
    def test_explain_topic_produces_non_empty_output(self, topic: str) -> None:
        result = _runner.invoke(app, ["explain", topic])

        assert result.output.strip() != "", f"explain {topic!r} produced empty output"


# ---------------------------------------------------------------------------
# Each topic contains expected keyword
# ---------------------------------------------------------------------------


class TestExplainTopicsContainExpectedContent:
    @pytest.mark.parametrize("topic,expected_keyword", _EXPLAIN_TOPIC_KEYWORDS)
    def test_explain_topic_output_contains_expected_keyword(
        self, topic: str, expected_keyword: str
    ) -> None:
        result = _runner.invoke(app, ["explain", topic])

        assert expected_keyword.lower() in result.output.lower(), (
            f"explain {topic!r} output does not contain expected keyword {expected_keyword!r}"
        )


# ---------------------------------------------------------------------------
# explain --help exits cleanly
# ---------------------------------------------------------------------------


def test_explain_help_exits_cleanly() -> None:
    result = _runner.invoke(app, ["explain", "--help"])

    assert result.exit_code == EXIT_CODE_CLEAN


# ---------------------------------------------------------------------------
# All 9 topics are discoverable via explain --help
# ---------------------------------------------------------------------------


def test_explain_help_lists_all_nine_topics() -> None:
    result = _runner.invoke(app, ["explain", "--help"])

    # All topic names must appear somewhere in the help text.
    for topic in _EXPLAIN_TOPIC_NAMES:
        assert topic in result.output, f"explain --help does not list topic {topic!r}"
