"""Explain command group — phi-scan explain <topic>."""

from __future__ import annotations

import typer

from phi_scan.help_text import (
    EXPLAIN_CONFIDENCE_TEXT,
    EXPLAIN_CONFIG_TEXT,
    EXPLAIN_DEIDENTIFICATION_TEXT,
    EXPLAIN_DETECTION_TEXT,
    EXPLAIN_FRAMEWORKS_TEXT,
    EXPLAIN_HIPAA_TEXT,
    EXPLAIN_IGNORE_TEXT,
    EXPLAIN_REMEDIATION_TEXT,
    EXPLAIN_REPORTS_TEXT,
    EXPLAIN_RISK_LEVELS_TEXT,
    EXPLAIN_SEVERITY_TEXT,
)
from phi_scan.output import get_console

explain_app = typer.Typer(name="explain", help="Explain PhiScan concepts and configuration.")


def _render_explain_topic(topic_markup: str) -> None:
    """Render a help_text constant to the terminal with Rich markup."""
    get_console().print(topic_markup)


@explain_app.command("confidence")
def explain_confidence() -> None:
    """Explain confidence scores: what they mean and how the threshold works."""
    _render_explain_topic(EXPLAIN_CONFIDENCE_TEXT)


@explain_app.command("severity")
def explain_severity() -> None:
    """Explain HIGH / MEDIUM / LOW / INFO severity levels and the threshold."""
    _render_explain_topic(EXPLAIN_SEVERITY_TEXT)


@explain_app.command("risk-levels")
def explain_risk_levels() -> None:
    """Explain CRITICAL / HIGH / MODERATE / LOW / CLEAN risk assessment."""
    _render_explain_topic(EXPLAIN_RISK_LEVELS_TEXT)


@explain_app.command("hipaa")
def explain_hipaa() -> None:
    """List all 18 HIPAA Safe Harbor identifier categories with descriptions."""
    _render_explain_topic(EXPLAIN_HIPAA_TEXT)


@explain_app.command("detection")
def explain_detection() -> None:
    """Describe how the four detection layers work together."""
    _render_explain_topic(EXPLAIN_DETECTION_TEXT)


@explain_app.command("config")
def explain_config() -> None:
    """Show an annotated .phi-scanner.yml with every option explained."""
    _render_explain_topic(EXPLAIN_CONFIG_TEXT)


@explain_app.command("ignore")
def explain_ignore() -> None:
    """Explain .phi-scanignore patterns and inline suppression directives."""
    _render_explain_topic(EXPLAIN_IGNORE_TEXT)


@explain_app.command("reports")
def explain_reports() -> None:
    """List available output formats and when to use each."""
    _render_explain_topic(EXPLAIN_REPORTS_TEXT)


@explain_app.command("remediation")
def explain_remediation() -> None:
    """Show the full remediation playbook for all 18 HIPAA categories."""
    _render_explain_topic(EXPLAIN_REMEDIATION_TEXT)


@explain_app.command("frameworks")
def explain_frameworks() -> None:
    """List all supported compliance frameworks with citations and penalty ranges."""
    _render_explain_topic(EXPLAIN_FRAMEWORKS_TEXT)


@explain_app.command("deidentification")
def explain_deidentification() -> None:
    """Explain HIPAA Safe Harbor vs Expert Determination and known detection gaps."""
    _render_explain_topic(EXPLAIN_DEIDENTIFICATION_TEXT)
