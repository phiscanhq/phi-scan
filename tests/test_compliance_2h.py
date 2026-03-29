"""Phase 2H compliance scope and known-limitations tests.

Verifies:
  2H.1b — HITECH Act, 42 CFR Part 2, GINA, and Expert Determination are
           referenced in the phi-scan explain hipaa output.
  2H.1c — SUD field names are detected and mapped to
           PhiCategory.SUBSTANCE_USE_DISORDER (distinct from UNIQUE_ID).
  2H.1d — GINA is mentioned in help text (genetic identifiers covered).
  2H.1e — NIST SP 800-122 is mentioned in help text.
  2H.2  — docs/known-limitations.md and docs/de-identification.md exist
           and document each required gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from phi_scan.constants import (
    SUD_FIELD_NAME_PATTERNS,
    PhiCategory,
)
from phi_scan.detection_coordinator import detect_phi_in_text_content
from phi_scan.help_text import EXPLAIN_HIPAA_TEXT

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_DOCS_ROOT: Path = Path(__file__).parent.parent / "docs"
_DE_ID_DOC_PATH: Path = _DOCS_ROOT / "de-identification.md"
_KNOWN_LIMITS_DOC_PATH: Path = _DOCS_ROOT / "known-limitations.md"

# ---------------------------------------------------------------------------
# Help-text keyword constants (no magic strings in logic code)
# ---------------------------------------------------------------------------

_HITECH_KEYWORD: str = "HITECH"
_BUSINESS_ASSOCIATE_KEYWORD: str = "business associate"
_BREACH_NOTIFICATION_KEYWORD: str = "breach notification"
_CFR_PART_2_KEYWORD: str = "42 CFR Part 2"
_GINA_KEYWORD: str = "GINA"
_NIST_KEYWORD: str = "NIST SP 800-122"
_EXPERT_DETERMINATION_KEYWORD: str = "Expert Determination"

# ---------------------------------------------------------------------------
# SUD detection constants
# ---------------------------------------------------------------------------

# Subset required by PLAN.md 2H.1c spec — must be present in the constant.
_PLAN_REQUIRED_SUD_PATTERNS: frozenset[str] = frozenset(
    {
        "substance_use",
        "addiction_treatment",
        "sud_diagnosis",
        "alcohol_abuse",
        "opioid_treatment",
        "methadone",
        "buprenorphine",
        "naloxone",
    }
)

# Template for generating a Python assignment containing a SUD field name.
# Follows the pattern: <field_name> = "<field_name>_record"
_SUD_ASSIGNMENT_SUFFIX: str = "_record"
_SUD_ASSIGNMENT_TEMPLATE: str = '{field_name} = "{field_name}{suffix}"\n'

# ---------------------------------------------------------------------------
# Doc content keyword constants (2H.2)
# ---------------------------------------------------------------------------

_DOC_PDF_KEYWORD: str = "PDF"
_DOC_DICOM_KEYWORD: str = "DICOM"
_DOC_OFFICE_KEYWORD: str = "docx"
_DOC_COMPILED_KEYWORD: str = "Compiled"
_DOC_EXPERT_DET_KEYWORD: str = "Expert Determination"
_DOC_SAFE_HARBOR_KEYWORD: str = "Safe Harbor"
_DOC_HITECH_KEYWORD: str = "HITECH"

# ---------------------------------------------------------------------------
# 2H.1b — HITECH Act in explain hipaa
# ---------------------------------------------------------------------------


def test_explain_hipaa_text_mentions_hitech_act() -> None:
    """EXPLAIN_HIPAA_TEXT references the HITECH Act by name."""
    assert _HITECH_KEYWORD in EXPLAIN_HIPAA_TEXT


def test_explain_hipaa_text_mentions_business_associates() -> None:
    """EXPLAIN_HIPAA_TEXT states that HITECH extended obligations to business associates."""
    assert _BUSINESS_ASSOCIATE_KEYWORD in EXPLAIN_HIPAA_TEXT


def test_explain_hipaa_text_mentions_breach_notification() -> None:
    """EXPLAIN_HIPAA_TEXT references breach notification thresholds."""
    assert _BREACH_NOTIFICATION_KEYWORD in EXPLAIN_HIPAA_TEXT


def test_explain_hipaa_text_mentions_42_cfr_part_2() -> None:
    """EXPLAIN_HIPAA_TEXT references 42 CFR Part 2 for SUD records."""
    assert _CFR_PART_2_KEYWORD in EXPLAIN_HIPAA_TEXT


# ---------------------------------------------------------------------------
# 2H.1d — GINA in explain hipaa
# ---------------------------------------------------------------------------


def test_explain_hipaa_text_mentions_gina() -> None:
    """EXPLAIN_HIPAA_TEXT references GINA for genetic identifier coverage."""
    assert _GINA_KEYWORD in EXPLAIN_HIPAA_TEXT


# ---------------------------------------------------------------------------
# 2H.1e — NIST SP 800-122 in explain hipaa
# ---------------------------------------------------------------------------


def test_explain_hipaa_text_mentions_nist_sp_800_122() -> None:
    """EXPLAIN_HIPAA_TEXT references NIST SP 800-122 for PII alignment."""
    assert _NIST_KEYWORD in EXPLAIN_HIPAA_TEXT


# ---------------------------------------------------------------------------
# 2H.1a — Expert Determination limitation in explain hipaa
# ---------------------------------------------------------------------------


def test_explain_hipaa_text_mentions_expert_determination_limitation() -> None:
    """EXPLAIN_HIPAA_TEXT states that Expert Determination requires a statistician."""
    assert _EXPERT_DETERMINATION_KEYWORD in EXPLAIN_HIPAA_TEXT


# ---------------------------------------------------------------------------
# 2H.1c — SUD field name detection
# ---------------------------------------------------------------------------


def test_all_plan_required_sud_patterns_present_in_constant() -> None:
    """All PLAN.md 2H.1c required SUD patterns are in SUD_FIELD_NAME_PATTERNS."""
    missing = _PLAN_REQUIRED_SUD_PATTERNS - SUD_FIELD_NAME_PATTERNS

    assert missing == frozenset(), f"Required SUD patterns missing from constant: {sorted(missing)}"


def test_substance_use_disorder_is_distinct_from_unique_id() -> None:
    """PhiCategory.SUBSTANCE_USE_DISORDER is a different enum member from UNIQUE_ID.

    PLAN.md 2H.1c explicitly prohibits reusing UNIQUE_ID for SUD records — the
    two categories fall under different statutes with different consent requirements.
    """
    assert PhiCategory.SUBSTANCE_USE_DISORDER is not PhiCategory.UNIQUE_ID
    assert PhiCategory.SUBSTANCE_USE_DISORDER.value != PhiCategory.UNIQUE_ID.value


@pytest.mark.parametrize("field_name", sorted(SUD_FIELD_NAME_PATTERNS))
def test_sud_field_name_produces_finding(field_name: str) -> None:
    """Each SUD field name in SUD_FIELD_NAME_PATTERNS produces at least one finding."""
    source_line = _SUD_ASSIGNMENT_TEMPLATE.format(
        field_name=field_name,
        suffix=_SUD_ASSIGNMENT_SUFFIX,
    )
    findings = detect_phi_in_text_content(source_line, Path("module.py"))

    assert len(findings) >= 1, f"No finding produced for SUD field name {field_name!r}"


@pytest.mark.parametrize("field_name", sorted(SUD_FIELD_NAME_PATTERNS))
def test_sud_finding_maps_to_substance_use_disorder_category(field_name: str) -> None:
    """SUD field name findings are categorised as SUBSTANCE_USE_DISORDER."""
    source_line = _SUD_ASSIGNMENT_TEMPLATE.format(
        field_name=field_name,
        suffix=_SUD_ASSIGNMENT_SUFFIX,
    )
    findings = detect_phi_in_text_content(source_line, Path("module.py"))

    sud_findings = [f for f in findings if f.hipaa_category == PhiCategory.SUBSTANCE_USE_DISORDER]
    assert len(sud_findings) >= 1, (
        f"No SUBSTANCE_USE_DISORDER finding for SUD field name {field_name!r}"
    )


# ---------------------------------------------------------------------------
# 2H.2 — Documentation: docs/de-identification.md
# ---------------------------------------------------------------------------


def test_de_identification_doc_exists() -> None:
    """docs/de-identification.md exists at the project root."""
    assert _DE_ID_DOC_PATH.is_file(), f"Missing required documentation file: {_DE_ID_DOC_PATH}"


def test_de_identification_doc_mentions_safe_harbor() -> None:
    """docs/de-identification.md references HIPAA Safe Harbor."""
    doc_text = _DE_ID_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_SAFE_HARBOR_KEYWORD in doc_text


def test_de_identification_doc_mentions_expert_determination() -> None:
    """docs/de-identification.md documents the Expert Determination limitation."""
    doc_text = _DE_ID_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_EXPERT_DET_KEYWORD in doc_text


def test_de_identification_doc_mentions_hitech() -> None:
    """docs/de-identification.md documents the HITECH Act scope."""
    doc_text = _DE_ID_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_HITECH_KEYWORD in doc_text


# ---------------------------------------------------------------------------
# 2H.2 — Documentation: docs/known-limitations.md
# ---------------------------------------------------------------------------


def test_known_limitations_doc_exists() -> None:
    """docs/known-limitations.md exists at the project root."""
    assert _KNOWN_LIMITS_DOC_PATH.is_file(), (
        f"Missing required documentation file: {_KNOWN_LIMITS_DOC_PATH}"
    )


def test_known_limitations_doc_mentions_pdf() -> None:
    """docs/known-limitations.md documents the PDF scanning gap (2H.2a)."""
    doc_text = _KNOWN_LIMITS_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_PDF_KEYWORD in doc_text


def test_known_limitations_doc_mentions_dicom() -> None:
    """docs/known-limitations.md documents the DICOM scanning gap (2H.2b)."""
    doc_text = _KNOWN_LIMITS_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_DICOM_KEYWORD in doc_text


def test_known_limitations_doc_mentions_office_documents() -> None:
    """docs/known-limitations.md documents the Office document scanning gap (2H.2c)."""
    doc_text = _KNOWN_LIMITS_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_OFFICE_KEYWORD in doc_text


def test_known_limitations_doc_mentions_compiled_code() -> None:
    """docs/known-limitations.md documents the compiled code scope boundary (2H.2d)."""
    doc_text = _KNOWN_LIMITS_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_COMPILED_KEYWORD in doc_text


def test_known_limitations_doc_mentions_expert_determination() -> None:
    """docs/known-limitations.md documents the Expert Determination limitation."""
    doc_text = _KNOWN_LIMITS_DOC_PATH.read_text(encoding="utf-8")

    assert _DOC_EXPERT_DET_KEYWORD in doc_text
