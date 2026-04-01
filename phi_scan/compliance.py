"""Multi-framework compliance mapping engine (Phase 4B).

Maps PhiCategory findings to applicable regulatory controls across all supported
compliance frameworks.  HIPAA Safe Harbor is always active; other frameworks are
opt-in via the --framework CLI flag.

Design constraints:
  - ComplianceControl is frozen so instances are shared safely across findings.
  - CATEGORY_CONTROLS is a module-level constant built once at import time.
  - annotate_findings is a pure function — no I/O, no mutation.
  - parse_framework_flag raises ValueError (not typer.BadParameter) so this module
    stays framework-agnostic; the CLI layer converts the error to typer.BadParameter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from phi_scan.constants import PhiCategory

if TYPE_CHECKING:
    from phi_scan.models import ScanFinding

__all__ = [
    "ComplianceControl",
    "ComplianceFramework",
    "FrameworkMetadata",
    "InvalidFrameworkError",
    "CATEGORY_CONTROLS",
    "FRAMEWORK_METADATA",
    "IMPLEMENTED_FRAMEWORKS",
    "annotate_findings",
    "parse_framework_flag",
]

# ---------------------------------------------------------------------------
# Enums and dataclasses
# ---------------------------------------------------------------------------


class ComplianceFramework(StrEnum):
    """Supported compliance frameworks for annotation.

    Values match the tokens accepted by the --framework CLI flag (lowercase).
    HIPAA is always active; all other values are opt-in.
    """

    HIPAA = "hipaa"
    HITECH = "hitech"
    SOC2 = "soc2"
    HITRUST = "hitrust"
    NIST = "nist"
    GDPR = "gdpr"
    CFR_PART_2 = "42cfr2"
    GINA = "gina"
    CMIA = "cmia"
    BIPA = "bipa"
    SHIELD = "shield"
    MRPA = "mrpa"


# Every ComplianceFramework member is implemented; updated here when new
# frameworks are added so the CLI validation uses a single source of truth.
IMPLEMENTED_FRAMEWORKS: frozenset[ComplianceFramework] = frozenset(ComplianceFramework)


@dataclass(frozen=True)
class ComplianceControl:
    """A single compliance control applicable to a PhiCategory finding."""

    framework: ComplianceFramework
    control_id: str
    control_name: str
    citation: str


@dataclass(frozen=True)
class FrameworkMetadata:
    """Display metadata for a compliance framework (used by explain frameworks)."""

    display_name: str
    enforcement_body: str
    penalty_range: str
    description: str


class InvalidFrameworkError(ValueError):
    """Raised when an unrecognised framework token is passed to parse_framework_flag.

    Subclasses ValueError so callers that need broad compatibility can still catch
    ValueError, but _resolve_framework_flag catches this type precisely to avoid
    masking unrelated ValueErrors from future refactors.
    """


# ---------------------------------------------------------------------------
# Framework metadata (used by `phi-scan explain frameworks`)
# ---------------------------------------------------------------------------

FRAMEWORK_METADATA: Mapping[ComplianceFramework, FrameworkMetadata] = {
    ComplianceFramework.HIPAA: FrameworkMetadata(
        display_name="HIPAA",
        enforcement_body="HHS Office for Civil Rights (OCR)",
        penalty_range="$100–$50,000 per violation; $1.9M annual cap per violation category",
        description=(
            "Health Insurance Portability and Accountability Act. Governs PHI in covered "
            "entities and business associates. PhiScan implements the Safe Harbor "
            "de-identification method (45 CFR §164.514(b)(2)), which requires removing all "
            "18 named identifiers before data is considered de-identified."
        ),
    ),
    ComplianceFramework.HITECH: FrameworkMetadata(
        display_name="HITECH Act",
        enforcement_body="HHS OCR + State Attorneys General",
        penalty_range="$100–$50,000 per violation; mandatory breach notification",
        description=(
            "Health Information Technology for Economic and Clinical Health Act. Extends "
            "HIPAA with mandatory breach notification (45 CFR §§164.400–414). HIGH-confidence "
            "findings represent 'unsecured PHI' under the HITECH definition and directly "
            "trigger breach notification obligations to affected individuals, HHS, and the media."
        ),
    ),
    ComplianceFramework.SOC2: FrameworkMetadata(
        display_name="SOC 2 Type II",
        enforcement_body="AICPA (American Institute of CPAs)",
        penalty_range="Loss of certification; customer contract breach penalties",
        description=(
            "Service Organization Control 2. Trust Services Criteria CC6.x govern logical "
            "access and data protection. PHI committed to source code is a CC6.6 violation "
            "(logical access security measures). CC6.7 governs data transmission and disposal. "
            "CC6.1 requires logical and physical access controls."
        ),
    ),
    ComplianceFramework.HITRUST: FrameworkMetadata(
        display_name="HITRUST CSF v11",
        enforcement_body="HITRUST Alliance",
        penalty_range="Loss of certification; contractual penalties with covered entities",
        description=(
            "Health Information Trust Alliance Common Security Framework. Harmonises HIPAA, "
            "NIST, ISO 27001, and PCI-DSS. PHI in source code triggers 07.a (inventory of "
            "assets — PHI in source is an uncontrolled asset), 09.s (monitoring system use), "
            "01.v (information access restriction), and 09.ab (monitoring system use)."
        ),
    ),
    ComplianceFramework.NIST: FrameworkMetadata(
        display_name="NIST SP 800-53 Rev 5 / SP 800-122",
        enforcement_body="NIST (advisory); federal agencies via FISMA",
        penalty_range="Federal contract termination; FISMA non-compliance",
        description=(
            "NIST Special Publications 800-53 Rev 5 (security controls for federal systems) "
            "and 800-122 (PII confidentiality guide). SC-28 requires protection of information "
            "at rest; PM-22 governs PII quality; PT-2/PT-3 address authority and purpose for "
            "processing PII. 800-122 controls 2.1, 2.2, and 4.1 govern PII identification, "
            "minimisation, and safeguards."
        ),
    ),
    ComplianceFramework.GDPR: FrameworkMetadata(
        display_name="GDPR",
        enforcement_body="EU Data Protection Authorities (DPAs)",
        penalty_range="Up to €20M or 4% of global annual turnover (whichever is higher)",
        description=(
            "EU General Data Protection Regulation. Article 9 covers special categories "
            "(health, genetic, biometric data requiring explicit consent — highest-risk GDPR "
            "category). Article 4(15) defines health data. Article 32 requires appropriate "
            "technical measures; PHI in source code violates data protection by design "
            "(Article 25)."
        ),
    ),
    ComplianceFramework.CFR_PART_2: FrameworkMetadata(
        display_name="42 CFR Part 2",
        enforcement_body="SAMHSA + HHS",
        penalty_range="Up to $500 per violation (first offense); enhanced for repeat violations",
        description=(
            "Substance Use Disorder patient record confidentiality. Stricter than HIPAA — "
            "prohibits disclosure without explicit written patient consent even for treatment "
            "referrals. Re-disclosure is separately prohibited. Applies to SUD diagnosis codes, "
            "treatment program references, and SUD medication names."
        ),
    ),
    ComplianceFramework.GINA: FrameworkMetadata(
        display_name="GINA",
        enforcement_body="EEOC (employment); HHS OCR (health plans)",
        penalty_range="$50,000–$300,000 per violation (employment context)",
        description=(
            "Genetic Information Nondiscrimination Act. Prohibits use of genetic information "
            "in employment and health insurance. rs-IDs (dbSNP), VCF data, Ensembl gene IDs, "
            "and gene panel names map to GINA Title II and to HIPAA's genetic information "
            "provisions under 45 CFR §164.514(b)(1)."
        ),
    ),
    ComplianceFramework.CMIA: FrameworkMetadata(
        display_name="California CMIA / SB 3 / AB 825",
        enforcement_body="California DOJ; private right of action",
        penalty_range="Up to $250,000 per violation; private right of action",
        description=(
            "California Confidentiality of Medical Information Act. Stricter than HIPAA for "
            "health apps and digital health services. SB 3 / AB 825 extend protections to "
            "genomic data: genetic identifiers require explicit consent. Civil penalties up to "
            "$250,000 per violation; private right of action available."
        ),
    ),
    ComplianceFramework.BIPA: FrameworkMetadata(
        display_name="Illinois BIPA",
        enforcement_body="Illinois AG; private right of action",
        penalty_range=(
            "$1,000 per negligent violation; $5,000 per intentional violation; "
            "private right of action"
        ),
        description=(
            "Illinois Biometric Information Privacy Act. Covers fingerprints, iris scans, "
            "face geometry, voiceprints, and other biometric identifiers. Requires written "
            "notice and consent before collection. No safe-harbor provision. Statute of "
            "limitations: 5 years. Class actions are common."
        ),
    ),
    ComplianceFramework.SHIELD: FrameworkMetadata(
        display_name="New York SHIELD Act",
        enforcement_body="New York AG",
        penalty_range="Up to $5,000 per violation; up to $250,000 per incident",
        description=(
            "Stop Hacks and Improve Electronic Data Security Act. Expands New York breach "
            "notification to cover a broader definition of private information than federal "
            "HIPAA. Applies to any entity handling NY residents' data regardless of where "
            "the entity is located."
        ),
    ),
    ComplianceFramework.MRPA: FrameworkMetadata(
        display_name="Texas MRPA",
        enforcement_body="Texas AG",
        penalty_range="Up to $5,000 per violation",
        description=(
            "Texas Medical Records Privacy Act. Covers all identifiable health information "
            "including information not covered by HIPAA. Applies to healthcare facilities, "
            "physicians, and electronic health record systems operating in Texas."
        ),
    ),
}

# ---------------------------------------------------------------------------
# Control instance constants
# ---------------------------------------------------------------------------
# One module-level constant per distinct control. Shared by reference across
# all category tuples — never instantiate ComplianceControl inline below.

# HITECH ----------------------------------------------------------------

# Documentary constant only — not used in runtime logic. Extracted from the
# HITECH citation string so the regulatory threshold is named rather than a
# bare numeric literal. If severity-escalation logic based on affected-individual
# count is ever added, reference this constant rather than the literal 500.
_HITECH_BREACH_NOTIFICATION_THRESHOLD: int = 500

_HITECH_BREACH_NOTIFICATION = ComplianceControl(
    framework=ComplianceFramework.HITECH,
    control_id="45 CFR §§164.400–414",
    control_name="Breach Notification for Unsecured PHI",
    citation=(
        "HITECH Act 45 CFR §§164.400–414: findings with HIGH confidence represent "
        "'unsecured PHI' and trigger mandatory breach notification to affected individuals, "
        "HHS, and the media when "
        f"{_HITECH_BREACH_NOTIFICATION_THRESHOLD}+ individuals are affected."
    ),
)

# SOC 2 Type II ---------------------------------------------------------

_SOC2_CC6_1 = ComplianceControl(
    framework=ComplianceFramework.SOC2,
    control_id="CC6.1",
    control_name="Logical and Physical Access Controls",
    citation=(
        "SOC 2 CC6.1: logical and physical access controls must prevent unauthorised access "
        "to sensitive data. PHI committed to source code exposes data outside authorised "
        "access control boundaries."
    ),
)
_SOC2_CC6_6 = ComplianceControl(
    framework=ComplianceFramework.SOC2,
    control_id="CC6.6",
    control_name="Logical Access Security Measures",
    citation=(
        "SOC 2 CC6.6: logical access security measures must restrict access to sensitive "
        "data. PHI in source code is a direct CC6.6 violation — it exposes data to all "
        "developers with repository access."
    ),
)
_SOC2_CC6_7 = ComplianceControl(
    framework=ComplianceFramework.SOC2,
    control_id="CC6.7",
    control_name="Data Transmission and Disposal",
    citation=(
        "SOC 2 CC6.7: data transmission and disposal controls must ensure sensitive data "
        "is not retained in unauthorised locations. PHI in source code represents an "
        "unauthorised retention of sensitive data."
    ),
)

# HITRUST CSF v11 -------------------------------------------------------

_HITRUST_07A = ComplianceControl(
    framework=ComplianceFramework.HITRUST,
    control_id="07.a",
    control_name="Inventory of Assets",
    citation=(
        "HITRUST CSF v11 07.a: all information assets must be inventoried and assigned an "
        "owner. PHI found in source code represents an uncontrolled, unregistered asset "
        "that falls outside the approved asset inventory."
    ),
)
_HITRUST_09S = ComplianceControl(
    framework=ComplianceFramework.HITRUST,
    control_id="09.s",
    control_name="Monitoring System Use and Exchange of Information",
    citation=(
        "HITRUST CSF v11 09.s: organisations must monitor the use and exchange of "
        "information. PHI detected in source code indicates a monitoring gap — sensitive "
        "data was committed without detection."
    ),
)
_HITRUST_01V = ComplianceControl(
    framework=ComplianceFramework.HITRUST,
    control_id="01.v",
    control_name="Information Access Restriction",
    citation=(
        "HITRUST CSF v11 01.v: access to information must be restricted to authorised "
        "individuals. PHI in version control is accessible to all repository users, "
        "violating the principle of least privilege."
    ),
)
_HITRUST_09AB = ComplianceControl(
    framework=ComplianceFramework.HITRUST,
    control_id="09.ab",
    control_name="Monitoring System Use",
    citation=(
        "HITRUST CSF v11 09.ab: monitoring controls must detect unauthorised use of "
        "information systems. A PHI finding in source code indicates that data handling "
        "monitoring did not prevent the commit."
    ),
)

# NIST SP 800-53 Rev 5 / SP 800-122 ------------------------------------

_NIST_PROTECTION_INFORMATION_AT_REST = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="SC-28",
    control_name="Protection of Information at Rest",
    citation=(
        "NIST SP 800-53 Rev 5 SC-28: the system must protect the confidentiality and "
        "integrity of information at rest. PHI stored in source code at rest without "
        "encryption or access controls violates SC-28."
    ),
)
_NIST_SYSTEM_INTEGRITY_POLICY = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="SI-1",
    control_name="System and Information Integrity Policy",
    citation=(
        "NIST SP 800-53 Rev 5 SI-1: organisations must establish and enforce a system "
        "and information integrity policy. PHI committed to source code indicates a "
        "process failure in information integrity controls."
    ),
)
_NIST_PII_QUALITY_MANAGEMENT = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="PM-22",
    control_name="Personally Identifiable Information Quality Management",
    citation=(
        "NIST SP 800-53 Rev 5 PM-22: organisations must ensure PII/PHI quality and "
        "accuracy through documented processes. PHI in source code indicates an "
        "unmanaged data quality gap."
    ),
)
_NIST_AUTHORITY_TO_PROCESS_PII = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="PT-2",
    control_name="Authority to Process PII",
    citation=(
        "NIST SP 800-53 Rev 5 PT-2: processing of PII must be authorised by legal "
        "authority or consent. PHI in source code is processed outside authorised "
        "data flows, violating PT-2."
    ),
)
_NIST_PURPOSES_OF_PII_PROCESSING = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="PT-3",
    control_name="Purposes of PII Processing",
    citation=(
        "NIST SP 800-53 Rev 5 PT-3: purposes for processing PII must be documented and "
        "limited to the stated purpose. PHI in source code represents processing outside "
        "the documented and authorised purpose."
    ),
)
_NIST_IDENTIFY_PII = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="SP 800-122 §2.1",
    control_name="Identify PII",
    citation=(
        "NIST SP 800-122 §2.1: organisations must identify all PII held by the system. "
        "PHI detected in source code indicates a gap in PII inventory and identification."
    ),
)
_NIST_MINIMIZE_PII = ComplianceControl(
    framework=ComplianceFramework.NIST,
    control_id="SP 800-122 §2.2",
    control_name="Minimise PII",
    citation=(
        "NIST SP 800-122 §2.2: organisations must minimise PII collection and retention. "
        "PHI in source code represents unnecessary retention beyond the minimum required."
    ),
)

# GDPR ------------------------------------------------------------------

_GDPR_PERSONAL_DATA_DEFINITION = ComplianceControl(
    framework=ComplianceFramework.GDPR,
    control_id="GDPR Art. 4(1)",
    control_name="Personal Data Definition",
    citation=(
        "GDPR Article 4(1): personal data means any information relating to an identified "
        "or identifiable natural person. This finding constitutes personal data under GDPR "
        "and must be protected accordingly."
    ),
)
_GDPR_PROTECTION_BY_DESIGN = ComplianceControl(
    framework=ComplianceFramework.GDPR,
    control_id="GDPR Art. 25",
    control_name="Data Protection by Design and by Default",
    citation=(
        "GDPR Article 25: controllers must implement data protection by design and by "
        "default. Committing personal data to source code is an architectural failure "
        "of data protection by design."
    ),
)
_GDPR_SECURITY_OF_PROCESSING = ComplianceControl(
    framework=ComplianceFramework.GDPR,
    control_id="GDPR Art. 32",
    control_name="Security of Processing",
    citation=(
        "GDPR Article 32: appropriate technical measures must ensure security of personal "
        "data processing. PHI in version-controlled source code lacks the access controls "
        "and encryption required by Article 32."
    ),
)
_GDPR_HEALTH_DATA_DEFINITION = ComplianceControl(
    framework=ComplianceFramework.GDPR,
    control_id="GDPR Art. 4(15)",
    control_name="Health Data Definition",
    citation=(
        "GDPR Article 4(15): health data means personal data related to the physical or "
        "mental health of a natural person. This finding constitutes health data and is "
        "subject to the special-category protections of Article 9."
    ),
)
_GDPR_SPECIAL_CATEGORIES = ComplianceControl(
    framework=ComplianceFramework.GDPR,
    control_id="GDPR Art. 9",
    control_name="Special Categories of Personal Data",
    citation=(
        "GDPR Article 9: processing of special-category data (health, genetic, biometric) "
        "is prohibited unless explicit consent has been obtained. This finding falls within "
        "the highest-risk GDPR category and requires explicit consent to process."
    ),
)

# 42 CFR Part 2 ---------------------------------------------------------

_CFR2_PATIENT_RECORD_CONFIDENTIALITY = ComplianceControl(
    framework=ComplianceFramework.CFR_PART_2,
    control_id="42 CFR Part 2",
    control_name="SUD Patient Record Confidentiality",
    citation=(
        "42 CFR Part 2: Substance Use Disorder patient records may not be disclosed "
        "without explicit written patient consent — even for treatment referrals. This "
        "prohibition is stricter than HIPAA and includes re-disclosure restrictions. "
        "Any SUD-related data in source code constitutes an unauthorised disclosure."
    ),
)

# GINA ------------------------------------------------------------------

_GINA_TITLE_II = ComplianceControl(
    framework=ComplianceFramework.GINA,
    control_id="GINA Title II",
    control_name="Genetic Information in Employment",
    citation=(
        "GINA Title II: employers may not use genetic information in employment decisions. "
        "Genetic identifiers in source code (rs-IDs, VCF data, gene panel names) represent "
        "a genetic information handling violation under GINA."
    ),
)
_GINA_HIPAA_GENETIC = ComplianceControl(
    framework=ComplianceFramework.GINA,
    control_id="45 CFR §164.514(b)(1)",
    control_name="HIPAA Genetic Information Provisions",
    citation=(
        "HIPAA 45 CFR §164.514(b)(1): genetic information is PHI and must be removed under "
        "the Safe Harbor method. GINA aligns with this provision for health plan contexts."
    ),
)

# California CMIA -------------------------------------------------------

_CMIA_MEDICAL_INFORMATION = ComplianceControl(
    framework=ComplianceFramework.CMIA,
    control_id="Cal. Civ. Code §56.10",
    control_name="Confidentiality of Medical Information",
    citation=(
        "California CMIA §56.10: medical information may not be disclosed without written "
        "authorisation. This finding constitutes medical information under CMIA and may not "
        "be stored in source code without explicit written patient authorisation."
    ),
)
_CMIA_GENOMIC = ComplianceControl(
    framework=ComplianceFramework.CMIA,
    control_id="Cal. Civ. Code §56.181 (SB 3 / AB 825)",
    control_name="Genomic Data Protections",
    citation=(
        "California SB 3 / AB 825 (Cal. Civ. Code §56.181): genomic data requires explicit "
        "written consent for collection, use, and disclosure. Genetic identifiers in source "
        "code violate this provision."
    ),
)

# Illinois BIPA ---------------------------------------------------------

_BIPA_BIOMETRIC_COLLECTION = ComplianceControl(
    framework=ComplianceFramework.BIPA,
    control_id="740 ILCS 14/15",
    control_name="Biometric Identifier Collection and Retention",
    citation=(
        "Illinois BIPA 740 ILCS 14/15: entities may not collect or store biometric "
        "identifiers without a written release. Biometric data in source code has been "
        "collected and stored without the required written release. Private right of "
        "action applies."
    ),
)

# New York SHIELD Act ---------------------------------------------------

_SHIELD_PRIVATE_INFORMATION = ComplianceControl(
    framework=ComplianceFramework.SHIELD,
    control_id="NY Gen. Bus. Law §899-bb",
    control_name="Private Information — Reasonable Security",
    citation=(
        "NY SHIELD Act §899-bb: any person or entity that owns or licenses private "
        "information of New York residents must implement reasonable safeguards. PHI in "
        "source code fails the reasonable safeguard standard."
    ),
)

# Texas MRPA ------------------------------------------------------------

_MRPA_HEALTH_INFORMATION = ComplianceControl(
    framework=ComplianceFramework.MRPA,
    control_id="Tex. Health & Safety Code §181.001–.205",
    control_name="Identifiable Health Information",
    citation=(
        "Texas MRPA §181.001–.205: covered entities may not use or disclose protected "
        "health information without written authorisation. This finding constitutes "
        "identifiable health information under MRPA."
    ),
)

# ---------------------------------------------------------------------------
# Convenience tuples — groups of controls shared across many categories
# ---------------------------------------------------------------------------

_SOC2_ALL = (_SOC2_CC6_1, _SOC2_CC6_6, _SOC2_CC6_7)
_HITRUST_ALL = (_HITRUST_07A, _HITRUST_09S, _HITRUST_01V, _HITRUST_09AB)
_NIST_ALL = (
    _NIST_PROTECTION_INFORMATION_AT_REST,
    _NIST_SYSTEM_INTEGRITY_POLICY,
    _NIST_PII_QUALITY_MANAGEMENT,
    _NIST_AUTHORITY_TO_PROCESS_PII,
    _NIST_PURPOSES_OF_PII_PROCESSING,
    _NIST_IDENTIFY_PII,
    _NIST_MINIMIZE_PII,
)
_GDPR_BASE = (
    _GDPR_PERSONAL_DATA_DEFINITION,
    _GDPR_PROTECTION_BY_DESIGN,
    _GDPR_SECURITY_OF_PROCESSING,
)
_GDPR_HEALTH = (*_GDPR_BASE, _GDPR_HEALTH_DATA_DEFINITION, _GDPR_SPECIAL_CATEGORIES)
_GDPR_PERSONAL = _GDPR_BASE  # non-health personal data
_HITECH_ALL = (_HITECH_BREACH_NOTIFICATION,)
_CMIA_BASE = (_CMIA_MEDICAL_INFORMATION,)
_CMIA_GENOMIC_BASE = (*_CMIA_BASE, _CMIA_GENOMIC)

# Controls applied to every HIPAA Safe Harbor PHI category (non-HIPAA frameworks)
_UNIVERSAL_SECONDARY = (
    *_HITECH_ALL,
    *_SOC2_ALL,
    *_HITRUST_ALL,
    *_NIST_ALL,
)


def _hipaa(item: str, control_name: str) -> ComplianceControl:
    """Return a HIPAA Safe Harbor control for a single §164.514(b)(2)(i) item."""
    return ComplianceControl(
        framework=ComplianceFramework.HIPAA,
        control_id=f"45 CFR §164.514(b)(2)(i)({item})",
        control_name=control_name,
        citation=(
            f"HIPAA Safe Harbor §164.514(b)(2)(i)({item}): {control_name} must be removed "
            "or generalised before health information is considered de-identified under the "
            "Safe Harbor method."
        ),
    )


# ---------------------------------------------------------------------------
# Category → controls mapping
# ---------------------------------------------------------------------------
# Each entry is a tuple of ComplianceControl instances. Controls are ordered:
# HIPAA first, then HITECH, SOC2, HITRUST, NIST, GDPR, then state/special laws.
# Categories not present have no applicable controls (empty tuple by default).

CATEGORY_CONTROLS: Mapping[PhiCategory, tuple[ComplianceControl, ...]] = {
    PhiCategory.NAME: (
        _hipaa("A", "Names"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.GEOGRAPHIC: (
        _hipaa("B", "Geographic Subdivisions Smaller than State"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.DATE: (
        _hipaa("C", "Elements of Dates (Except Year) for Individuals Older Than 89"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.PHONE: (
        _hipaa("D", "Phone Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.FAX: (
        _hipaa("E", "Fax Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.EMAIL: (
        _hipaa("F", "Email Addresses"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.SSN: (
        _hipaa("G", "Social Security Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.MRN: (
        _hipaa("H", "Medical Record Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.HEALTH_PLAN: (
        _hipaa("I", "Health Plan Beneficiary Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.ACCOUNT: (
        _hipaa("J", "Account Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.CERTIFICATE: (
        _hipaa("K", "Certificate and License Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.VEHICLE: (
        _hipaa("L", "Vehicle Identifiers and Serial Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.DEVICE: (
        _hipaa("M", "Device Identifiers and Serial Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.URL: (
        _hipaa("N", "Web Universal Resource Locators (URLs)"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.IP: (
        _hipaa("O", "Internet Protocol (IP) Address Numbers"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.BIOMETRIC: (
        _hipaa("P", "Biometric Identifiers Including Finger and Voice Prints"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _GDPR_SPECIAL_CATEGORIES,  # Art. 9 explicitly covers biometric for unique identification
        _CMIA_BASE[0],
        _BIPA_BIOMETRIC_COLLECTION,
        _GINA_TITLE_II,
        _GINA_HIPAA_GENETIC,
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.PHOTO: (
        _hipaa("Q", "Full-Face Photographs and Comparable Images"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _GDPR_SPECIAL_CATEGORIES,  # biometric data derived from photographs
        _CMIA_BASE[0],
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.UNIQUE_ID: (
        _hipaa("R", "Any Other Unique Identifying Number, Characteristic, or Code"),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_PERSONAL,
        _SHIELD_PRIVATE_INFORMATION,
    ),
    PhiCategory.SUBSTANCE_USE_DISORDER: (
        _hipaa("R", "Any Other Unique Identifying Number, Characteristic, or Code"),
        _CFR2_PATIENT_RECORD_CONFIDENTIALITY,
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _MRPA_HEALTH_INFORMATION,
    ),
    PhiCategory.QUASI_IDENTIFIER_COMBINATION: (
        # No specific HIPAA Safe Harbor sub-item; cite the re-identification standard
        ComplianceControl(
            framework=ComplianceFramework.HIPAA,
            control_id="45 CFR §164.514(b)",
            control_name="Re-identification Risk — Quasi-identifier Combination",
            citation=(
                "HIPAA 45 CFR §164.514(b): information is only de-identified under Safe "
                "Harbor when ALL 18 identifiers are removed. A quasi-identifier combination "
                "(e.g., ZIP + DOB + sex) can re-identify individuals even when no single "
                "field is a named Safe Harbor identifier (Sweeney, 2000)."
            ),
        ),
        *_UNIVERSAL_SECONDARY,
        *_GDPR_HEALTH,
        _CMIA_BASE[0],
        _SHIELD_PRIVATE_INFORMATION,
        _MRPA_HEALTH_INFORMATION,
    ),
}

# Module-level integrity guard: every ComplianceFramework member must have a
# FRAMEWORK_METADATA entry. Fails loudly at import time if a new framework is
# added without updating the metadata table.
assert frozenset(FRAMEWORK_METADATA) == frozenset(ComplianceFramework), (
    "FRAMEWORK_METADATA is missing entries for: "
    f"{frozenset(ComplianceFramework) - frozenset(FRAMEWORK_METADATA)}"
)

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

# HIPAA is always included regardless of enabled_frameworks.
_HIPAA_SINGLETON: frozenset[ComplianceFramework] = frozenset({ComplianceFramework.HIPAA})


def _filter_controls_for_frameworks(
    controls: tuple[ComplianceControl, ...],
    effective: frozenset[ComplianceFramework],
) -> tuple[ComplianceControl, ...]:
    """Return only the controls whose framework is in *effective*."""
    return tuple(c for c in controls if c.framework in effective)


def annotate_findings(
    findings: tuple[ScanFinding, ...],
    enabled_frameworks: frozenset[ComplianceFramework],
) -> Mapping[int, tuple[ComplianceControl, ...]]:
    """Return per-finding compliance controls for the enabled frameworks.

    Keys are 0-based positional indices produced by enumerate() over *findings*
    — they are never PHI values, raw matched text, or value hashes.  The values
    are tuples of ComplianceControl instances whose fields contain only
    regulatory metadata (framework name, control ID, control name, citation).
    No raw PHI or ScanFinding content is stored in the returned dict.

    HIPAA controls are always included regardless of *enabled_frameworks*.
    Findings with no applicable controls for the enabled frameworks map to
    an empty tuple.

    Args:
        findings: Tuple of ScanFinding instances from a completed scan.
        enabled_frameworks: Frameworks selected by --framework; HIPAA is
            added automatically if absent.

    Returns:
        Mapping of 0-based finding index → tuple of applicable ComplianceControl.
    """
    effective = enabled_frameworks | _HIPAA_SINGLETON
    annotations: dict[int, tuple[ComplianceControl, ...]] = {}
    for idx, finding in enumerate(findings):
        all_controls = CATEGORY_CONTROLS.get(finding.hipaa_category, ())
        annotations[idx] = _filter_controls_for_frameworks(all_controls, effective)
    return annotations


def parse_framework_flag(framework_flag_value: str | None) -> frozenset[ComplianceFramework]:
    """Parse a comma-separated --framework flag value into a frozenset.

    Returns an empty frozenset when *framework_flag_value* is None or blank.
    Raises ValueError for any unrecognised framework token.  The ValueError
    message contains only framework name tokens (never PHI or scan content).

    Args:
        framework_flag_value: Comma-separated framework names, e.g. "gdpr,soc2,hitrust".

    Returns:
        frozenset of ComplianceFramework members for the requested frameworks.

    Raises:
        InvalidFrameworkError: If any token is not a valid ComplianceFramework value.
    """
    if not framework_flag_value:
        return frozenset()
    parsed: set[ComplianceFramework] = set()
    invalid: list[str] = []
    for token in (t.strip().lower() for t in framework_flag_value.split(",") if t.strip()):
        try:
            parsed.add(ComplianceFramework(token))
        except ValueError:
            invalid.append(token)
    if invalid:
        valid = ", ".join(sorted(f.value for f in ComplianceFramework))
        raise InvalidFrameworkError(
            f"Unknown framework(s): {', '.join(sorted(invalid))}. Valid values: {valid}"
        )
    return frozenset(parsed)
