# PhiScan Feature Tiers — Community / Pro / Cloud

This document defines the feature boundary between PhiScan's three
planned product tiers. The Community tier is the open-source offering.
Pro and Cloud are future commercial tiers that fund continued
development of the project.

**Last updated:** 2026-04-16

---

## Tier Definitions

| Tier | Distribution | License | Target User |
|------|-------------|---------|-------------|
| **Community** | PyPI (`phi-scan`) | MIT | Individual developers, small teams, open-source projects |
| **Pro** | Private registry (planned) | Commercial | Security teams, mid-size organizations, regulated enterprises |
| **Cloud** | Hosted SaaS (planned) | Subscription | Multi-team organizations needing centralized visibility |

---

## Feature Boundary Matrix

### Detection and Scanning

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Regex detection (all 18 HIPAA Safe Harbor categories) | Yes | Yes | Yes |
| NLP named entity recognition (Presidio + spaCy) | Yes | Yes | Yes |
| FHIR R4 field scanning | Yes | Yes | Yes |
| HL7 v2 segment parsing (PID, NK1, IN1) | Yes | Yes | Yes |
| Parallel file scanning (`--workers N`) | Yes | Yes | Yes |
| Plugin API v1 (third-party recognizers) | Yes | Yes | Yes |
| Enterprise rule packs (PCI-DSS, FedRAMP, state-specific) | — | Yes | Yes |
| Custom AI-trained detection models | — | Yes | Yes |

### Output and Reporting

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Table, JSON, SARIF, CSV, JUnit output | Yes | Yes | Yes |
| GitLab Code Quality and SAST output | Yes | Yes | Yes |
| PDF and HTML enterprise reports | Yes | Yes | Yes |
| Compliance framework annotation (all 12 frameworks) | Yes | Yes | Yes |
| Premium report templates (branded, custom layouts) | — | Yes | Yes |
| Scheduled report generation and delivery | — | — | Yes |

### CI/CD Integration

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Pre-commit hook (`phi-scan install-hook`) | Yes | Yes | Yes |
| GitHub Actions, GitLab CI, Azure, CircleCI, Bitbucket, Jenkins, CodeBuild | Yes | Yes | Yes |
| PR comment posting and commit status reporting | Yes | Yes | Yes |
| GitHub SARIF upload | Yes | Yes | Yes |
| Priority CI platform support and debugging | — | Yes | Yes |

### Baseline and Suppression

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Baseline mode (`--baseline`, `baseline create/show/diff`) | Yes | Yes | Yes |
| Inline suppression comments (`# phi-scan:ignore`) | Yes | Yes | Yes |
| `.phi-scanignore` file-level exclusions | Yes | Yes | Yes |
| Centralized suppression policy management | — | — | Yes |

### AI Confidence Review

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Optional AI review layer (Anthropic, OpenAI, Google AI) | Yes | Yes | Yes |
| Advanced AI workflows (batch re-scoring, custom prompts) | — | Yes | Yes |
| AI-assisted auto-remediation suggestions | — | Yes | Yes |

### Audit and Compliance

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Immutable SQLite audit trail (SHA-256 hashes only) | Yes | Yes | Yes |
| Scan history and dashboard (`history`, `dashboard`) | Yes | Yes | Yes |
| HIPAA audit trail retention (6-year default) | Yes | Yes | Yes |
| Centralized audit log aggregation | — | — | Yes |
| Compliance posture dashboard (multi-repo) | — | — | Yes |

### Administration and Collaboration

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| Single-user CLI operation | Yes | Yes | Yes |
| Organization-wide policy enforcement | — | — | Yes |
| Team-based access controls and roles | — | — | Yes |
| Multi-repository scan aggregation | — | — | Yes |
| SSO / SAML integration | — | — | Yes |

### Support

| Feature | Community | Pro | Cloud |
|---------|-----------|-----|-------|
| GitHub Issues (community support) | Yes | Yes | Yes |
| Documentation and troubleshooting guides | Yes | Yes | Yes |
| Priority email support | — | Yes | Yes |
| Dedicated Slack channel | — | — | Yes |
| SLA-backed response times | — | — | Yes |

---

## Guiding Principles

1. **The core scanner stays free.** Every detection layer, output
   format, CI integration, and compliance annotation that ships in the
   Community tier today remains in the Community tier. Features are
   never moved from Community to a paid tier.

2. **Pro adds depth, not gates.** Pro features extend existing
   capabilities (enterprise rule packs, advanced AI workflows, premium
   reports) rather than restricting access to core functionality.

3. **Cloud adds breadth.** Cloud features address multi-team and
   multi-repo coordination (centralized policy, aggregated dashboards,
   SSO) that do not apply to single-user CLI operation.

4. **No telemetry in Community.** The Community tier does not phone
   home, collect usage metrics, or require account registration. This
   is a permanent guarantee, not a launch decision.

---

## What Stays Free Forever

The following capabilities are part of the Community tier and will not
be paywalled, feature-gated, or intentionally degraded in any future
release of the v1.x line:

- All 4 detection layers (regex, NLP, FHIR, HL7).
- All 18 HIPAA Safe Harbor identifier categories.
- All 9 output formats (table, JSON, SARIF, CSV, JUnit, CodeQuality,
  GitLab SAST, PDF, HTML).
- All 12 compliance framework annotations.
- Baseline mode and inline suppression.
- Immutable SQLite audit trail with HIPAA-compliant retention.
- Pre-commit hook and CI/CD platform integrations (all 7 platforms).
- Parallel file scanning.
- Plugin API v1 (third-party recognizer support).
- Optional AI confidence review layer.
- `phi-scan plugins list` command.
- `phi-scan explain` educational commands.

New capabilities introduced in future v1.x releases MAY be designated
as Pro or Cloud features at the time of their introduction. Existing
Community capabilities will never be reclassified.

---

## Version History

| Date | Change |
|------|--------|
| 2026-04-16 | Initial boundary matrix for C3/C4 scorecard checks |
