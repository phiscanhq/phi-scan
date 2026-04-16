# Org Migration Status — `joeyessak/*` → `phiscanhq/*`

**Last updated:** 2026-04-15
**Pre-flight evidence date:** 2026-04-18 (per [`docs/org-migration-preflight-report.md`](org-migration-preflight-report.md); evidence remains valid — refresh before transfer per runbook Appendix A)
**Purpose:** Single operational source of truth for migration-go readiness.
**Runbook:** [`docs/org-migration-checklist.md`](org-migration-checklist.md)
**Pre-flight snapshot:** [`docs/org-migration-preflight-report.md`](org-migration-preflight-report.md)
**Final gate form:** [`docs/migration/go-no-go.md`](migration/go-no-go.md)
**Maintainer evidence form:** [`docs/migration/maintainer-checklist.md`](migration/maintainer-checklist.md)
**Tracking issue:** [`joeyessak/phi-scan#158`](https://github.com/joeyessak/phi-scan/issues/158)
**Comms drafts (not published):** [`docs/migration/communication-draft.md`](migration/communication-draft.md)
**Tracking-issue template:** [`docs/migration/ticket-template.md`](migration/ticket-template.md)
**Post-transfer canonical patch pack (draft):** [`docs/migration/post-transfer-patch-pack.md`](migration/post-transfer-patch-pack.md)

No transfer action has been taken. No repo config has been changed.

---

## Scope decision — GHCR deferred

PyPI is the only required distribution channel for migration-go. GHCR
container publication is deferred to a post-migration hardening track
and is **not a transfer blocker**. All GHCR-related gates in the
checklist, pre-flight report, go/no-go form, maintainer checklist,
ticket template, and communication drafts have been reclassified as
**DEFERRED** in this PR.

CI workflow files are intentionally unchanged in this PR. Any container
publish steps that currently reference `ghcr.io/joeyessak/phi-scan`
remain operational and will be addressed in a later post-migration
hardening PR.

---

## Classification table

Every migration-go readiness item, classified so the maintainer can
execute from one page.

| # | Item | Classification | Evidence / Unblock command |
|---|------|----------------|-----------------------------|
| 1 | Repo clean (no open PRs, no in-flight runs, `main` green) | **done-with-evidence** | Pre-flight §1 (verified 2026-04-18) |
| 2 | Hardcoded-reference sweep with plan | **done-with-evidence** | Pre-flight §2 (0 P0, 15 P1 hunks, 5 P2 entries) |
| 3 | Branch-protection ruleset captured | **done-with-evidence** | Pre-flight §3.1 (ruleset `14041817` `Protect main`) |
| 4 | Actions secrets enumerated | **done-with-evidence** | Pre-flight §3.2 (`ANTHROPIC_API_KEY`, `PYPI_API_TOKEN`) |
| 5 | Variables / environments / webhooks | **done-with-evidence** | Pre-flight §3.3–3.5 (all empty) |
| 6 | Collaborators / teams / `CODEOWNERS` | **done-with-evidence** | Pre-flight §3.6 (solo admin, no `CODEOWNERS`) |
| 7 | PyPI 2FA confirmed | **done-with-evidence** | Maintainer confirmed 2026-04-14; see `docs/migration/maintainer-checklist.md §1` |
| 8 | GHCR pull + digest recorded | **de-scoped** | See "Scope decision — GHCR deferred" above |
| 9 | Sigstore bundle verifies under current subject | **pending-until-signed-release** | Bound to first S11-signed release (≥ v0.6.0); `v0.5.0` pre-dates S11 (PR #123, 2026-04-11) and has no `.sigstore.json` asset. Command pack retained in `docs/migration/maintainer-checklist.md §3`. |
| 10 | Draft migration notice prepared | **done-with-evidence** | [`docs/migration/communication-draft.md §1`](migration/communication-draft.md) |
| 11 | Draft release-notes entry prepared | **done-with-evidence** | [`docs/migration/communication-draft.md §2`](migration/communication-draft.md) |
| 12 | Migration ticket opened | **done-with-evidence** | [`joeyessak/phi-scan#158`](https://github.com/joeyessak/phi-scan/issues/158) — opened 2026-04-14 from `docs/migration/ticket-template.md` |
| 13 | Maintainer "migration go" approval | **pending-with-command** | Sign off on [`docs/migration/go-no-go.md`](migration/go-no-go.md) after rows 1–12 are GO |

---

## Migration-go blockers remaining

Only two items stand between current state and executable migration-go:

1. **Sigstore verification** — bound to the **first S11-signed release
   (≥ v0.6.0)**. The latest release `v0.5.0` was tagged 2026-04-04,
   before the S11 Sigstore signing step was merged to
   `.github/workflows/release.yml` in PR #123 on 2026-04-11, so no
   `.sigstore.json` bundle exists for `v0.5.0`. Once a release ≥ v0.6.0
   is cut, the maintainer runs the command pack in
   `docs/migration/maintainer-checklist.md §3` and pastes the
   `Verified OK` stdout into that section. Publishing v0.6.0 is a
   separate go/no-go decision outside this status doc.
2. **Maintainer go approval** — sign off on `docs/migration/go-no-go.md`
   once every other gate reads `GO`.

Cleared since last status:
- PyPI 2FA confirmed by maintainer 2026-04-14 (row 7).
- Migration tracking issue opened (row 12); see link below.
- Sigstore gate language tightened 2026-04-15: rebound row 9 to the
  first S11-signed release (≥ v0.6.0) after confirming `v0.5.0` carries
  no Sigstore bundle.

No other gate requires action. No repo config, workflow, or code change
is needed before migration-go.

---

## What changes after migration-go

Execution order is frozen in `docs/org-migration-checklist.md` §2–§5.
This status doc is updated after each phase boundary:

1. After §2.7 passes — mark `phi-scan` transfer complete; append digest
   evidence if available.
2. After §3 completes — mark `phi-scan-action` transfer complete.
3. After the 48-hour observation window closes — close out this status
   doc and link to the post-mortem note on the migration ticket.

---

## Not in PR 1

The following are intentionally out of scope for the status-closure PR:

- CI workflow edits (including any `ghcr.io/joeyessak/phi-scan` references).
- Relocation of drafts out of `docs/migration/communication-draft.md`.
- Any transfer action or URL flip.
- Any content change to the drafts themselves beyond softening the
  container-image language consistent with the GHCR deferral.
