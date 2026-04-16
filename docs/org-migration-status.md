# Org Migration Status — `joeyessak/*` → `phiscanhq/*`

**Last updated:** 2026-04-16
**Pre-flight evidence date:** 2026-04-18 (per [`docs/org-migration-preflight-report.md`](org-migration-preflight-report.md))
**Purpose:** Single operational source of truth for migration status.
**Runbook:** [`docs/org-migration-checklist.md`](org-migration-checklist.md)
**Pre-flight snapshot:** [`docs/org-migration-preflight-report.md`](org-migration-preflight-report.md)
**Final gate form:** [`docs/migration/go-no-go.md`](migration/go-no-go.md)
**Maintainer evidence form:** [`docs/migration/maintainer-checklist.md`](migration/maintainer-checklist.md)
**Tracking issue:** [`phiscanhq/phi-scan#158`](https://github.com/phiscanhq/phi-scan/issues/158)
**Comms drafts (not published):** [`docs/migration/communication-draft.md`](migration/communication-draft.md)
**Tracking-issue template:** [`docs/migration/ticket-template.md`](migration/ticket-template.md)
**Post-transfer canonical patch pack:** [`docs/migration/post-transfer-patch-pack.md`](migration/post-transfer-patch-pack.md)

**Transfer executed 2026-04-16.** Both repositories now live under `phiscanhq/*`.
48-hour observation window: 2026-04-16 → 2026-04-18.

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
| 9 | Sigstore bundle verifies under current subject | **done-with-evidence** | `v0.6.1` wheel + sdist bundles verified 2026-04-15 via `cosign verify-blob` → `Verified OK`. Evidence in `docs/migration/maintainer-checklist.md §3`. |
| 10 | Draft migration notice prepared | **done-with-evidence** | [`docs/migration/communication-draft.md §1`](migration/communication-draft.md) |
| 11 | Draft release-notes entry prepared | **done-with-evidence** | [`docs/migration/communication-draft.md §2`](migration/communication-draft.md) |
| 12 | Migration ticket opened | **done-with-evidence** | [`joeyessak/phi-scan#158`](https://github.com/joeyessak/phi-scan/issues/158) — opened 2026-04-14 from `docs/migration/ticket-template.md` |
| 13 | Maintainer "migration go" approval | **done-with-evidence** | Signed off on [`docs/migration/go-no-go.md`](migration/go-no-go.md) 2026-04-15 — all gates GO |

---

## Transfer execution log

**Transfer executed 2026-04-16** by maintainer instruction.

| Step | Action | Evidence |
|------|--------|----------|
| §2.1 | `joeyessak/phi-scan` → `phiscanhq/phi-scan` | `gh api repos/phiscanhq/phi-scan` confirms `full_name: phiscanhq/phi-scan` |
| §2.2 | Ruleset + secrets verified intact | Ruleset `Protect main` present; `ANTHROPIC_API_KEY` + `PYPI_API_TOKEN` confirmed |
| §2.6 | Post-transfer patch pack applied | PR #166 merged (`bd5687f`) — 11 files, 31 ins / 26 del |
| §2.7 | End-to-end validation | `pip install phi-scan==0.6.1` → OK; `phi-scan --version` → `0.6.1`; `joeyessak/phi-scan` 301 → `phiscanhq/phi-scan`; ruleset intact |
| §3   | `joeyessak/phi-scan-action` → `phiscanhq/phi-scan-action` | `gh api repos/phiscanhq/phi-scan-action` confirms transfer |
| §4   | 48-hour observation window started | 2026-04-16 → 2026-04-18 |

### Old URL redirect

`https://github.com/joeyessak/phi-scan` returns HTTP 301 →
`https://github.com/phiscanhq/phi-scan`. GitHub redirect is active.

---

## What remains

1. **48-hour observation window** (2026-04-16 → 2026-04-18): monitor
   PyPI installs, GitHub redirect, CI runs, and pre-commit fetches.
2. **Close observation window**: update this doc and close tracking
   issue #158 with post-transfer evidence.
3. **PyPI token rotation** (optional hardening): generate new token
   scoped to `phiscanhq` org, rotate old `joeyessak`-scoped token.
4. **GHCR** remains deferred — not a transfer blocker.
