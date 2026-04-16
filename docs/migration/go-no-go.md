# Migration Go / No-Go Checklist

This is the final gate before the maintainer initiates the repo transfer
described in `docs/org-migration-checklist.md` §2. Every row must be
`GO` before proceeding.

---

## Automated gates (verifiable from the repo)

| # | Check | Status |
|---|-------|--------|
| 1 | No open PRs on `joeyessak/phi-scan` | `GO` (verified 2026-04-15) |
| 2 | No in-flight CI runs | `GO` (verified 2026-04-15) |
| 3 | `main` green on latest commit | `GO` (`cdc64b2`, all 5 check-runs SUCCESS, 2026-04-15) |
| 4 | Release branch is parked or merged | `N/A` (no release branches) |
| 5 | No P0 entries in `docs/org-migration-preflight-report.md` §2 | `GO` |
| 6 | Branch protection ruleset matches pre-flight snapshot §3.1 | `GO` (unchanged since pre-flight §3.1) |
| 7 | Actions secrets match pre-flight snapshot §3.2 | `GO` (unchanged since pre-flight §3.2) |

## Maintainer-run gates (human evidence required)

| # | Check | Status | Evidence link |
|---|-------|--------|---------------|
| 8 | PyPI 2FA confirmed | `GO` (confirmed 2026-04-14) | `docs/migration/maintainer-checklist.md#1-pypi-2fa-confirmation` |
| 9 | ~~GHCR pull + digest recorded~~ | **`N/A — DEFERRED`** | Out-of-scope for migration-go; see [`docs/org-migration-status.md`](../org-migration-status.md) |
| 10 | Sigstore bundle verifies under current subject | `GO` (v0.6.1, verified 2026-04-15) | Both wheel + sdist bundles `Verified OK` via `cosign verify-blob`. See `docs/migration/maintainer-checklist.md#3-sigstore--keyless-oidc-verification`. |

## Operational gates

| # | Check | Status |
|---|-------|--------|
| 11 | Migration ticket is open and linked to runbook + pre-flight | `GO` ([#158](https://github.com/joeyessak/phi-scan/issues/158), opened 2026-04-14) |
| 12 | Communication drafts reviewed (not yet published) | `GO` (reviewed 2026-04-15; [`docs/migration/communication-draft.md`](communication-draft.md)) |
| 13 | Rollback plan reviewed by maintainer | `GO` (reviewed 2026-04-15; [`docs/org-migration-checklist.md §5`](../org-migration-checklist.md)) |
| 14 | Maintainer has allocated a 4-hour transfer window plus the 48-hour observation window | `GO` (window TBD — maintainer sets times at transfer execution) |

---

## Final approval

If **every row above is `GO`**, the maintainer signs here and proceeds to
§2 of `docs/org-migration-checklist.md`.

```
I have reviewed every gate above and approve the transfer.

Name: Joey Essak
Date: 2026-04-15
Time window opened: ____-__-__ __:__ UTC  (set at transfer execution)
Observation window ends: ____-__-__ __:__ UTC  (48h after above)
```

If **any row is `NO-GO`**, do not transfer. Resolve the blocker, rerun
this checklist, and record the second attempt.
