# Migration Go / No-Go Checklist

This is the final gate before the maintainer initiates the repo transfer
described in `docs/org-migration-checklist.md` §2. Every row must be
`GO` before proceeding.

---

## Automated gates (verifiable from the repo)

| # | Check | Status |
|---|-------|--------|
| 1 | No open PRs on `joeyessak/phi-scan` | `GO` / `NO-GO` |
| 2 | No in-flight CI runs | `GO` / `NO-GO` |
| 3 | `main` green on latest commit | `GO` / `NO-GO` |
| 4 | Release branch is parked or merged | `GO` / `NO-GO` / `N/A` |
| 5 | No P0 entries in `docs/org-migration-preflight-report.md` §2 | `GO` |
| 6 | Branch protection ruleset matches pre-flight snapshot §3.1 | `GO` / `NO-GO` |
| 7 | Actions secrets match pre-flight snapshot §3.2 | `GO` / `NO-GO` |

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
| 12 | Communication drafts reviewed (not yet published) | `GO` / `NO-GO` |
| 13 | Rollback plan reviewed by maintainer | `GO` / `NO-GO` |
| 14 | Maintainer has allocated a 4-hour transfer window plus the 48-hour observation window | `GO` / `NO-GO` |

---

## Final approval

If **every row above is `GO`**, the maintainer signs here and proceeds to
§2 of `docs/org-migration-checklist.md`.

```
I have reviewed every gate above and approve the transfer.

Name: ____________________
Date: YYYY-MM-DD
Time window opened: YYYY-MM-DD HH:MM UTC
Observation window ends: YYYY-MM-DD HH:MM UTC (48h later)
```

If **any row is `NO-GO`**, do not transfer. Resolve the blocker, rerun
this checklist, and record the second attempt.
