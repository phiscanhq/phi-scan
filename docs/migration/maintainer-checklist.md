# Maintainer Migration Checklist — `joeyessak/*` → `phiscanhq/*`

**Companion to:** `docs/org-migration-checklist.md` (runbook),
`docs/org-migration-preflight-report.md` (pre-flight snapshot).

This document is the operational form the maintainer fills in before
initiating the transfer. Every row below must be `STATUS: DONE` with
evidence pasted inline before go / no-go approval is given in §1.6 of the
runbook.

---

## 1. PyPI 2FA confirmation

```
STATUS: DONE
```

**Required:** Confirm the account that owns the `phi-scan` project on
PyPI has 2FA enabled **and** that the 2FA device / recovery codes are
accessible to the maintainer performing the transfer.

Evidence:

```
Maintainer confirmed out-of-band on 2026-04-14 that:
— 2FA is active on the PyPI account that owns the `phi-scan` project
— 2FA device and recovery codes are accessible to the maintainer
  performing the transfer
```

Date confirmed: `2026-04-14`

---

## 2. GHCR pull + digest verification — **Deferred (post-migration hardening)**

```
STATUS: DEFERRED — out-of-scope for migration-go
```

> GHCR container publication is not required for migration-go (PyPI is
> the sole required distribution channel). This section is retained
> for the later post-migration hardening track. See
> [`docs/org-migration-status.md`](../org-migration-status.md).

**Post-migration hardening (not a migration-go gate):** pull the current
canonical container image and record the manifest digest so
post-transfer parity can be verified.

Commands to run (authenticated to ghcr.io):

```bash
docker pull ghcr.io/joeyessak/phi-scan:latest
docker inspect ghcr.io/joeyessak/phi-scan:latest \
  --format '{{index .RepoDigests 0}}'
```

Evidence to paste:

```
PASTE EVIDENCE HERE
— output of `docker inspect ... --format '{{index .RepoDigests 0}}'`
  in the form: ghcr.io/joeyessak/phi-scan@sha256:<64-hex>
```

Date confirmed: `YYYY-MM-DD`

Expected post-transfer digest match: the same image content pushed to
`ghcr.io/phiscanhq/phi-scan:<tag>` must produce the same `sha256:` digest.
Record the post-transfer digest here after §2.5 of the runbook completes.

---

## 3. Sigstore / keyless OIDC verification

```
STATUS: DONE
```

**Historical gap (recorded 2026-04-15):** `v0.5.0` (tagged 2026-04-04)
pre-dates the S11 Sigstore signing step (PR #123, merged 2026-04-11)
and has no `.sigstore.json` bundle. The gate was bound to the first
S11-signed release (≥ v0.6.0). `v0.6.0` was published to PyPI on
2026-04-15 but its GitHub Release creation failed (release-workflow
notes-escaping bug, fixed in #163); `v0.6.1` is the first release
with a complete GitHub Release + Sigstore bundles attached.

**Commands executed against v0.6.1:**

```bash
gh release download v0.6.1 --repo joeyessak/phi-scan

cosign verify-blob \
  --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v0.6.1" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle phi_scan-0.6.1-py3-none-any.whl.sigstore.json \
  phi_scan-0.6.1-py3-none-any.whl
```

**Evidence — wheel verification:**

```
Verified OK
```

```bash
cosign verify-blob \
  --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v0.6.1" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle phi_scan-0.6.1.tar.gz.sigstore.json \
  phi_scan-0.6.1.tar.gz
```

**Evidence — sdist verification:**

```
Verified OK
```

**GitHub Release assets confirmed (v0.6.1):**

```
phi_scan-0.6.1-py3-none-any.whl
phi_scan-0.6.1-py3-none-any.whl.sigstore.json
phi_scan-0.6.1.tar.gz
phi_scan-0.6.1.tar.gz.sigstore.json
sbom.cyclonedx.json
```

**OIDC subject:** `repo:joeyessak/phi-scan:…` (pre-transfer baseline).
Post-transfer bundles will verify under `repo:phiscanhq/phi-scan:…`.

**Cosign version:** v3.0.6 (linux/amd64)

**Release workflow run:** https://github.com/joeyessak/phi-scan/actions/runs/24487133619 (all 13 steps SUCCESS)

Date confirmed: `2026-04-15`

---

## 4. Roll-up

Rows §1 (PyPI 2FA) and §3 (Sigstore) must be `STATUS: DONE` before the
maintainer gives the "migration go" approval referenced in §1.6 of the
runbook. Row §2 (GHCR) is **deferred** and is not a migration-go gate.

Row §3 cleared on 2026-04-15: `v0.6.1` is the first release with a
complete GitHub Release + Sigstore bundles. Both wheel and sdist
bundles verified with `cosign verify-blob` → `Verified OK`. All
required rows (§1, §3) are now `STATUS: DONE`.

Signed off by: Joey Essak
Date: 2026-04-15
