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
STATUS: PENDING
```

**Required:** Verify the latest release's Sigstore bundle against the
current OIDC subject (`repo:joeyessak/phi-scan:…`) and capture the output.
This is the pre-transfer baseline that the post-transfer bundle will be
compared against (with the subject flipped to `repo:phiscanhq/phi-scan:…`).

Commands to run (replace `<version>` with the latest released version):

```bash
gh release download v<version> --repo joeyessak/phi-scan

cosign verify-blob \
  --cert-identity "https://github.com/joeyessak/phi-scan/.github/workflows/release.yml@refs/tags/v<version>" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle phi_scan-<version>-py3-none-any.whl.sigstore.json \
  phi_scan-<version>-py3-none-any.whl
```

Evidence to paste:

```
PASTE EVIDENCE HERE
— full `cosign verify-blob` stdout, including the "Verified OK" line
— the OIDC subject embedded in the cert
```

Date confirmed: `YYYY-MM-DD`

---

## 4. Roll-up

Rows §1 (PyPI 2FA) and §3 (Sigstore) must be `STATUS: DONE` before the
maintainer gives the "migration go" approval referenced in §1.6 of the
runbook. Row §2 (GHCR) is **deferred** and is not a migration-go gate.

Signed off by: `MAINTAINER_NAME`
Date: `YYYY-MM-DD`
