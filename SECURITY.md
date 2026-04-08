# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in PhiScan, please report it responsibly.

**Email:** joey.essak@gmail.com (will migrate to security@phiscan.dev at first
public release)

**PGP encryption:** for sensitive reports, you may encrypt your email using our
PGP public key (will be added to this repository as `SECURITY-PGP.asc` and
published at https://phiscan.dev/.well-known/pgp-key.txt prior to first public
release).

**What to include:**

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Any potential impact assessment

**Response commitment:**

- **Acknowledgment:** within 48 hours of receipt
- **Initial assessment:** within 7 days
- **Resolution target:** within 30 days for confirmed vulnerabilities

**Disclosure timeline:**

- We follow coordinated disclosure. Please allow up to 90 days before public
  disclosure to give us time to develop and release a fix.
- Once a fix is released, we will publish a security advisory on GitHub.

## CI/CD Configuration Requirements

PhiScan's CI pipeline relies on the following configuration to maintain full PHI
detection coverage. Deviating from these requirements weakens the security posture.

### Branch protection (required)

The `main` branch must have branch protection rules enabled with:

- **Require pull request before merging** — prevents direct commits to `main` that
  bypass the diff-based PHI/PII scan
- **Require status checks to pass** — the `PHI/PII scan` check must be required
- **Do not allow bypassing the above settings** — admin bypass must be disabled

**Why this matters:** `.phi-scanignore` excludes `tests/test_*.py` via a glob
pattern. The compensating control is the diff-based PR scan (`diff_ref: origin/main`
in `ci.yml`), which scans new and modified test files before they reach `main`. A
CI enforcement step verifies that `diff_ref` remains configured. However, if an
admin can push directly to `main` bypassing branch protection, new test files
containing real PHI would reach `main` unscanned and then be silently excluded from
all future full-repo push scans. Branch protection with admin-bypass disabled is
the only mechanism that closes this gap.

### Diff-based PR scan (enforced by CI)

`ci.yml` must configure `diff_ref: origin/main` on the `Scan for PHI/PII` step for
pull request events. A dedicated CI step (`Verify compensating controls for glob
ignore rules`) fails the build if this key is removed while the test glob exclusion
remains in `.phi-scanignore`.

---

## Security Design Principles

PhiScan is designed to handle sensitive data environments. Key security properties:

- **Local execution only:** all scanning runs locally within your CI/CD pipeline
  runner. No PHI or PII is ever transmitted to an external API or third-party service.
- **No raw PHI in logs:** audit logs store SHA-256 hashes of detected values, never
  the raw values themselves.
- **Immutable audit trail:** audit log entries are append-only (INSERT only, never
  UPDATE or DELETE) per HIPAA requirements (45 CFR §164.530(j)).
- **Pinned dependencies:** all dependency versions will be pinned with a committed
  lockfile to prevent supply chain attacks.

## Scope

The following are in scope for security reports:

- PHI/PII leakage through scanner output or logs
- Audit log tampering or bypass
- Dependency vulnerabilities in pinned packages
- Unintended external network calls during scanning

The following are out of scope:

- Vulnerabilities in user-scanned codebases (that's what PhiScan detects)
- Social engineering attacks
- Denial of service against the CLI tool (as a local CLI, availability attacks
  are not a meaningful threat model)
