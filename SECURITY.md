# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in PhiScan, please report it responsibly.

**Email:** security@phiscan.dev

**PGP encryption:** for sensitive reports, you may encrypt your email using our
PGP public key (published at https://phiscan.dev/.well-known/pgp-key.txt once
the project is public).

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
- Denial of service against the CLI tool itself
