# PhiScan

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/joeyessak/phi-scan/actions/workflows/ci.yml)

HIPAA & FHIR compliant PHI/PII scanner for CI/CD pipelines. Local execution only — no PHI ever leaves your infrastructure.

---

## What it does

PhiScan scans source code for Protected Health Information (PHI) and Personally Identifiable Information (PII) before it reaches your main branch. It integrates into CI/CD pipelines to block pull requests that contain exposed PHI.

All scanning runs locally inside your pipeline runner. Nothing is sent to an external API.

---

## Install

```bash
pipx install phi-scan
```

Or with uv:

```bash
uv tool install phi-scan
```

---

## Usage

```bash
# Scan a directory
phi-scan scan ./src

# Scan only files changed in the last commit
phi-scan scan --diff HEAD~1

# Scan a single file
phi-scan scan --file path/to/handler.py

# Output as JSON
phi-scan scan ./src --output json

# Show help
phi-scan --help
```

---

## Contributing

### Branch protection rules

The `main` branch is protected. All changes arrive via pull request. No one pushes directly to `main`.

| Rule | Setting |
| ---- | ------- |
| Require CI to pass before merge | All jobs in `ci.yml` must pass (lint, typecheck, tests on all 3 platforms) |
| Require at least one review | Enforced when collaborators join the project |
| No direct pushes to `main` | Branch protection enforced via GitHub settings |

To configure these rules: **Settings → Branches → Add branch protection rule → `main`**, then enable:
- "Require a pull request before merging"
- "Require status checks to pass before merging" → select the `CI` workflow jobs
- "Do not allow bypassing the above settings"

### CI workflows

| Workflow | Trigger | What it does |
| -------- | ------- | ------------ |
| `ci.yml` | Every push and PR targeting `main` | Lint (ruff), typecheck (mypy), tests (pytest + coverage) on Python 3.12 × ubuntu/macos/windows |
| `release.yml` | Push of a `v*` tag | Runs tests, builds sdist + wheel, publishes to PyPI, creates GitHub Release |
| `claude-review.yml` | Every PR open/update | Posts an automated Claude code review comment |

---

## License

[MIT](LICENSE)
