# PhiScan

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)

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

## License

[MIT](LICENSE)
