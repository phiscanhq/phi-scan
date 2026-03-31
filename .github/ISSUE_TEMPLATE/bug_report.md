---
name: Bug report
about: Report a reproducible problem with PhiScan
title: '[Bug] '
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to reproduce

1. Install PhiScan with `pipx install phi-scan`
2. Run `phi-scan scan ...`
3. See error

## Expected behaviour

What you expected to happen.

## Actual behaviour

What actually happened. Include the full error output.

## Environment

```
phi-scan --version:
python --version:
OS:
Install method (pipx / uv / pip):
Optional extras installed (nlp / fhir / hl7 / none):
```

## Configuration

Paste the relevant sections of your `.phi-scanner.yml` if applicable:

```yaml

```

## Debug log

Run with `--log-level debug` and paste the output (redact any sensitive paths):

```
phi-scan --log-level debug scan . 2>&1 | head -100
```

## Additional context

Add any other context about the problem here.
