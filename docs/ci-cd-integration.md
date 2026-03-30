# CI/CD Integration

PhiScan supports two git hook integration methods: the **pre-commit framework**
(recommended for teams) and a **native git hook** (recommended for individuals
or environments where pre-commit is not available).

Both methods run phi-scan locally inside the pipeline runner or developer
machine. No PHI or PII is transmitted to any external service.

---

## Method 1 — Pre-commit Framework (Recommended)

The [pre-commit framework](https://pre-commit.com) manages git hooks as
versioned, reproducible configuration. It is the standard approach for team
repositories.

### Prerequisites

```bash
pip install pre-commit
# or
brew install pre-commit
```

### Installation

Create or edit `.pre-commit-config.yaml` in your repository root:

```yaml
repos:
  - repo: https://github.com/joeyessak/phi-scan
    rev: v0.1.0
    hooks:
      - id: phi-scan
```

Then install the hooks:

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

### Running Manually

```bash
# Scan all files tracked by git
pre-commit run phi-scan --all-files

# Scan specific files
pre-commit run phi-scan --files src/api/patient.py tests/fixtures/records.json
```

### Configuration Options

All `phi-scan scan` flags can be passed via `args` in your
`.pre-commit-config.yaml`. These are appended to the hook's built-in
`phi-scan scan --diff HEAD` entry.

#### Set a minimum severity threshold

Only report findings at `medium` severity or above:

```yaml
repos:
  - repo: https://github.com/joeyessak/phi-scan
    rev: v0.1.0
    hooks:
      - id: phi-scan
        args: ['--severity-threshold', 'medium']
```

Accepted values: `info`, `low`, `medium`, `high`.

#### Use baseline mode

Only report NEW findings not covered by your committed `.phi-scanbaseline`:

```yaml
hooks:
  - id: phi-scan
    args: ['--baseline']
```

Run `phi-scan baseline create` once to snapshot your current accepted findings
before enabling this flag.

#### Write a machine-readable report

Emit a SARIF report alongside the terminal output:

```yaml
hooks:
  - id: phi-scan
    args: ['--output', 'sarif', '--report-path', 'phi-scan-results.sarif']
```

#### Combine options

```yaml
hooks:
  - id: phi-scan
    args:
      - '--severity-threshold'
      - 'medium'
      - '--baseline'
      - '--output'
      - 'sarif'
      - '--report-path'
      - 'phi-scan-results.sarif'
```

### Skipping the Hook

To skip phi-scan on a single commit:

```bash
SKIP=phi-scan git commit -m "your message"
```

To skip all hooks on a single commit:

```bash
git commit --no-verify -m "your message"
```

> **Note:** `--no-verify` bypasses all hooks, including phi-scan. Reserve this
> for genuine emergencies and document the reason in the commit message.

### Updating phi-scan

```bash
pre-commit autoupdate
```

This updates the `rev` pin in `.pre-commit-config.yaml` to the latest release.

---

## Method 2 — Native Git Hook

The native git hook writes a shell script directly to `.git/hooks/pre-commit`.
It requires no external tooling and works in any git repository.

### Installation

```bash
phi-scan install-hook
```

This writes the following script to `.git/hooks/pre-commit`:

```sh
#!/bin/sh
# phi-scan pre-commit hook — installed by phi-scan install-hook
phi-scan scan --diff HEAD --quiet
if [ $? -ne 0 ]; then
  echo 'phi-scan: PHI/PII detected — commit blocked'
  exit 1
fi
```

### Uninstallation

```bash
phi-scan uninstall-hook
```

PhiScan will only remove hooks it installed. If a hook at `.git/hooks/pre-commit`
was not written by `phi-scan install-hook`, it will not be touched.

### Limitations

| Limitation | Detail |
|---|---|
| Per-repository, not shared | `.git/hooks/` is not committed. Every developer must run `install-hook` separately. |
| No version pinning | The hook runs whatever version of phi-scan is installed on the local machine. |
| Single hook slot | If another tool already occupies `.git/hooks/pre-commit`, `install-hook` will refuse to overwrite it. |

For shared, versioned hook configuration across a team, use the pre-commit
framework (Method 1).

---

## Comparison

| Feature | Pre-commit Framework | Native Git Hook |
|---|---|---|
| Shared via `.pre-commit-config.yaml` | Yes — committed to repo | No — per developer |
| Version-pinned | Yes — `rev:` field | No |
| Works without pre-commit installed | No | Yes |
| Configurable args | Yes — `args:` in config | Edit hook script manually |
| Baseline mode | Yes | Requires manual script edit |
| Skippable per-commit | `SKIP=phi-scan` | `git commit --no-verify` |

---

## Exit Codes

Both integration methods rely on phi-scan's standard exit codes:

| Code | Meaning |
|---|---|
| `0` | No findings (or all findings covered by baseline in `--baseline` mode) |
| `1` | PHI/PII findings detected — commit blocked |
| `2` | Scan error (config invalid, file unreadable, etc.) |
