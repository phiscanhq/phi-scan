# Plugin Developer Guide

PhiScan's plugin system allows third parties to add custom PHI recognisers
without modifying the core codebase. Plugins register via Python entry points
and are discovered automatically at scan startup.

This guide targets **Plugin API v1** (`PLUGIN_API_VERSION = "1.0"`). The
authoritative contract, compatibility policy, and deprecation process live in
[docs/plugin-api-v1.md](plugin-api-v1.md); this document is the practical
tutorial companion.

---

## Overview

A PhiScan plugin is a Python package that:

1. Implements one or more `BaseRecognizer` subclasses.
2. Declares class-level metadata (`name`, `entity_types`, `plugin_api_version`).
3. Implements `detect(line, context)` — called by the host once per line of
   every file in scope, returning zero or more `ScanFinding` objects.
4. Registers its recognizers via a `phi_scan.plugins` entry point in
   `pyproject.toml`.

The host is responsible for file traversal, line iteration, value hashing,
severity derivation, and output redaction. Plugins never handle raw PHI
end-to-end — they return line-relative offsets and a confidence score, and
the host takes it from there.

---

## Quick Start

```bash
mkdir phi-scan-acme && cd phi-scan-acme
mkdir -p src/phi_scan_acme tests
touch src/phi_scan_acme/__init__.py
touch src/phi_scan_acme/recognizer.py
touch tests/test_recognizer.py
touch pyproject.toml
```

---

## Implementing a Recognizer

```python
# src/phi_scan_acme/recognizer.py
from __future__ import annotations

import re

from phi_scan.plugin_api import BaseRecognizer, ScanContext, ScanFinding

_ACME_EMPLOYEE_ID_PATTERN = re.compile(r"\bEMP-\d{6}\b")
_ACME_EMPLOYEE_ID_CONFIDENCE = 0.90


class AcmeEmployeeIdRecognizer(BaseRecognizer):
    """Detect ACME Corp employee IDs (``EMP-123456``) in source code."""

    name = "acme_employee_id"
    entity_types = ("ACME_EMPLOYEE_ID",)
    plugin_api_version = "1.0"
    version = "0.1.0"
    description = "Detects ACME Corp employee identifiers."

    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        match = _ACME_EMPLOYEE_ID_PATTERN.search(line)
        if match is None:
            return []
        return [
            ScanFinding(
                entity_type="ACME_EMPLOYEE_ID",
                start_offset=match.start(),
                end_offset=match.end(),
                confidence=_ACME_EMPLOYEE_ID_CONFIDENCE,
            )
        ]
```

### Multiple findings per line

A single line may contain several matches. `detect` is allowed to return
more than one `ScanFinding` per call:

```python
def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
    return [
        ScanFinding(
            entity_type="ACME_EMPLOYEE_ID",
            start_offset=match.start(),
            end_offset=match.end(),
            confidence=_ACME_EMPLOYEE_ID_CONFIDENCE,
        )
        for match in _ACME_EMPLOYEE_ID_PATTERN.finditer(line)
    ]
```

Offsets are **line-relative** (0-indexed, using `match.start()` and
`match.end()` directly). Never translate them to file-absolute positions —
the host re-resolves line/column using `context.line_number`.

---

## Class Attribute Contract

Recognizers declare metadata as **class attributes**, not `@property`
methods. The loader validates this metadata at discovery time and skips
any plugin whose metadata is malformed.

| Attribute | Required | Rule |
|-----------|----------|------|
| `name` | Yes | Lowercase snake_case, must match `^[a-z][a-z0-9_]*$`. Used as the collision key across installed distributions. |
| `entity_types` | Yes | Non-empty sequence (`tuple` preferred) of uppercase strings matching `^[A-Z][A-Z0-9_]*$`. Must be unique within the sequence. Every returned `ScanFinding.entity_type` MUST appear here. |
| `plugin_api_version` | Yes | Must equal the host's `PLUGIN_API_VERSION` exactly (currently `"1.0"`). Mismatches are rejected at load time with a warning. |
| `version` | No | Plugin's own semver string. Informational. Defaults to `"0.0.0"`. |
| `description` | No | One-line human description. Informational. Defaults to `""`. |

---

## What the Host Guarantees

Plugin authors do **not** hash values, derive severity, or redact output.
The host handles these concerns uniformly for all findings so that plugin
bugs cannot leak PHI:

- **Value hashing.** The host takes `line[start_offset:end_offset]`, hashes
  it with SHA-256, and stores only the digest in the audit log and output.
- **Severity derivation.** The host maps `confidence` to a `SeverityLevel`
  using the project-wide confidence bands. Plugins must not pre-inflate
  confidence to force a higher severity.
- **Output redaction.** The matched slice is replaced with `[REDACTED]` in
  any `code_context` emitted to the terminal, JSON, SARIF, CSV, or report
  artifacts.
- **File traversal and line iteration.** The host resolves symlinks safely,
  enforces size and extension policies, and decodes text. Plugins receive
  a single decoded `line` per call.

---

## Plugin Author Obligations

These obligations are mandatory. A plugin that violates any of them will
be rejected from distribution through official channels and may be blocked
by the host at runtime in a future API revision.

1. **Never log `line` content or matched slices.** Do not emit the line,
   the `line[start:end]` slice, or any substring containing user data to
   `print`, `logging`, structured logs, telemetry, or any other sink.
2. **No network calls, DNS lookups, or database queries.** Recognizers
   must operate entirely in-process. PhiScan's contract to its users is
   that no data leaves the machine during scanning; plugins inherit that
   contract.
3. **No writing matched slices to disk.** Do not persist matched content
   to temporary files, caches, or state directories.
4. **Sanitize raised exceptions.** If `detect` raises, the host drops the
   line's batch with a warning. Exception messages MUST NOT include the
   `line`, the matched slice, or any substring of either.
5. **Do not open or read `context.file_path`.** The host already provides
   the line content. Opening the file directly bypasses the host's safe
   traversal, size, and decoding policies and is prohibited.

---

## Registering via Entry Points

```toml
# pyproject.toml
[project]
name = "phi-scan-acme"
version = "0.1.0"
dependencies = ["phi-scan>=0.4.0,<1.0"]

[project.entry-points."phi_scan.plugins"]
acme_employee_id = "phi_scan_acme.recognizer:AcmeEmployeeIdRecognizer"
```

The entry point key (`acme_employee_id`) must be unique across every
installed plugin. Prefix with your organisation or product name to avoid
collisions: `acme_<name>`, `phi_scan_<name>`.

---

## Testing Your Plugin

### Unit Tests

```python
# tests/test_recognizer.py
from pathlib import Path

from phi_scan.plugin_api import ScanContext
from phi_scan_acme.recognizer import AcmeEmployeeIdRecognizer


def _build_context() -> ScanContext:
    return ScanContext(
        file_path=Path("config.py"),
        line_number=1,
        file_extension=".py",
    )


def test_recognizer_detects_employee_id() -> None:
    recognizer = AcmeEmployeeIdRecognizer()
    findings = recognizer.detect('employee_id = "EMP-123456"', _build_context())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.entity_type == "ACME_EMPLOYEE_ID"
    assert finding.start_offset == 16
    assert finding.end_offset == 26
    assert 0.0 <= finding.confidence <= 1.0


def test_recognizer_returns_empty_list_on_clean_line() -> None:
    recognizer = AcmeEmployeeIdRecognizer()
    assert recognizer.detect("x = 123", _build_context()) == []


def test_recognizer_finds_multiple_matches_per_line() -> None:
    recognizer = AcmeEmployeeIdRecognizer()
    findings = recognizer.detect("EMP-111111 EMP-222222", _build_context())
    assert len(findings) == 2
```

### Integration Test — Discovery

Use the host's public loader API to confirm PhiScan sees your plugin.
Both helpers return a `PluginRegistry`:

- `discover_plugin_registry()` — exposes both loaded and skipped plugins,
  useful for asserting why a plugin was rejected.
- `load_plugin_registry()` — returns only successfully loaded plugins,
  matching runtime behaviour.

```python
from phi_scan.plugin_loader import (
    discover_plugin_registry,
    load_plugin_registry,
)


def test_plugin_is_loaded_by_host() -> None:
    registry = load_plugin_registry()
    recognizer_names = [plugin.recognizer.name for plugin in registry.loaded]
    assert "acme_employee_id" in recognizer_names


def test_plugin_has_no_skip_reason() -> None:
    registry = discover_plugin_registry()
    skipped_names = [plugin.entry_point_name for plugin in registry.skipped]
    assert "acme_employee_id" not in skipped_names
```

### Test Fixture Requirements

Never use real PHI in test fixtures. When a pattern requires a structurally
valid value (checksum, check digit), synthesize one — never copy from a
real record, document, or dataset.

---

## Confidence Guidance

`confidence` is a float in `[0.0, 1.0]`. Use the following bands as a
starting reference; tune based on false-positive and false-negative rates
in your target corpora.

| Signal Strength | Recommended Confidence |
|-----------------|------------------------|
| Checksum or algorithm validation (e.g. Luhn, check digit) | 0.92–0.97 |
| Strong structural match + supporting context keyword | 0.88–0.92 |
| Strong structural match, no context | 0.80–0.88 |
| Field-name match only (value not inspected) | 0.85–0.90 |
| Weak NLP-style signal | 0.50–0.70 |

The host derives `SeverityLevel` from `confidence` using the project-wide
bands documented in [docs/confidence-scoring.md](confidence-scoring.md).
Plugins should not encode severity decisions themselves.

---

## Distributing Your Plugin

### PyPI

```bash
uv build
uv publish
```

Users install with:

```bash
pip install phi-scan-acme
# PhiScan discovers the plugin automatically on the next scan.
phi-scan scan .
```

### Naming Convention

- PyPI package: `phi-scan-<name>` (e.g. `phi-scan-acme`, `phi-scan-dicom`)
- Python import name: `phi_scan_<name>`
- Recognizer `name`: lowercase snake_case, organisation-prefixed
  (`acme_employee_id`, `dicom_patient_id`)

### Version Compatibility

Pin the minimum PhiScan version your plugin targets and cap the major
version so that a future v2 API break does not silently install against
an incompatible host:

```toml
dependencies = ["phi-scan>=0.4.0,<1.0"]
```

The host enforces exact-match on `plugin_api_version` at load time. If a
future v1.1 minor bump introduces new optional surface, your plugin will
continue to load unchanged under the existing `"1.0"` declaration —
consult [docs/plugin-api-v1.md](plugin-api-v1.md) for the compatibility
and deprecation policy before upgrading your declared API version.

---

## Listing Installed Plugins

```bash
phi-scan plugins list
phi-scan plugins list --json   # machine-readable
```

Shows every discovered plugin, whether it loaded or was skipped, and the
reason for any skip.

---

## API Reference

### `BaseRecognizer` (Abstract Base Class)

```python
from collections.abc import Sequence

from phi_scan.plugin_api import BaseRecognizer, ScanContext, ScanFinding


class BaseRecognizer(ABC):
    name: str
    entity_types: Sequence[str]
    plugin_api_version: str = "1.0"
    version: str = "0.0.0"
    description: str = ""

    @abstractmethod
    def detect(self, line: str, context: ScanContext) -> list[ScanFinding]:
        """Return ScanFinding objects for the given line. May be empty."""
```

### `ScanContext`

```python
@dataclass(frozen=True)
class ScanContext:
    file_path: Path         # provided for language-gating/logging; never open
    line_number: int        # 1-indexed
    file_extension: str     # includes leading dot, "" if none
```

### `ScanFinding`

```python
@dataclass(frozen=True)
class ScanFinding:
    entity_type: str        # must appear in recognizer.entity_types
    start_offset: int       # line-relative, 0-indexed, >= 0
    end_offset: int         # line-relative, exclusive, > start_offset
    confidence: float       # [0.0, 1.0]
```

The dataclass validates its arguments in `__post_init__`, so malformed
findings raise at construction time rather than silently corrupting output.

### Version Constant

```python
from phi_scan.plugin_api import PLUGIN_API_VERSION

assert PLUGIN_API_VERSION == "1.0"
```
