# Plugin Developer Guide

PhiScan's plugin system allows third parties to add custom PHI recognisers
without modifying the core codebase. Plugins register via Python entry points
and are discovered automatically at startup.

> **Note:** The plugin API is currently in preview. The interface is stable
> for the patterns described below, but additional capabilities (custom
> output formatters, custom compliance frameworks) are planned for Phase 8.

---

## Overview

A PhiScan plugin is a Python package that:

1. Implements one or more `PhiRecognizer` subclasses
2. Registers them via a `phi_scan.recognizers` entry point in `pyproject.toml`
3. Returns `ScanFinding` instances from its `recognize()` method

PhiScan discovers and loads all registered recognisers at scan startup.

---

## Quick Start

```bash
# Create a minimal plugin package
mkdir phi-scan-myplugin && cd phi-scan-myplugin
touch src/phi_scan_myplugin/__init__.py
touch src/phi_scan_myplugin/recognizer.py
touch pyproject.toml
```

---

## Implementing a Recognizer

```python
# src/phi_scan_myplugin/recognizer.py
from __future__ import annotations

from pathlib import Path

from phi_scan.plugin_api import PhiRecognizer
from phi_scan.models import ScanFinding
from phi_scan.constants import PhiCategory, DetectionLayer, SeverityLevel
from phi_scan.hashing import compute_value_hash, severity_from_confidence


class MyCustomRecognizer(PhiRecognizer):
    """Detect ACME Corp employee IDs in source code."""

    @property
    def name(self) -> str:
        """Unique name for this recognizer — used in logs and findings."""
        return "ACME_EMPLOYEE_ID"

    @property
    def supported_categories(self) -> frozenset[PhiCategory]:
        """PHI categories this recognizer can produce."""
        return frozenset({PhiCategory.UNIQUE_ID})

    def recognize(
        self,
        file_content: str,
        file_path: Path,
    ) -> list[ScanFinding]:
        """Scan file_content for ACME employee IDs.

        IMPORTANT: Never store or return raw matched values.
        Always hash with compute_value_hash() before including in ScanFinding.
        """
        import re

        # Example: ACME IDs are EMP- followed by 6 digits
        pattern = re.compile(r"\bEMP-\d{6}\b")
        findings: list[ScanFinding] = []

        for line_number, line in enumerate(file_content.splitlines(), start=1):
            match = pattern.search(line)
            if match is None:
                continue

            matched_value = match.group()
            confidence = 0.90

            findings.append(
                ScanFinding(
                    file_path=file_path,          # must be relative
                    line_number=line_number,
                    entity_type=self.name,
                    hipaa_category=PhiCategory.UNIQUE_ID,
                    confidence=confidence,
                    detection_layer=DetectionLayer.REGEX,
                    value_hash=compute_value_hash(matched_value),   # NEVER store raw
                    severity=severity_from_confidence(confidence),
                    code_context=line.replace(matched_value, "[REDACTED]"),
                    remediation_hint=(
                        "Replace ACME employee ID with a test-only placeholder "
                        "(e.g., EMP-000000)."
                    ),
                )
            )

        return findings
```

---

## PHI Safety Requirements

These requirements are mandatory for all plugins. Violations will cause
your plugin to be rejected from distribution.

### Never Store Raw PHI Values

The `ScanFinding.value_hash` field must contain the SHA-256 digest of the
matched value — never the value itself.

```python
# CORRECT
value_hash = compute_value_hash(matched_value)

# WRONG — never do this
value_hash = matched_value
```

### Redact PHI in code_context

The `code_context` field holds the source line shown to the user. The
matched PHI must be replaced with `[REDACTED]`.

```python
# CORRECT
code_context = line.replace(matched_value, "[REDACTED]")

# WRONG — exposes PHI in output
code_context = line
```

### Relative File Paths Only

`ScanFinding.file_path` must be relative to the scan root. Never use an
absolute path.

```python
# CORRECT (file_path passed in from PhiScan is already relative)
file_path=file_path

# WRONG
file_path=Path("/absolute/path/to/file.py")
```

### No External Network Calls

Recognisers must operate entirely locally. No API calls, no database
lookups, no DNS resolution. PhiScan's security contract is "no data ever
leaves your infrastructure."

---

## Registering via Entry Points

```toml
# pyproject.toml
[project]
name = "phi-scan-myplugin"
version = "0.1.0"
dependencies = ["phi-scan>=0.4.0"]

[project.entry-points."phi_scan.recognizers"]
acme_employee_id = "phi_scan_myplugin.recognizer:MyCustomRecognizer"
```

The entry point name (`acme_employee_id`) must be unique across all installed
plugins. Use a namespace prefix to avoid collisions:
`yourcompany_<name>` or `phi_scan_<name>`.

---

## Testing Your Plugin

### Unit Tests

```python
# tests/test_recognizer.py
from pathlib import Path
from phi_scan_myplugin.recognizer import MyCustomRecognizer


def test_recognizer_detects_employee_id() -> None:
    recognizer = MyCustomRecognizer()
    content = 'employee_id = "EMP-123456"'
    findings = recognizer.recognize(content, Path("config.py"))

    assert len(findings) == 1
    assert findings[0].entity_type == "ACME_EMPLOYEE_ID"
    assert findings[0].line_number == 1
    assert "EMP-123456" not in findings[0].code_context   # must be redacted
    assert "[REDACTED]" in findings[0].code_context


def test_recognizer_no_false_positive_on_clean_content() -> None:
    recognizer = MyCustomRecognizer()
    findings = recognizer.recognize("x = 123", Path("app.py"))
    assert findings == []


def test_recognizer_phi_not_in_value_hash() -> None:
    """value_hash must be SHA-256, not the raw matched value."""
    recognizer = MyCustomRecognizer()
    findings = recognizer.recognize('emp = "EMP-123456"', Path("test.py"))
    assert len(findings) == 1
    assert findings[0].value_hash != "EMP-123456"
    assert len(findings[0].value_hash) == 64   # SHA-256 hex digest
```

### Integration Test

```python
def test_plugin_discovered_by_phi_scan() -> None:
    """Verify the plugin is found by PhiScan's entry point discovery."""
    from phi_scan.plugin_api import load_recognizer_plugins
    recognizers = load_recognizer_plugins()
    names = [r.name for r in recognizers]
    assert "ACME_EMPLOYEE_ID" in names
```

### Test Fixture Requirements

Never use real PHI in test fixtures. For patterns that require structurally
valid values (Luhn checksum, check digit), use the safe values from
`phi_scan/constants.py` as a reference.

---

## Confidence Score Guidelines

Use the following table as a reference when setting `base_confidence`:

| Signal Strength | Recommended Confidence |
|---|---|
| Checksum or algorithm validation | 0.92–0.97 |
| Strong structural match + context keyword | 0.88–0.92 |
| Strong structural match, no context | 0.80–0.88 |
| Field-name detection (value not inspected) | 0.85–0.90 |
| Weak pattern, NLP-style | 0.50–0.70 |

Confidence is used to derive `severity`:
- `confidence ≥ 0.90` → `HIGH`
- `confidence ≥ 0.70` → `MEDIUM`
- `confidence ≥ 0.40` → `LOW`
- `confidence < 0.40` → `INFO`

---

## Distributing Your Plugin

### PyPI Distribution

```bash
uv build
uv publish
```

Users install with:
```bash
pip install phi-scan-myplugin
# PhiScan discovers the plugin automatically at startup
phi-scan scan .
```

### Naming Convention

PyPI package name: `phi-scan-<name>` (e.g., `phi-scan-acme`, `phi-scan-dicom`)  
Python import name: `phi_scan_<name>` (e.g., `phi_scan_acme`, `phi_scan_dicom`)

### Versioning

Pin the minimum PhiScan version your plugin requires:
```toml
dependencies = ["phi-scan>=0.4.0,<1.0"]
```

---

## Listing Installed Plugins

```bash
phi-scan plugins list
```

Shows all discovered plugins with their recognizer names and supported
PHI categories.

---

## API Reference

### `PhiRecognizer` (Abstract Base Class)

```python
from phi_scan.plugin_api import PhiRecognizer

class PhiRecognizer(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique recognizer name. Used in entity_type and logs."""
        ...

    @property
    @abstractmethod
    def supported_categories(self) -> frozenset[PhiCategory]:
        """PHI categories this recognizer may produce."""
        ...

    @abstractmethod
    def recognize(
        self,
        file_content: str,
        file_path: Path,
    ) -> list[ScanFinding]:
        """Scan file_content for PHI. Return empty list if no findings."""
        ...
```

### Utility Functions

```python
from phi_scan.hashing import compute_value_hash, severity_from_confidence

# Hash a matched value (ALWAYS use this — never store raw PHI)
value_hash: str = compute_value_hash("EMP-123456")
# Returns: SHA-256 hex digest string, 64 characters

# Derive severity from a confidence score
severity: SeverityLevel = severity_from_confidence(0.92)
# Returns: SeverityLevel.HIGH
```

### Available Enums

```python
from phi_scan.constants import PhiCategory, DetectionLayer, SeverityLevel

# PhiCategory — use the most specific applicable category
PhiCategory.NAME
PhiCategory.SSN
PhiCategory.UNIQUE_ID     # catch-all for proprietary identifiers
PhiCategory.BIOMETRIC
# ... (see docs/hipaa-identifiers.md for full list)

# DetectionLayer — use REGEX for pattern-based, NLP for ML-based
DetectionLayer.REGEX
DetectionLayer.NLP
```
