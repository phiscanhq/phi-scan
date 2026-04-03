# Confidence Scoring

PhiScan assigns every finding a confidence score between `0.0` and `1.0`.
This score represents how certain the detection engine is that the matched
value is genuine PHI, not a placeholder, test value, or false positive.

---

## Confidence → Severity Mapping

Severity is derived directly from the confidence score. The mapping is
fixed and cannot be overridden independently.

| Severity | Confidence Range | Meaning |
|---|---|---|
| `HIGH` | ≥ 0.90 | Near-certain PHI; checksum-validated or structurally unique |
| `MEDIUM` | 0.70 – 0.89 | Probable PHI; strong pattern match in context |
| `LOW` | 0.40 – 0.69 | Possible PHI; pattern match without corroborating context |
| `INFO` | < 0.40 | Weak signal; review manually |

These thresholds are defined as `CONFIDENCE_HIGH_FLOOR`, `CONFIDENCE_MEDIUM_FLOOR`,
and `CONFIDENCE_LOW_FLOOR` in `phi_scan/constants.py`.

---

## Per-Layer Confidence Ranges

Each detection layer produces findings in a defined confidence band.

### Layer 1 — Regex

**Range: 0.85 – 1.0**

Regex patterns are designed for high precision. Each pattern in the registry
has a `base_confidence` value reflecting how structurally distinctive the
match is:

- **Checksum-validated patterns** (SSN, NPI, DEA, VIN, MBI) produce
  confidence of 0.92–0.97. The algorithm validates the actual check digit or
  restricted ranges, not just the shape.
- **Context-confirmed patterns** (MRN, Account, Health Plan) produce higher
  confidence when a keyword like `mrn`, `medical_record`, or `account_number`
  appears on the same line, and lower confidence (0.65) when no context is
  found. This is controlled by `context_pattern` in the `PhiPattern` registry.
- **Field-name patterns** (Biometric, SUD) detect PHI by the name of the
  variable or JSON key rather than the value. These are always high-confidence
  because the field name leaves no ambiguity.

### Layer 2 — NLP (Optional)

**Range: 0.50 – 0.90**

The NLP layer uses Microsoft Presidio with the spaCy `en_core_web_lg` model.
It detects names, locations, and dates in free-text strings. Because NLP
models are probabilistic, confidence is lower than structured pattern
matching.

NLP findings are bounded between `CONFIDENCE_NLP_MIN` (0.50) and
`CONFIDENCE_NLP_MAX` (0.90) regardless of the Presidio score.

Install: `pip install "phi-scan[nlp]"` then `phi-scan setup`.

### Layer 3 — FHIR / HL7 (Optional)

**Range: 0.80 – 0.95**

FHIR R4 field-name scanning and HL7 v2 segment parsing use structural
knowledge of the respective data formats. When a value is found in a known
PHI-bearing FHIR field (e.g., `Patient.name.family`) or HL7 segment field
(e.g., PID-5), the finding is treated as near-certain PHI at
`CONFIDENCE_HIGH_FLOOR` (0.90).

Install: `pip install "phi-scan[hl7]"` for HL7 scanning.

### Layer 4 — Quasi-Identifier Combinations

**Fixed: 0.90**

Quasi-identifier combinations (ZIP + DOB, NAME + DATE, AGE > 90 +
GEOGRAPHIC, etc.) are always assigned `CONFIDENCE_HIGH_FLOOR` (0.90).
The combination itself is what creates re-identification risk — the
confidence reflects the structural risk, not the certainty of any
individual identifier.

---

## Variable-Name Context Boost

When the left-hand side of an assignment matches a PHI-suggestive variable
name (e.g., `patient_ssn`, `dob`, `mrn`, `insurance_id`), the confidence
score for that finding is boosted by `VARIABLE_CONTEXT_CONFIDENCE_BOOST`
(+0.15), capped at `CONFIDENCE_SCORE_MAXIMUM` (1.0).

**Suggestive variable patterns:** `address`, `beneficiary`, `birth`,
`diagnosis`, `dob`, `email`, `insurance`, `mrn`, `name`, `patient`,
`phone`, `ssn`.

Example:

```python
# Without context boost: confidence = 0.65 (low context MRN)
record_id = "MRN-004821"

# With context boost: confidence = 0.80 (mrn in variable name → +0.15)
mrn = "MRN-004821"
```

---

## Tuning the Confidence Threshold

The `confidence_threshold` setting filters out findings below the specified
score before they are reported. The default is `0.6`.

```yaml
# .phi-scanner.yml
scan:
  confidence_threshold: 0.6   # default; reports LOW, MEDIUM, and HIGH findings
```

### Recommended Threshold Values

| Threshold | Effect |
|---|---|
| `0.40` | Report everything including INFO — maximum coverage, high false positive rate |
| `0.60` | Default — good balance for CI/CD pipelines |
| `0.70` | MEDIUM and HIGH only — lower noise in high-volume codebases |
| `0.90` | HIGH only — near-zero false positives; may miss ambiguous PHI |

Override per-run with `--severity-threshold`:

```bash
# Block only HIGH-confidence findings in CI
phi-scan scan . --severity-threshold high
```

---

## Severity Threshold vs. Confidence Threshold

These are two independent filters:

- **`confidence_threshold`** (float): Hides findings whose raw confidence
  score falls below the value. Applies before severity calculation.
- **`severity_threshold`** (enum): Hides findings below the specified
  severity level (info → low → medium → high). Because severity is derived
  from confidence, `--severity-threshold high` is equivalent to
  `--confidence-threshold 0.90` in most cases.

Use `confidence_threshold` in `.phi-scanner.yml` for persistent per-project
tuning. Use `--severity-threshold` for ad-hoc overrides.

---

## Reading Confidence in Output

### Table output

```
┌─────────────────┬──────┬────────────────┬──────────┬────────────┐
│ File            │ Line │ Entity         │ Severity │ Confidence │
├─────────────────┼──────┼────────────────┼──────────┼────────────┤
│ src/fixtures.py │   42 │ SSN            │ HIGH     │ 0.97       │
│ config/test.yml │    8 │ PHONE          │ MEDIUM   │ 0.88       │
│ scripts/seed.py │   15 │ MRN (no ctx)   │ LOW      │ 0.65       │
└─────────────────┴──────┴────────────────┴──────────┴────────────┘
```

### JSON output

```json
{
  "entity_type": "SSN",
  "hipaa_category": "ssn",
  "confidence": 0.97,
  "severity": "high",
  "detection_layer": "regex"
}
```

---

## Why Findings Cluster Near Band Boundaries

Layer base confidences are designed to place findings near the middle of
their severity bands, not on the boundaries. A regex SSN pattern produces
0.97, well into HIGH. An NLP name finding produces 0.70–0.85, in MEDIUM to
HIGH. This avoids cliff effects where a tiny score difference causes a
severity jump.

The context boost (+0.15) is the primary mechanism that can move a finding
from LOW to MEDIUM or MEDIUM to HIGH. This is intentional: finding `ssn = "123-45-6789"`
in a variable named `ssn` is more certain than finding it in `x = "123-45-6789"`.
