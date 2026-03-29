# Known Limitations

This document describes file types and scenarios that PhiScan intentionally
skips or cannot fully address. Each entry includes the rationale, the scope
boundary, and the planned resolution where applicable.

---

## Binary File Formats

PhiScan scans text-based source files. The following binary formats contain
PHI in many healthcare codebases but are **not scanned** in Phase 2.

### PDF Files (`.pdf`)

**Status:** Not scanned. Skipped as binary.

`.pdf` is listed in `KNOWN_BINARY_EXTENSIONS` (`phi_scan/constants.py`).
Lab results, discharge summaries, and medical records are frequently committed
to repositories as PDFs. These files may contain all 18 HIPAA Safe Harbor
identifier categories embedded in document text, form fields, and metadata.

**Limitation message:** "PDF files are not scanned. Install `phi-scan[pdf]`
when available to enable text extraction via `pdfminer.six`."

**Planned resolution:** A future phase will add `pdfminer.six` as an optional
dependency under the `[pdf]` extras group, extracting text content from PDF
files for scanning. Tracked as a post-Phase 2 enhancement.

---

### DICOM Files (`.dcm`)

**Status:** Not scanned. Skipped as binary.

DICOM (Digital Imaging and Communications in Medicine) files contain patient
metadata in structured header tags, including:

- Patient Name (0010,0010)
- Patient ID / MRN (0010,0020)
- Patient Birth Date (0010,0030)
- Patient Sex (0010,0040)
- Referring Physician Name (0008,0090)
- Study Date (0008,0020)

Medical imaging files are committed to repositories as test fixtures and
sample data. DICOM headers contain dense PHI and are not accessible without
a DICOM parser.

**Planned resolution:** Post-1.0 feature. Will require `pydicom` as an
optional dependency. Tracked as a post-1.0 enhancement.

---

### Office Documents (`.docx`, `.xlsx`, `.pptx`)

**Status:** Not scanned. Skipped as binary.

`.docx`, `.xlsx`, and `.pptx` are listed in `KNOWN_BINARY_EXTENSIONS`.
Clinical notes, patient rosters, care plans, and billing spreadsheets are
commonly stored as Office files in test fixtures and sample data directories.
These files may contain PHI in document body text, cell values, comments,
and embedded metadata.

**Planned resolution:** A future phase will add `python-docx` and `openpyxl`
as optional dependencies under the `[office]` extras group. Tracked as a
post-Phase 2 enhancement.

---

### Compiled Code (`.class`, `.pyc`, `.pyo`)

**Status:** Not scanned. Intentional scope boundary.

Java `.class` files, Python `.pyc` bytecode, and `.pyo` optimised bytecode
files are in `KNOWN_BINARY_EXTENSIONS`. These are compiled artefacts derived
from source files.

**Rationale:** PHI hardcoded in source code is caught by PhiScan at the
source level — before compilation. Scanning compiled artefacts would
duplicate findings from their source counterparts. Post-compilation bytecode
is an out-of-scope boundary by design.

If a repository contains only compiled artefacts without source code,
PhiScan cannot scan them. This scenario is outside the intended CI/CD
use case (source code repositories).

---

## De-identification Method Coverage

### Expert Determination Not Implemented

PhiScan implements **HIPAA Safe Harbor only** (45 CFR §164.514(b)(2)).

Expert Determination (45 CFR §164.514(b)(1)) requires a qualified statistician
to certify that the risk of identifying an individual from the remaining data
is "very small." A clean PhiScan scan does **not** constitute Expert
Determination certification.

See `docs/de-identification.md` for the full scope description.

---

## NLP Layer — Optional Dependency

**Status:** Degraded capability when `presidio_analyzer` is not installed.

The NLP detection layer (Layer 2) requires `spaCy` and `presidio-analyzer`:

```
pip install phi-scan[nlp]
```

Without this dependency:

- Name detection is limited to field-name pattern matching (e.g., `patient_name = ...`)
- Location detection within free-text strings is unavailable
- The NLP layer emits a warning and skips gracefully

Run `phi-scan setup` after installing `phi-scan[nlp]` to download the
required spaCy model (`en_core_web_lg`).

---

## HL7 v2 Layer — Optional Dependency

**Status:** Degraded capability when the `hl7` library is not installed.

The HL7 v2 segment parser requires the `hl7` library (bundled with `phi-scan[fhir]`):

```
pip install phi-scan[fhir]
```

Without this dependency, HL7 v2 files are scanned by the regex layer only.
Structured segment fields (PID.5 name, PID.19 SSN) may produce lower-confidence
findings or be missed entirely.

---

## Archive Files

**Status:** Not scanned. Skipped as binary.

`.zip`, `.tar`, `.tar.gz`, `.jar`, `.war` files are listed in
`KNOWN_BINARY_EXTENSIONS` or `ARCHIVE_EXTENSIONS`. PHI committed inside
archive files is not detected.

**Rationale:** Archives typically contain build artefacts or dependency
bundles. Expanding and scanning archive contents is out of scope for Phase 2.

---

## Large Files

**Status:** Skipped above configured size threshold.

Files larger than `scan.max_file_size_mb` (default: 10 MB) are skipped with
a warning. Adjust in `.phi-scanner.yml`:

```yaml
scan:
  max_file_size_mb: 25
```

Large generated files (minified JS bundles, SQL dumps) frequently exceed the
default limit. Add them to `.phi-scanignore` rather than raising the limit.
