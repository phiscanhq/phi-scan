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

## Advisory Scope Limitations

### Expert Determination Not Implemented

PhiScan implements **HIPAA Safe Harbor only** (45 CFR §164.514(b)(2)).

Expert Determination (45 CFR §164.514(b)(1)) requires a qualified statistician
to certify that the risk of identifying an individual from the remaining data
is "very small." A clean PhiScan scan does **not** constitute Expert
Determination certification.

See `docs/de-identification.md` for the full scope description.

---

### State Law Compliance Is Advisory

PhiScan maps PHI findings to state-level frameworks (California CMIA, Illinois
BIPA, New York SHIELD Act, Texas MRPA) using the `--framework` flag. These
mappings are advisory only.

**What the mappings provide:**
- The applicable control ID and name from each framework
- The regulatory citation for that control
- A reference to which PHI category triggers the control

**What the mappings do not determine:**
- Whether your organisation is subject to a given state law (this depends on
  where your patients, customers, or employees are located)
- Whether a specific finding constitutes a violation under that law (context
  that only legal counsel can assess)
- Compliance with state-specific procedural requirements (notice periods,
  breach notification formats, consent forms)

> **Advisory:** State law compliance annotation is a research aid, not a legal
> determination. Confirm applicability and compliance posture with qualified
> legal counsel for each jurisdiction.

---

### 42 CFR Part 2 Detection Is Pattern-Based

PhiScan's 42 CFR Part 2 detection identifies field names and identifiers that
match SUD (Substance Use Disorder) treatment terminology using
`SUD_FIELD_NAME_PATTERNS`. It does **not** determine:

- Whether the scanned record is held by a **federally assisted** SUD treatment
  programme (the primary applicability criterion under 42 CFR § 2.12)
- Whether the field actually contains SUD treatment information, or merely
  uses SUD-adjacent terminology
- Whether a disclosure would require patient consent under Part 2

A `SUBSTANCE_USE_DISORDER` finding means: "this field name matches SUD
terminology — verify whether Part 2 applies to this record."

---

### PHI in Context vs. PHI in Isolation

PhiScan evaluates each file and finding independently. It does not model
cross-file or cross-system context. This creates two important limitations:

**False positives from context:** A field named `patient_mrn` containing a
clearly fictional value (e.g., `MRN-000000`) may still be flagged because the
field name implies PHI. Use `# phi-scan:ignore[MRN]` to suppress confirmed
false positives.

**False negatives from isolation:** PHI that is safe in isolation may be
identifying in combination with data from another file or system. For example:

- A file containing only a ZIP code produces no finding
- A separate file containing only a date of birth produces no finding
- Together, the ZIP + DOB combination creates re-identification risk

Layer 4 (quasi-identifier combination detection) catches same-file
combinations within 50 lines. Cross-file combinations are outside the
detection scope.

> **Recommendation:** For datasets with high re-identification risk, supplement
> PhiScan with a dataset-level privacy analysis tool that evaluates the full
> data schema across all files.

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

The HL7 v2 segment parser requires the `hl7` library:

```
pip install phi-scan[hl7]
```

Without this dependency, HL7 v2 files are scanned by the regex layer only.
Structured segment fields (PID.5 name, PID.19 SSN) may produce lower-confidence
findings or be missed entirely.

---

## Archive Files

### ZIP, JAR, WAR (`.zip`, `.jar`, `.war`)

**Status:** Scanned in-memory. Text members only. Decompression bomb protection active.

PhiScan opens these files with `zipfile.ZipFile` and scans text-based members
whose extension appears in `ARCHIVE_SCANNABLE_EXTENSIONS` (`.conf`, `.json`,
`.properties`, `.xml`, `.yaml`, `.yml`). Binary members (`.class`, `.pyc`,
media files) are skipped within the archive. Archive contents are never
extracted to disk — the local-execution-only contract is preserved.

**Decompression bomb protection:** Before reading any member, PhiScan checks
`ZipInfo.file_size` and the compression ratio. Members exceeding
`ARCHIVE_MAX_MEMBER_UNCOMPRESSED_BYTES` (100 MB) or a compression ratio above
`ARCHIVE_MAX_COMPRESSION_RATIO` (200:1) are skipped with a `WARNING` log. The
scan continues with remaining members. See [security.md](security.md) for details.

### TAR and Compressed Archives (`.tar`, `.tar.gz`, `.gz`)

**Status:** Not scanned. Skipped as binary.

`.tar`, `.tar.gz`, and `.gz` files are listed in `KNOWN_BINARY_EXTENSIONS`.
PHI committed inside these archives is not detected.

**Rationale:** TAR inspection requires the `tarfile` module and a separate
streaming decompression path. This is deferred to a post-Phase 2 enhancement.

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
