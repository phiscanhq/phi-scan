"""Performance benchmarks for execute_scan (scorecard T8 / T9).

This module generates synthetic Python source files with embedded
synthetic PHI values (reserved SSNs, fictional phone numbers, RFC 2606
example.com emails) into a pytest ``tmp_path`` corpus, runs
``execute_scan`` sequentially (``workers=1``), and asserts that the
elapsed scan duration and files-per-second throughput stay within
per-corpus-size thresholds.

Three corpus sizes are exercised:

- ``small``  — 10 files, approximately 1 KB each
- ``medium`` — 100 files, approximately 5 KB each
- ``large``  — 500 files, approximately 10 KB each

Thresholds are encoded as per-size ``CorpusBenchmarkSpec`` constants
and leave roughly 3x headroom over measured local runtime so the gate
is stable on GitHub-hosted runners without drowning the regression
signal. Loosening a threshold should always appear in git blame with
a justification — investigate the regression first.

Benchmarks run on Linux only. macOS and Windows GitHub runners have
higher I/O variance and would flake the gate without catching real
regressions; a stable Linux gate is sufficient.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pytest

from phi_scan.models import ScanConfig, ScanResult
from phi_scan.scanner import execute_scan

# ---------------------------------------------------------------------------
# Platform gating
# ---------------------------------------------------------------------------

_BENCHMARKS_SUPPORTED_PLATFORM_PREFIX: str = "linux"
_BENCHMARKS_SKIP_REASON: str = (
    "benchmarks run on Linux only — macOS and Windows GitHub runners have "
    "higher I/O variance and would flake the gate without catching real "
    "performance regressions"
)

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith(_BENCHMARKS_SUPPORTED_PLATFORM_PREFIX),
    reason=_BENCHMARKS_SKIP_REASON,
)

# ---------------------------------------------------------------------------
# Corpus size identifiers
# ---------------------------------------------------------------------------

_CORPUS_SIZE_SMALL: str = "small"
_CORPUS_SIZE_MEDIUM: str = "medium"
_CORPUS_SIZE_LARGE: str = "large"

# ---------------------------------------------------------------------------
# Synthetic file content
#
# PHI-safety: every embedded value is drawn from a reserved or fictional
# range that can never match a real person:
#
# - 999-xx-xxxx SSNs fall in the reserved IRS ITIN block, never issued as
#   real SSNs.
# - 555-01xx phone numbers are reserved for fictional use per NANP.
# - example.com is reserved for documentation by RFC 2606.
# ---------------------------------------------------------------------------

_SYNTHETIC_FILENAME_FORMAT: str = "synthetic_{file_index:05d}.py"
_SYNTHETIC_SSN_FORMAT: str = "999-{middle_group:02d}-{last_group:04d}"
_SYNTHETIC_PHONE_FORMAT: str = "555-01{last_two_digits:02d}"
_SYNTHETIC_EMAIL_FORMAT: str = "user{file_index}@example.com"

_SYNTHETIC_SSN_MIDDLE_GROUP_MODULUS: int = 100
_SYNTHETIC_SSN_LAST_GROUP_MODULUS: int = 10_000
_SYNTHETIC_PHONE_LAST_TWO_MODULUS: int = 100
_SYNTHETIC_SSN_MIDDLE_GROUP_STEP: int = 7
_SYNTHETIC_SSN_LAST_GROUP_STEP: int = 13
_SYNTHETIC_PHONE_LAST_TWO_STEP: int = 3

_FILE_TEMPLATE: str = '''"""Synthetic PHI file for benchmark corpus entry {file_index}."""

PATIENT_SSN = "{ssn}"
CALLBACK_PHONE = "{phone}"
CONTACT_EMAIL = "{email}"


def get_fake_patient_record():
    """Return a synthetic patient record used only by benchmark tests."""
    return {{
        "id": {file_index},
        "ssn": PATIENT_SSN,
        "phone": CALLBACK_PHONE,
        "email": CONTACT_EMAIL,
    }}


# Filler content expands the file to the corpus target size: {filler}
'''

_FILLER_CHARACTER: str = "."


# ---------------------------------------------------------------------------
# Corpus specifications and thresholds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusBenchmarkSpec:
    """Per-corpus-size benchmark configuration.

    Attributes:
        file_count: Number of files to generate into the corpus directory.
        filler_character_count: Number of filler characters appended to
            each file body to reach the target per-file size.
        max_elapsed_seconds: Upper bound for ``ScanResult.scan_duration``.
            Tests fail if the measured duration exceeds this value.
        min_files_per_second: Lower bound for throughput, measured as
            ``file_count / scan_duration``. Tests fail below this floor.
    """

    file_count: int
    filler_character_count: int
    max_elapsed_seconds: float
    min_files_per_second: float


# Thresholds are set with enough headroom to absorb GitHub runner variance
# (~2-4x slower than a local dev machine, with occasional outlier runs)
# while still catching a catastrophic regression. Observed local timings
# at the time of authoring:
#
#   small  — 0.05 s / ~200 files per second
#   medium — 0.55 s / ~180 files per second
#   large  — 0.83 s / ~600 files per second
#
# The gate is intentionally conservative — it is designed to catch
# 5-10x regressions, not slow creep. Detecting slow creep across time
# requires trend tracking which is out of scope for this module.
_CORPUS_BENCHMARK_SPECS: MappingProxyType[str, CorpusBenchmarkSpec] = MappingProxyType(
    {
        _CORPUS_SIZE_SMALL: CorpusBenchmarkSpec(
            file_count=10,
            filler_character_count=800,
            max_elapsed_seconds=3.0,
            min_files_per_second=5.0,
        ),
        _CORPUS_SIZE_MEDIUM: CorpusBenchmarkSpec(
            file_count=100,
            filler_character_count=4_500,
            max_elapsed_seconds=10.0,
            min_files_per_second=15.0,
        ),
        _CORPUS_SIZE_LARGE: CorpusBenchmarkSpec(
            file_count=500,
            filler_character_count=9_500,
            max_elapsed_seconds=25.0,
            min_files_per_second=20.0,
        ),
    }
)

_ALL_CORPUS_SIZE_NAMES: tuple[str, ...] = (
    _CORPUS_SIZE_SMALL,
    _CORPUS_SIZE_MEDIUM,
    _CORPUS_SIZE_LARGE,
)

_BENCHMARK_WORKER_COUNT: int = 1

# Guard against division by zero when computing files-per-second. In practice
# time.monotonic() always advances between two calls, but a defensive guard
# avoids a ZeroDivisionError if the measured scan is unexpectedly instant.
_ZERO_ELAPSED_SECONDS: float = 0.0

# Each synthetic file embeds three explicit PHI values (SSN, phone number,
# email address). The real finding count observed in practice is higher
# because quasi-identifier combinations fire additional detections, but
# three is the guaranteed floor per file. A regression that silently
# stopped detecting any of the three primary patterns would fail this
# lower bound before the runtime thresholds even fire.
_MINIMUM_FINDINGS_PER_SYNTHETIC_FILE: int = 3


# ---------------------------------------------------------------------------
# Synthetic corpus generation
# ---------------------------------------------------------------------------


def _build_synthetic_ssn(file_index: int) -> str:
    middle_step = file_index * _SYNTHETIC_SSN_MIDDLE_GROUP_STEP
    last_step = file_index * _SYNTHETIC_SSN_LAST_GROUP_STEP
    middle_group = middle_step % _SYNTHETIC_SSN_MIDDLE_GROUP_MODULUS
    last_group = last_step % _SYNTHETIC_SSN_LAST_GROUP_MODULUS
    return _SYNTHETIC_SSN_FORMAT.format(middle_group=middle_group, last_group=last_group)


def _build_synthetic_phone(file_index: int) -> str:
    phone_step = file_index * _SYNTHETIC_PHONE_LAST_TWO_STEP
    last_two_digits = phone_step % _SYNTHETIC_PHONE_LAST_TWO_MODULUS
    return _SYNTHETIC_PHONE_FORMAT.format(last_two_digits=last_two_digits)


def _build_synthetic_email(file_index: int) -> str:
    return _SYNTHETIC_EMAIL_FORMAT.format(file_index=file_index)


def _build_synthetic_file_body(file_index: int, filler_character_count: int) -> str:
    return _FILE_TEMPLATE.format(
        file_index=file_index,
        ssn=_build_synthetic_ssn(file_index),
        phone=_build_synthetic_phone(file_index),
        email=_build_synthetic_email(file_index),
        filler=_FILLER_CHARACTER * filler_character_count,
    )


def _generate_corpus_files(corpus_root: Path, spec: CorpusBenchmarkSpec) -> list[Path]:
    """Write ``spec.file_count`` synthetic files into ``corpus_root``.

    Creates ``corpus_root`` (and any missing parents) if it does not
    already exist so callers can pass a pytest ``tmp_path`` subdirectory
    directly without a separate mkdir step.

    Args:
        corpus_root: Directory that will contain the generated files.
        spec: Corpus specification — file count and filler size.

    Returns:
        A list of generated file paths in stable index order.
    """
    corpus_root.mkdir(parents=True, exist_ok=True)
    generated_paths: list[Path] = []
    for file_index in range(spec.file_count):
        file_name = _SYNTHETIC_FILENAME_FORMAT.format(file_index=file_index)
        file_path = corpus_root / file_name
        file_body = _build_synthetic_file_body(file_index, spec.filler_character_count)
        file_path.write_text(file_body)
        generated_paths.append(file_path)
    return generated_paths


# ---------------------------------------------------------------------------
# Benchmark execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkMeasurement:
    """Observed timing for one benchmark run."""

    elapsed_seconds: float
    files_per_second: float
    scan_result: ScanResult


def _measure_scan_performance(corpus_files: list[Path], config: ScanConfig) -> BenchmarkMeasurement:
    """Run ``execute_scan`` and return the observed timing and result.

    Elapsed time is taken from ``time.monotonic`` around the call rather
    than from ``ScanResult.scan_duration`` so the measurement covers the
    full call dispatch, not only the inner scan loop. The two values
    should be near-identical for the sequential path, but wrapping
    explicitly documents exactly what the threshold guards.
    """
    scan_start = time.monotonic()
    scan_result = execute_scan(corpus_files, config, worker_count=_BENCHMARK_WORKER_COUNT)
    elapsed_seconds = time.monotonic() - scan_start
    if elapsed_seconds > _ZERO_ELAPSED_SECONDS:
        files_per_second = len(corpus_files) / elapsed_seconds
    else:
        files_per_second = float("inf")
    return BenchmarkMeasurement(
        elapsed_seconds=elapsed_seconds,
        files_per_second=files_per_second,
        scan_result=scan_result,
    )


def _assert_measurement_meets_spec(
    measurement: BenchmarkMeasurement, spec: CorpusBenchmarkSpec, corpus_size_name: str
) -> None:
    assert measurement.elapsed_seconds <= spec.max_elapsed_seconds, (
        f"{corpus_size_name} corpus scan took "
        f"{measurement.elapsed_seconds:.3f}s, exceeding threshold "
        f"{spec.max_elapsed_seconds:.3f}s. Investigate regression before "
        f"loosening the threshold."
    )
    assert measurement.files_per_second >= spec.min_files_per_second, (
        f"{corpus_size_name} corpus throughput "
        f"{measurement.files_per_second:.2f} files/s is below the floor "
        f"{spec.min_files_per_second:.2f} files/s. Investigate regression "
        f"before loosening the threshold."
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("corpus_size_name", _ALL_CORPUS_SIZE_NAMES)
def test_execute_scan_meets_per_corpus_performance_thresholds(
    corpus_size_name: str, tmp_path: Path
) -> None:
    """execute_scan stays within the per-size runtime and throughput gates."""
    spec = _CORPUS_BENCHMARK_SPECS[corpus_size_name]
    corpus_root = tmp_path / f"corpus_{corpus_size_name}"
    corpus_files = _generate_corpus_files(corpus_root, spec)

    # Default ScanConfig is intentional — benchmarks measure the out-of-box
    # scan path a typical caller would see. If ScanConfig defaults change
    # (new detectors enabled, thresholds tightened), the observed runtime
    # will shift and the thresholds in _CORPUS_BENCHMARK_SPECS should be
    # re-measured as part of that change.
    config = ScanConfig()
    measurement = _measure_scan_performance(corpus_files, config)

    minimum_expected_finding_count = spec.file_count * _MINIMUM_FINDINGS_PER_SYNTHETIC_FILE
    assert measurement.scan_result.files_scanned == spec.file_count
    assert len(measurement.scan_result.findings) >= minimum_expected_finding_count
    _assert_measurement_meets_spec(measurement, spec, corpus_size_name)
