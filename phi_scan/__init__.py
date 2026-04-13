"""PhiScan — HIPAA & FHIR compliant PHI/PII scanner for CI/CD pipelines."""

from importlib.metadata import PackageNotFoundError, version

from phi_scan.plugin_api import (
    PLUGIN_API_VERSION,
    BaseRecognizer,
    ScanContext,
    ScanFinding,
)

__app_name__ = "phi-scan"

try:
    __version__: str = version(__app_name__)
except PackageNotFoundError:  # pragma: no cover — only hit when package is not installed
    __version__ = "0.0.0+unknown"

__all__ = [
    "BaseRecognizer",
    "PLUGIN_API_VERSION",
    "ScanContext",
    "ScanFinding",
    "__app_name__",
    "__version__",
]
