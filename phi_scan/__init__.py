"""PhiScan — HIPAA & FHIR compliant PHI/PII scanner for CI/CD pipelines."""

from phi_scan.plugin_api import (
    PLUGIN_API_VERSION,
    BaseRecognizer,
    ScanContext,
    ScanFinding,
)

__version__ = "0.5.0"
__app_name__ = "phi-scan"

__all__ = [
    "BaseRecognizer",
    "PLUGIN_API_VERSION",
    "ScanContext",
    "ScanFinding",
    "__app_name__",
    "__version__",
]
