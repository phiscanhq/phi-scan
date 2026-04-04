"""Smoke tests verifying the phi_scan package is importable and correctly identified."""

import phi_scan


def test_version_is_defined() -> None:
    assert phi_scan.__version__ == "0.5.0"


def test_app_name_is_defined() -> None:
    assert phi_scan.__app_name__ == "phi-scan"
