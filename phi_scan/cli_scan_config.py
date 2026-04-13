"""Compatibility shim — real module lives at `phi_scan.cli.scan_config`.

This top-level re-export preserves the historical import path
`phi_scan.cli_scan_config` while the canonical home is the `phi_scan.cli`
package. New code should import from `phi_scan.cli.scan_config` directly.
"""

from phi_scan.cli import scan_config as _module
from phi_scan.cli.scan_config import *  # noqa: F401,F403

__all__ = getattr(_module, "__all__", [name for name in dir(_module) if not name.startswith("_")])
