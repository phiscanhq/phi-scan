"""Environment variable access for CI/CD adapters.

Provides a safe accessor that returns ``None`` for unset or empty
variables, used by both platform detection and adapter auth lookups.
"""

from __future__ import annotations

import os


def fetch_environment_variable(variable_name: str) -> str | None:
    """Return the environment variable value, or None if unset or empty."""
    return os.environ.get(variable_name, "").strip() or None
