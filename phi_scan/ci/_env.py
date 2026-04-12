"""Environment variable access for CI/CD adapters.

Provides a safe accessor that returns ``None`` for unset or empty
variables, used by both platform detection and adapter auth lookups.
"""

from __future__ import annotations

import os

_ENV_DEFAULT_EMPTY: str = ""


def fetch_environment_variable(variable_name: str) -> str | None:
    """Return the environment variable value, or None if unset or empty."""
    raw_env_string = os.environ.get(variable_name, _ENV_DEFAULT_EMPTY).strip()
    return raw_env_string if raw_env_string else None
