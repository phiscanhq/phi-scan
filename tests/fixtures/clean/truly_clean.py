# Synthetic zero-finding fixture: contains no PHI, no identifiers, no numbers that
# resemble identifiers, and no geographic or demographic signals. Used to exercise
# the CLEAN-path of the v2 terminal renderer.
# Expected findings: 0

from __future__ import annotations


def concatenate_strings(first: str, second: str) -> str:
    """Return the concatenation of two strings."""
    return first + second


def reverse_string(source: str) -> str:
    """Return the reverse of a string."""
    return source[::-1]


def is_palindrome(candidate: str) -> bool:
    """Return True when the candidate reads the same forwards and backwards."""
    normalized = candidate.lower()
    return normalized == normalized[::-1]
