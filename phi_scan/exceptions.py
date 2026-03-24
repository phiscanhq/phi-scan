"""Custom exception hierarchy for PhiScan.

All domain errors inherit from PhiScanError so callers can catch the entire
family with a single except clause when broad error handling is appropriate.
Each subclass targets a specific failure domain so callers can also catch
narrowly when they need to distinguish error types.
"""

from __future__ import annotations

__all__ = [
    "AuditLogError",
    "ConfigurationError",
    "MissingOptionalDependencyError",
    "PhiDetectionError",
    "PhiScanError",
    "SchemaMigrationError",
    "TraversalError",
]


class PhiScanError(Exception):
    """Base class for all PhiScan domain errors.

    Raise a specific subclass in preference to this base class. Use this
    base class only in except clauses that need to catch any PhiScan error.

    Args:
        message: Human-readable description of the failure including the
            bad value and what was expected where applicable.
    """


class ConfigurationError(PhiScanError):
    """Raised when a configuration file is missing, malformed, or contains
    an invalid value.

    Args:
        message: Description of the invalid configuration including the
            offending key, the bad value, and what was expected.
    """


class TraversalError(PhiScanError):
    """Raised when the file-system or git traversal cannot proceed.

    Covers unreadable root paths, attempts to scan outside a git repository
    when a git operation is required, and invalid diff references.

    Args:
        message: Description of the traversal failure including the path
            or git ref that caused it.
    """


class AuditLogError(PhiScanError):
    """Raised when the SQLite audit log cannot be read from or written to.

    Args:
        message: Description of the failure including the database path
            and the underlying cause.
    """


class PhiDetectionError(PhiScanError):
    """Raised when a detection layer produces an internally inconsistent finding.

    This is a bug in a detection layer, not a user-facing error. Examples include
    a confidence score outside [0.0, 1.0] or a malformed value hash.

    Args:
        message: Description of the invariant that was violated, including the
            bad value and the expected range or format.
    """


class MissingOptionalDependencyError(PhiScanError):
    """Raised when an optional dependency required for a feature is not installed.

    The caller catches this exception to disable the feature gracefully and log
    a structured warning. Never silence it with a bare except or pass clause —
    re-raise as this type so callers can handle it specifically.

    Args:
        message: Description of the missing dependency including the package name
            and the install command that will resolve it.
    """


class SchemaMigrationError(PhiScanError):
    """Raised when a database schema migration fails or is not possible.

    Args:
        message: Description of the migration failure including the source
            version, the target version, and the reason it could not complete.
    """
