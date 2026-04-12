"""Custom exception hierarchy for PhiScan.

All domain errors inherit from PhiScanError so callers can catch the entire
family with a single except clause when broad error handling is appropriate.
Each subclass targets a specific failure domain so callers can also catch
narrowly when they need to distinguish error types.
"""

from __future__ import annotations

__all__ = [
    "AIConfigurationError",
    "AIReviewError",
    "AuditKeyMissingError",
    "AuditLogError",
    "BaselineError",
    "CIIntegrationError",
    "ConfigurationError",
    "FileReadError",
    "MissingOptionalDependencyError",
    "NotificationError",
    "PhiDetectionError",
    "PhiScanError",
    "PhiScanLoggingError",
    "PluginValidationError",
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


class FileReadError(PhiScanError):
    """Raised when a file cannot be read or decoded during scanning.

    Covers both OS-level failures (PermissionError, I/O error) and encoding
    failures (UnicodeDecodeError). Callers catch this to skip the file and
    continue scanning the rest of the targets.

    Args:
        message: Description of the failure including the file path,
            the encoding attempted (where relevant), and the underlying cause.
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


class BaselineError(PhiScanError):
    """Raised when a baseline file operation fails.

    Covers missing, malformed, or schema-mismatched baseline files, as well as
    I/O errors when reading or writing the .phi-scanbaseline file.

    Args:
        message: Description of the failure including the file path and cause.
    """


class AuditLogError(PhiScanError):
    """Raised when the SQLite audit log cannot be read from or written to.

    Args:
        message: Description of the failure including the database path
            and the underlying cause.
    """


class AuditKeyMissingError(AuditLogError):
    """Raised when the audit encryption key file cannot be found.

    This is the expected state for a newly installed instance that has not
    yet had ``phi-scan setup`` run. Callers can catch this subclass to treat
    the missing-key case differently from other audit failures (e.g. log at
    DEBUG rather than WARNING).

    Args:
        message: Description including the expected key path.
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


class PhiScanLoggingError(PhiScanError):
    """Raised when the logging system cannot be configured safely.

    Examples include a log file path that resolves to a symlink, which could
    allow an attacker to redirect log output to an arbitrary file.

    Args:
        message: Description of the unsafe configuration including the path
            and the reason it was rejected.
    """


class NotificationError(PhiScanError):
    """Raised when an email or webhook notification cannot be delivered.

    Notification failures are always best-effort — a ``NotificationError``
    must never prevent a scan result from being reported or an audit record
    from being written. Callers must catch this and log a warning rather than
    re-raising.

    Args:
        message: Description of the delivery failure including the channel
            (email/webhook), the destination, and the underlying cause.
    """


class SchemaMigrationError(PhiScanError):
    """Raised when a database schema migration fails or is not possible.

    Args:
        message: Description of the migration failure including the source
            version, the target version, and the reason it could not complete.
    """


class PluginValidationError(PhiScanError):
    """Raised internally by the plugin loader when a discovered recognizer
    fails Plugin API v1 validation.

    The loader catches every instance before it can reach a scan caller,
    logs the reason at WARNING level, and records the plugin in the
    skipped list of the returned ``PluginRegistry`` so PR-2's
    ``phi-scan plugins list`` command can display the reason. It is
    exported from ``phi_scan.exceptions`` so the loader and its test
    suite can reference it as a normal member of the domain-error
    hierarchy, but scan callers should never see it raised.

    Args:
        message: Description of the validation failure including the
            offending attribute or value and what was expected.
    """


class CIIntegrationError(PhiScanError):
    """Raised when a CI/CD platform API call fails.

    Covers HTTP errors, authentication failures, and CLI tool invocation
    failures across all supported CI/CD platforms. Error messages include
    only the HTTP status code and reason phrase — never the response body,
    which could echo back request content containing finding metadata.

    Args:
        message: Description of the failure including the platform name,
            the operation that failed, and the status code where applicable.
    """


class AIConfigurationError(PhiScanError):
    """Raised when the AI review layer cannot be initialised due to missing
    or invalid configuration.

    Examples include a missing API key when ``ai.enable_ai_review: true`` is
    set, an unrecognised model name whose provider cannot be inferred, or the
    required provider SDK not being installed.

    Args:
        message: Description of the configuration failure including the
            setting name and the resolution (e.g. env var to set or package
            to install).
    """


class AIReviewError(PhiScanError):
    """Raised when an AI provider API call for confidence review fails.

    This is a transient failure — callers must catch it and fall back to the
    local confidence score rather than crashing the scan. Never silence it
    with a bare except or pass clause.

    Args:
        message: Description of the API failure including the finding context
            and the underlying cause (API error type, parse error, etc.).
    """
