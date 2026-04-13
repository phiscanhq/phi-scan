"""AES-256-GCM encryption for audit findings_json, plus audit-key lifecycle.

This module owns:
  - Audit key filesystem layout (_audit_key_path, _redact_key_path).
  - Key generation (generate_audit_key) and loading (_load_audit_key).
  - Symmetric encryption/decryption of findings_json
    (_encrypt_findings_json / _decrypt_findings_json).
  - The PHI-field sentinel (_assert_no_raw_phi_fields) applied at the
    encryption boundary as defence in depth.

Nothing in this module performs hash-chain logic or SQL writes. It is safe
to import from any audit submodule with no circular dependency.
"""

from __future__ import annotations

import base64
import errno
import os
from pathlib import Path

from phi_scan.constants import AUDIT_ENCRYPTION_PREFIX, AUDIT_KEY_FILENAME
from phi_scan.exceptions import AuditKeyMissingError, AuditLogError, PhiDetectionError

# ---------------------------------------------------------------------------
# Error message templates
# ---------------------------------------------------------------------------

_ENCRYPTION_KEY_MISSING_ERROR: str = (
    "Audit encryption key not found at {redacted_key_path} — refusing to store findings_json "
    "as plaintext. Run 'phi-scan setup' to generate the audit key."
)
_KEY_FILE_EXISTS_ERROR: str = (
    "Audit key already exists at {redacted_key_path} — "
    "refusing to overwrite. Delete the file manually to regenerate."
)
_KEY_WRITE_ERROR: str = "Cannot write audit key to {redacted_key_path}: {io_strerror}"
_KEY_READ_ERROR: str = "Cannot read audit key from {redacted_key_path}: {io_strerror}"

# ---------------------------------------------------------------------------
# Crypto constants
# ---------------------------------------------------------------------------

# O_BINARY is Windows-only. On POSIX it is 0 (no-op). Without it, os.open on
# Windows opens in text mode and translates \n → \r\n, corrupting binary key data.
_O_BINARY: int = getattr(os, "O_BINARY", 0)

_AES_GCM_KEY_BYTES: int = 32  # 256-bit key
_AES_GCM_NONCE_BYTES: int = 12  # 96-bit nonce (GCM standard)
_AES_GCM_TAG_BYTES: int = 16  # 128-bit authentication tag
# Ciphertext layout: nonce(12) || ciphertext || tag(16), base64-encoded,
# prefixed with AUDIT_ENCRYPTION_PREFIX.
_AES_GCM_NONCE_END: int = _AES_GCM_NONCE_BYTES
_AES_GCM_TAG_START: int = -_AES_GCM_TAG_BYTES  # slice from end

# ScanFinding field names that carry raw or PHI-adjacent values and must NEVER
# appear as JSON keys in a serialised findings record stored to the audit DB.
# _assert_no_raw_phi_fields() checks the output of _serialize_findings() against
# this set before encryption as a defence-in-depth guard.
#   "file_path"        — raw path; must be stored only as file_path_hash
#   "code_context"     — source line (even though [REDACTED] replaces the match,
#                        the surrounding tokens may still be PHI-adjacent)
#   "remediation_hint" — free-text hint that may embed partial PHI
_FORBIDDEN_AUDIT_FIELD_NAMES: frozenset[str] = frozenset(
    {"file_path", "code_context", "remediation_hint"}
)


# ---------------------------------------------------------------------------
# Key path helpers
# ---------------------------------------------------------------------------


def _audit_key_path(key_dir: Path) -> Path:
    """Return the Path to the audit key file within key_dir."""
    return key_dir / AUDIT_KEY_FILENAME


def _redact_key_path(key_path: Path) -> str:
    """Return a safe representation of key_path that omits the directory.

    The directory component is PHI-revealing when the database is placed in a
    patient-data path. Only the filename is included — it is the constant
    AUDIT_KEY_FILENAME and carries no PHI.
    """
    return f"<redacted>/{key_path.name}"


# ---------------------------------------------------------------------------
# PHI sentinel
# ---------------------------------------------------------------------------


def _assert_no_raw_phi_fields(findings_json: str) -> None:
    """Raise PhiDetectionError if findings_json contains a known PHI field name.

    Defence-in-depth guard applied in _serialize_and_encrypt before encryption.
    """
    for field_name in _FORBIDDEN_AUDIT_FIELD_NAMES:
        if f'"{field_name}"' in findings_json:
            raise PhiDetectionError(
                f"_serialize_findings produced findings_json containing the raw PHI "
                f"field '{field_name}' — refusing to encrypt. This is a serialisation "
                f"bug; file a security issue."
            )


# ---------------------------------------------------------------------------
# Key load / generate
# ---------------------------------------------------------------------------


def _load_audit_key(key_dir: Path) -> bytearray | None:
    """Load the AES-256-GCM audit key from the key file.

    Returns None if the key file does not exist (encryption not configured).
    Raises AuditLogError if the file exists but cannot be read — silent
    degradation to plaintext after key setup would be a security failure.
    """
    key_path = _audit_key_path(key_dir)
    if not key_path.exists():
        return None
    try:
        return bytearray(key_path.read_bytes())
    except OSError as io_error:
        raise AuditLogError(
            _KEY_READ_ERROR.format(
                redacted_key_path=_redact_key_path(key_path),
                io_strerror=io_error.strerror or f"errno {io_error.errno}",
            )
        ) from io_error


def generate_audit_key(database_path: Path) -> Path:
    """Generate a new AES-256-GCM audit key and write it to the key file.

    The key file is created in the same directory as database_path with mode
    0o600. Raises AuditLogError if the file already exists — never silently
    overwrites an existing key.
    """
    key_path = _audit_key_path(database_path.parent)
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_bytes = os.urandom(_AES_GCM_KEY_BYTES)
        # O_CREAT | O_EXCL atomically creates key_path only if it does not already
        # exist — raises EEXIST if present, eliminating the TOCTOU window.
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        try:
            os.write(fd, key_bytes)
        finally:
            os.close(fd)
    except OSError as io_error:
        if io_error.errno == errno.EEXIST:
            raise AuditLogError(
                _KEY_FILE_EXISTS_ERROR.format(redacted_key_path=_redact_key_path(key_path))
            ) from io_error
        raise AuditLogError(
            _KEY_WRITE_ERROR.format(
                redacted_key_path=_redact_key_path(key_path),
                io_strerror=io_error.strerror or f"errno {io_error.errno}",
            )
        ) from io_error
    return key_path


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


def _encrypt_findings_json(plaintext: str, key: bytearray) -> str:
    """Encrypt a findings JSON string with AES-256-GCM.

    The output is: AUDIT_ENCRYPTION_PREFIX + base64(nonce + ciphertext + tag).
    Requires the ``cryptography`` package.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_AES_GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return AUDIT_ENCRYPTION_PREFIX + base64.b64encode(nonce + ciphertext_with_tag).decode()


def _decrypt_findings_json(encrypted: str, key: bytes) -> str:
    """Decrypt an encrypted findings JSON string produced by _encrypt_findings_json.

    Raises AuditLogError if decryption fails (wrong key or tampered ciphertext).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(encrypted[len(AUDIT_ENCRYPTION_PREFIX) :])
    nonce = raw[:_AES_GCM_NONCE_END]
    ciphertext_with_tag = raw[_AES_GCM_NONCE_END:]
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None).decode()
    except (InvalidTag, ValueError) as crypto_error:
        raise AuditLogError(
            f"Audit findings_json decryption failed — the key may be wrong "
            f"or the ciphertext has been tampered with: {crypto_error}"
        ) from crypto_error


def _serialize_and_encrypt(findings_json: str, key_dir: Path) -> str:
    """Encrypt findings_json with AES-256-GCM using the audit key in key_dir.

    Hard-fails if the key is absent — plaintext fallback is not permitted.
    """
    _assert_no_raw_phi_fields(findings_json)
    key = _load_audit_key(key_dir)
    if key is None:
        raise AuditKeyMissingError(
            _ENCRYPTION_KEY_MISSING_ERROR.format(
                redacted_key_path=_redact_key_path(_audit_key_path(key_dir))
            )
        )
    try:
        return _encrypt_findings_json(findings_json, key)
    finally:
        key[:] = bytes(len(key))
