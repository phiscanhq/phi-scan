# `phi_scan/audit.py` decomposition plan

**Status:** PLANNED — deferred from the pristine-closure pass.
**Module size:** 1437 lines, ~39 functions, SQLite + HMAC chain + AES-GCM envelope.

## Why deferred

`audit.py` carries three tightly coupled security invariants that must not
drift during a refactor:

1. **Hash chain determinism.** `_row_content_for_hashing`,
   `_compute_row_chain_hash`, `_get_previous_chain_hash`,
   `_attach_chain_hash` form a single chain protocol. A field-order change
   or missing call site silently breaks verification for every historical
   row.
2. **AES-GCM envelope format.** `_serialize_and_encrypt`,
   `_encrypt_findings_json`, `_decrypt_findings_json` share a binary
   layout; moving them into separate modules without byte-exact tests can
   break decryption of pre-existing audit databases in the field.
3. **No raw PHI in audit rows.** `_assert_no_raw_phi_fields` is a sentinel
   that must execute in the same module as row construction — moving it
   across a module boundary weakens the "fail before write" guarantee.

## Target layout

```
phi_scan/audit/
    __init__.py          # re-export the existing public surface
    writer.py            # insert_scan_event, create_audit_schema,
                         # ensure_current_schema, migrate_schema,
                         # query_recent_scans, get_last_scan,
                         # get_schema_version, purge_expired_audit_rows,
                         # generate_audit_key, verify_audit_chain
    hash_chain.py        # _row_content_for_hashing, _hmac_sha256,
                         # _get_previous_chain_hash, _attach_chain_hash,
                         # _compute_row_chain_hash, _verify_chain_rows,
                         # ChainVerifyResult
    crypto.py            # _encrypt_findings_json, _decrypt_findings_json,
                         # _serialize_and_encrypt, _load_audit_key,
                         # _audit_key_path, _redact_key_path
    _shared.py           # _open_database, _reject_symlink_database_path,
                         # _ensure_database_parent_exists,
                         # _get_current_timestamp, git-identity helpers,
                         # _assert_no_raw_phi_fields, _build_scan_event_row
```

## Recommended extraction order

1. **`_shared.py` first** — contains only leaf helpers with no crypto or
   chain invariants. Zero risk.
2. **`crypto.py` second** — has clear module boundary; its contract is
   "bytes in, bytes out". Verify with a round-trip test on an existing
   audit database before merging.
3. **`hash_chain.py` third** — must be extracted as a single atomic commit.
   Run `verify_audit_chain` against a pre-existing database fixture before
   and after; bytes-for-bytes equality of the computed chain hashes is the
   gate.
4. **`writer.py` last** — once its dependencies are extracted, `writer.py`
   is what remains. Largest surface, smallest logic change.

## Shim strategy

`phi_scan/audit.py` becomes a top-level re-export shim that preserves every
public name currently imported by callers:

```python
from phi_scan.audit.writer import (  # noqa: F401
    ChainVerifyResult,
    create_audit_schema,
    ensure_current_schema,
    generate_audit_key,
    get_last_scan,
    get_schema_version,
    insert_scan_event,
    migrate_schema,
    purge_expired_audit_rows,
    query_recent_scans,
    verify_audit_chain,
)
```

## Hard gates before shipping

- [ ] A regression fixture: an audit database written by the current
      monolithic `audit.py` must decrypt, verify, and produce identical
      chain hashes under the refactored package.
- [ ] `tests/test_audit*.py` passes unchanged.
- [ ] `tests/test_audit_encryption.py` passes unchanged.
- [ ] `verify_audit_chain` called against 10+ pre-existing rows returns
      `ChainVerifyResult(is_valid=True, ...)` byte-identical to the
      pre-refactor output.
- [ ] No new module-level side effects at import time.
- [ ] PHI sentinel test (`_assert_no_raw_phi_fields`) covers a row that
      crosses every module boundary in the new layout.

## Non-goals for the extraction pass

- Do not change the SQLite schema.
- Do not change the HMAC or AES-GCM parameters.
- Do not change the envelope format or chain-hash input serialisation.
- Do not rename any public function. The shim must preserve every
  existing import.
