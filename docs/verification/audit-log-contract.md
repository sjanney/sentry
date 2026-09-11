# Hash-chained audit-log contract

Each newline-delimited v1 audit record has canonical pipe-delimited fields:
sequence, hex-encoded run ID, policy version, policy hash, hex-encoded decision,
optional hex-encoded rule ID, hex-encoded redacted target class, prior SHA-256,
and its SHA-256. The digest covers every field before the final digest field.
Credential paths and contents are never represented; only a target class is
recorded.

The writer fsyncs each append. On restart it discards only an unterminated final
line, treating it as a crash tail; a malformed complete record fails recovery.
Rotation must retain an externally trusted checkpoint containing the prior final
sequence and hash. A verifier supplied that checkpoint detects deletion or
replacement after it. Without an external checkpoint, a truncated tail or full
log rewrite cannot be detected; SHA-256 chaining is tamper evidence, not a
trusted append-only storage system.

SHA-256 comes from the audited RustCrypto `sha2` crate. Tests cover corruption,
reordering, deletion with a checkpoint, and crash-tail recovery. The chain is
not yet fed by live kernel events, so this is audit-format evidence rather than
an end-to-end enforcement audit claim.

`scripts/verify_audit_log.py` is an independent Python verifier for complete
files. It accepts a log path and reports sequence or hash corruption without
using the Rust parser.
