# Versioned events and loss-aware ingestion

Status: accepted

Sentry event ABI v1 uses a fixed 48-byte little-endian header. Each event has a
version, kind, declared total size, daemon-assigned local sequence, monotonic
kernel timestamp, run ID, TGID/TID, and parent TGID. The declared size must be
between 48 bytes and 4096 bytes and exactly equal the received record length.
Reserved bytes and flags are zero in v1. Malformed, unknown-version,
unknown-kind, unknown-flag, nonzero-reserved, and length-mismatched events are
rejected explicitly rather than being accepted as a future-compatible record.

The BPF ring buffer is bounded to 1 MiB for the MVP. Userspace ingestion is
also bounded and never evicts earlier accepted events to make room. A full
queue produces a `Dropped` result with a monotonically increasing loss count;
malformed and redaction-rejected records have separate monotonic counters. The
audit subsystem will later persist all of those evidence-quality signals.

Credential-shaped paths and values are represented by a class such as
`credential`, not their raw value. Only approved non-sensitive targets enter
the normalized local schema. Public labels must be non-empty and cannot contain
path separators or control characters. Redaction happens before the event
enters the userspace queue.

The ABI layout and malformed-input behavior are unit tested in `sentry-types`.
The bounded queue, loss accounting, assigned sequence, and redaction behavior
are unit tested in `sentry-daemon`. On Linux, `sentryd capture-exec <object>
[duration-ms]` attaches the shared `capture_exec` tracepoint object through Aya
and drains its `events` ring buffer through that ingestor. Its printed summary
separates accepted records from dropped, malformed, redaction-rejected, and
sequence-exhausted results. This is observation plumbing only; it does not
activate any BPF policy map or enforcement claim.
