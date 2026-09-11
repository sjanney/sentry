# Versioned events and loss-aware ingestion

Status: accepted

Sentry event ABI v1 uses a fixed 48-byte little-endian header. Each event has a
version, kind, declared total size, daemon-assigned local sequence, monotonic
kernel timestamp, run ID, TGID/TID, and parent TGID. The declared size must be
between 48 bytes and 4096 bytes; malformed, unknown-version, and unknown-kind
events are rejected explicitly.

The BPF ring buffer is bounded to 1 MiB for the MVP. Userspace ingestion is
also bounded and never evicts earlier accepted events to make room. A full
queue produces a `Dropped` result with a monotonically increasing loss count;
the audit subsystem will later persist that evidence.

Credential-shaped paths and values are represented by a class such as
`credential`, not their raw value. Only approved non-sensitive targets enter
the normalized local schema. Redaction happens before the event enters the
userspace queue.

The ABI layout and malformed-input behavior are unit tested in `sentry-types`.
The bounded queue, loss accounting, assigned sequence, and redaction behavior
are unit tested in `sentry-daemon`.
