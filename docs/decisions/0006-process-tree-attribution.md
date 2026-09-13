# Process-tree attribution and coverage

Status: accepted

Sentry identifies a process by `(tgid, start_time_ns)`, not PID alone. An exec
creates a record; fork inherits run ID and coverage; exit removes the exact
identity. That avoids carrying state into a reused PID. Reparenting changes
only the parent relationship and never upgrades a process’s inherited coverage.

Launch-mode roots and their observed children have `Launch` coverage. Attach-
mode roots and children have `AttachPartial` coverage because reads or network
activity before attachment were not observed. Policies that require complete
secret-to-egress guarantees must reject `AttachPartial` domains.

Attribution state is bounded. Reaching the configured capacity is an explicit
error, not eviction of a live process. Unit tests cover exec/fork/exit,
short-lived children, PID reuse, reparenting, attach coverage, unknown parents,
and capacity exhaustion.

The Linux observation probe emits ABI v1 exec, fork, and exit records and the
daemon ingests each kind under a non-sensitive event-class label. This is not
yet a bridge into the tracker: the sched fork tracepoint exposes a child task
ID but the current 48-byte ABI carries neither the child's start time nor a
trustworthy child TGID for thread clones. Fork records therefore set TGID to
zero. Treating task IDs alone as tracker identities would reintroduce PID-reuse
errors, so live tracker attribution remains open until the kernel collector can
provide the full `(tgid, start_time_ns)` key.
