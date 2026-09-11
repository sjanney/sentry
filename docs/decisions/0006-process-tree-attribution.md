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
