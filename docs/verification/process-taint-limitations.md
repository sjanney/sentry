# Process-tree taint model and limitations

The bounded process tracker applies monotonic `secret` and `untrusted_input`
taint before its caller obtains the egress value. Taint inherits at fork and
persists across exec; exit removes the keyed process identity and prevents PID
reuse from inheriting prior state. Unit tests cover the transition, fork/exec
inheritance, and cleanup behavior.

This is userspace model evidence. It does not prove atomic kernel ordering
between a protected read and `connect`, thread races, a previously connected
socket, or byte-level information flow. The runtime must not claim those
guarantees until BPF state, hook ordering, and adversarial kernel-matrix tests
demonstrate them. The intentionally conservative process-level taint can
overblock unrelated egress from the same process; no quantitative overblocking
measurement is available yet.
