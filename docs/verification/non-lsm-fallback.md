# Non-LSM fallback: seccomp socket-deny subset

The mandatory fallback is a launch-time seccomp filter that denies `socket(2)`
with `EPERM`. It is independent of BPF LSM availability and therefore supports
only a restrictive policy subset: a newly launched process with default-deny
egress and no permitted network destinations. The arm64 kernel probe verifies
the syscall denial in a disposable process.

Before launch, the fallback must reject filesystem credential controls, domain
or CIDR allowlists, DNS-dependent rules, any policy that permits network
egress, and attach mode. Seccomp cannot revoke a socket opened before filter
installation, control inherited descriptors, or apply to an already-running
process. This subset is intentionally less capable than LSM plus cgroup
enforcement; it denies its declared violation rather than claiming equivalent
coverage.

The Rust policy layer exposes `validate_seccomp_fallback` as the pre-launch
gate. It accepts only an enforcing, default-deny policy with no destination
rules or required kernel capabilities; callers must fail closed on every error.

The current kernel evidence runs on an LSM-enabled host because its purpose is
to demonstrate the fallback’s independence from LSM hooks. A release gate still
requires the same probe on a declared host with BPF LSM disabled before the
fallback ticket can leave Backlog.
