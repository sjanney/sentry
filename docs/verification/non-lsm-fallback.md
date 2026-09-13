# Non-LSM fallback: seccomp socket-deny subset

The mandatory fallback is a launch-time seccomp filter that denies `socket(2)`
with `EPERM`. It is independent of BPF LSM availability and therefore supports
only a restrictive policy subset: a newly launched process with default-deny
egress and no permitted network destinations. The arm64 kernel probe verifies
the syscall denial in a disposable process.

The CLI exposes this exact subset on Linux:

```sh
sentry enforce --policy examples/seccomp-socket-deny.json -- COMMAND
```

It strictly decodes and validates the bounded fallback policy before starting
the command, installs `no_new_privs` and the seccomp filter, and then replaces
the Sentry process with the command. A successful installation reports
`enforcement_path=seccomp_socket_deny scope=socket(2)_only`; that scope label is
part of the evidence boundary and must not be presented as general network
containment.

Before launch, the fallback must reject filesystem credential controls, domain
or CIDR allowlists, DNS-dependent rules, any policy that permits network
egress, and attach mode. Seccomp cannot revoke a socket opened before filter
installation, control inherited descriptors, block descriptors received over
another channel, or apply to an already-running process. The current filter
does not deny `socketpair(2)`, `accept(2)`, `accept4(2)`, or socket-producing
operations from other kernel interfaces. This subset is intentionally less
capable than LSM plus cgroup enforcement; it denies its declared `socket(2)`
violation rather than claiming equivalent coverage.

The Rust policy layer exposes `validate_seccomp_fallback` as the pre-launch
gate. It accepts only schema version 1 with a nonzero policy version, enforcing
mode, default deny, no destination rules, and no required kernel capabilities;
callers fail before launch on every error. The runtime input is the strict
`PolicySpec` shape shown in `examples/seccomp-socket-deny.json`, rather than the
broader policy-v0 document containing filesystem controls the fallback cannot
represent.

The CLI integration test executes the real filter on Linux and proves a child
process receives `EPERM` from `socket(2)`. The current kernel evidence runs on
an LSM-enabled host because its purpose is to demonstrate the fallback’s
independence from LSM hooks. A release gate still requires the same CLI flow on
a declared host with BPF LSM disabled before the fallback ticket can leave
Backlog.
