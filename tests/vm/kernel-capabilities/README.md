# Kernel capability preflight

Run from the repository root:

```sh
bash tests/vm/kernel-capabilities/probe-linux-container.sh
```

Set `SENTRY_EXPECT_ARCH` (for example, `SENTRY_EXPECT_ARCH=aarch64`) to make a
matrix run fail closed when Docker exposes a different kernel architecture.

The probe reports BTF, cgroup-v2, seccomp mode, and the active-LSM preflight
state from a privileged disposable Docker Linux container. It deliberately
does not call a preflight result proof of enforcement. It also proves a
minimal launch-time seccomp filter can deny `getppid` in its own disposable
process. It also verifies the non-LSM seccomp fallback denies new `socket(2)`
calls in its own disposable process. It then loads a BPF LSM `file_open`
program and verifies it denies a
configured synthetic inode while allowing a separate workspace fixture; direct,
hard-link, and symlink opens of the protected inode must all fail. The loader
uses the Docker Linux VM's PID namespace because the BPF helper reports VM PIDs
rather than container PID-namespace values. The network attachment test in the
probe loads cgroup `connect4` and `connect6` programs and verifies they reject
synthetic direct-IP IPv4/IPv6 TCP and UDP connections only for the same loader
process. The broader CO-RE,
verifier-diagnostic, and x86_64 checks in the decision record remain required.
Inherited descriptors and mmap are explicitly unsupported by this `file_open`
probe; see `docs/verification/filesystem-enforcement-limitations.md`.
Pre-existing and inherited sockets plus DNS, rebinding, and proxy attribution
are unsupported by the egress probe; see
`docs/verification/egress-enforcement-limitations.md`.
The fallback subset and release-matrix gap are documented in
`docs/verification/non-lsm-fallback.md`.
