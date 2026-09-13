# Linux CI and VM matrix

## CI checks

`.github/workflows/ci.yml` runs on every push and pull request:

- formatting, unit tests, Clippy with warnings denied, and the information-flow
  reference cases;
- Linux compilation of the shared BPF object and the Aya/libbpf-rs userspace
  loaders; and
- an `aarch64-unknown-linux-gnu` Rust cross-build.

The CI compilation jobs do not claim BPF runtime coverage. A container or QEMU
userland architecture is not a substitute for the matching kernel architecture.

## Workspace boundaries and dependencies

The approved workspace keeps the shared ABI in `sentry-types`, policy parsing
and bounded compilation in `sentry-policy`, process and audit state in
`sentry-daemon`, the command surface in `sentry-cli`, and kernel-facing ABI
helpers in `sentry-ebpf`. The daemon and policy crates use `serde` and
`serde_json` for the versioned policy and audit formats; `sha2` provides the
stable policy and audit digests. All other workspace dependencies are local
crate edges so the ABI has one source of truth.

Aya remains the preferred kernel implementation candidate because it preserves
Rust on both sides of the boundary. `libbpf-rs` is retained only in the spike
as the rejected alternative for the kernel-side implementation: its loader is
Rust, but its CO-RE program source is C. No additional runtime framework or
license-bearing dependency is part of the approved scaffold.

## Real arm64 runtime evidence

Run on a Linux arm64 Docker host, including Docker Desktop’s arm64 Linux VM:

```sh
bash scripts/verify-linux-arm64-runtime.sh
```

This executes two independent privileged integration checks:

1. `tests/vm/toolchain-spike/run-linux-container-probe.sh` compiles the shared
   ring-buffer object, then loads and attaches it through Aya and libbpf-rs.
   It also starts `sentryd capture-exec`, executes `/bin/true` after attachment,
   and requires at least one event to reach the daemon's bounded ingestor.
2. `tests/vm/kernel-capabilities/probe-linux-container.sh` verifies seccomp
   self-denial, BPF-LSM file denial, and cgroup IPv4/IPv6 egress denial using
   the native kernel architecture's BPF target.

The recorded local evidence is Linux `6.12.54-linuxkit` on arm64 with BTF,
cgroup v2, and `capability,bpf` active. Both integration commands passed on
2026-09-12.

## Real x86_64 runtime requirement

Run `bash scripts/run_security_matrix.sh` on a real x86_64 Linux VM with BTF
and BPF LSM enabled. Record its kernel release, active LSM list, BTF source,
and output in this document. Do not count Docker `--platform linux/amd64` on an
arm64 host as x86_64 kernel validation; it is userspace emulation over an arm64
kernel.
