# Linux toolchain spike

`tracepoint-ringbuf.bpf.c` is the smallest shared runtime probe: a GPL BPF
tracepoint program reserves an event in a ring buffer. `aya-loader` loads that
object through Aya and attaches it; `libbpf-rs-loader` does the same through
libbpf-rs. They establish that the target kernel accepts a ring-buffer map and
exec, fork, and exit tracepoint attachment through each userspace API, trigger
a fresh child process, and consume all three fixed-size lifecycle events. Each
event is the exact 48-byte `sentry_types::EventHeader` ABI v1 and both loaders
strictly decode its kind and identity fields before passing the probe.

Exec and exit records contain the current TGID and TID. The fork tracepoint
provides the child task ID but not a trustworthy child TGID or start time, so
fork records set TGID to zero and carry the parent TGID plus child task ID.
These records are observation evidence only. They are not applied to the
PID-reuse-safe process tracker until a start-time identity is available. The
daemon assigns local sequences and redacted event-class labels; run attribution
also remains userspace work. The probe does not read files, make network
connections, enforce policy, or keep links after the container exits.

The probe prints both `kernel` and `arch` so each result is attributable to an
explicit Linux architecture rather than inferred from the calling host.

Run the native Linux architecture check from the repository root:

```sh
bash tests/vm/toolchain-spike/run-linux-container-probe.sh
```

Set `SENTRY_EXPECT_ARCH` (for example, `SENTRY_EXPECT_ARCH=aarch64`) when a
matrix job must fail closed if Docker selects a different kernel architecture.

The runner uses `rust:1.92-bookworm` so the Aya check satisfies Aya 0.14's
minimum supported Rust version. It installs only the BPF compiler and loader
packages needed inside its disposable container.

The container is privileged only so the disposable Docker Linux VM can load
and attach a BPF program. The checkout is mounted read-only, and loader links
are released when the container exits. The command is an environment capability
check, not the final Aya or libbpf-rs acceptance suite; the decision record
lists the remaining architecture and enforcement probes.
