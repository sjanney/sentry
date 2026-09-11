# Linux toolchain spike

`tracepoint-ringbuf.bpf.c` is the smallest shared runtime probe: a GPL BPF
tracepoint program reserves an event in a ring buffer. `aya-loader` loads that
object through Aya and attaches it; `libbpf-rs-loader` does the same through
libbpf-rs. They establish that the target kernel accepts a ring-buffer map and
tracepoint attachment through each userspace API, trigger a fresh `exec`, and
consume one fixed-size event. They do not read files, make network connections,
or keep links after the container exits.

Run the native Linux architecture check from the repository root:

```sh
bash tests/vm/toolchain-spike/run-linux-container-probe.sh
```

The runner uses `rust:1.92-bookworm` so the Aya check satisfies Aya 0.14's
minimum supported Rust version. It installs only the BPF compiler and loader
packages needed inside its disposable container.

The container is privileged only so the disposable Docker Linux VM can load
and attach a BPF program. The checkout is mounted read-only, and loader links
are released when the container exits. The command is an environment capability
check, not the final Aya or libbpf-rs acceptance suite; the decision record
lists the remaining architecture and enforcement probes.
