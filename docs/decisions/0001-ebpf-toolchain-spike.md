# eBPF toolchain spike: Aya vs libbpf-rs

Status: in progress

## Decision to make

Select the eBPF implementation toolchain for Sentry's Linux sensor. The
selection must support CO-RE/BTF loading, BPF LSM enforcement, cgroup egress
controls, ring-buffer event transport, and Linux x86_64 plus arm64.

The selected toolchain will be recorded only after the executable probes below
run on supported Linux kernels. API availability and a host-side compilation do
not settle this decision.

## Candidates

| Candidate | Kernel-side language | Userspace loader | Current version checked | Licensing |
| --- | --- | --- | --- | --- |
| Aya | Rust | Rust | `aya` 0.14.0 | MIT OR Apache-2.0 |
| libbpf-rs | C BPF source | Rust | `libbpf-rs` 0.27.1 | LGPL-2.1-only OR BSD-2-Clause |

Aya keeps both sides in Rust and exposes LSM, LSM-cgroup, cgroup-skb, and ring
buffer program support. libbpf-rs is a Rust userspace wrapper around libbpf;
its documented CO-RE workflow compiles `.bpf.c` source and generates Rust
skeleton bindings. Using it would therefore be an explicit exception to the
all-Rust kernel-side direction, not an implementation detail.

## Acceptance probes

For each candidate, the same intentionally small test object must:

1. Compile a process-lifecycle tracepoint and emit a fixed event through a BPF
   ring buffer.
2. Load and attach on an x86_64 Linux kernel with BTF; userspace must consume
   and validate the event schema.
3. Load and attach on an arm64 Linux kernel with BTF; userspace must consume
   and validate the same event schema.
4. Load a BPF LSM program at an available file-access hook, deny a synthetic
   protected-file operation, and retain verifier diagnostics on failure.
5. Attach a cgroup egress program and deny a synthetic outbound connection.
6. Confirm CO-RE relocation across the two selected kernel versions, including
   the object, kernel version, BTF source, attach result, and verifier log.
7. Exercise intentional verifier failure and record whether diagnostics are
   actionable enough for a security product workflow.

The probes use only synthetic files, a local test listener, and disposable VM
or container workloads. No user credentials or external destinations are part
of the test.

## Evidence gathered so far

The development host is macOS arm64 (`Darwin 25.5.0`), so it cannot load Linux
BPF programs or provide kernel verifier evidence. It has Rust 1.92.0 and
resolves the two candidate crates.

On 2026-09-11, the Docker Desktop Linux arm64 VM provided a usable baseline:
Linux `6.12.54-linuxkit`, BTF, cgroup v2, and an active BPF LSM
(`capability,bpf`). The reproducible container probe in
`tests/vm/toolchain-spike/` compiles a GPL ring-buffer tracepoint program and
uses Aya 0.14.0 with Rust 1.92.0 to load and attach it to
`sched_process_exec`, trigger `/bin/true`, and consume the resulting fixed-size
ring-buffer event. That Aya arm64 sub-probe passed.

The identical object also loaded, attached, triggered, and consumed the event
through libbpf-rs 0.27.1 in the same arm64 VM. Its loader necessarily consumes
a Clang-produced C BPF object;
therefore libbpf-rs preserves a Rust userspace loader, but it does not preserve
Rust kernel programs.

This is the first runtime evidence for both toolchains, but it does **not**
establish the toolchain decision: CO-RE relocation, toolchain-specific cgroup
egress and file-enforcement loading, verifier diagnostics, and x86_64
portability remain untested.

The documented Aya API includes `Lsm`, `LsmCgroup`, `CgroupSkb`, and BTF-backed
loading. Its LSM documentation requires a Linux kernel with `CONFIG_BPF_LSM=y`
and `CONFIG_DEBUG_INFO_BTF=y`, the BPF LSM enabled at boot, and a minimum
kernel version of 5.7. The documented libbpf-rs workflow provides CO-RE via
`libbpf-cargo`, a generated skeleton, and ring-buffer support. These are
capability indications, not acceptance evidence.

## Provisional direction

Aya is the current leading candidate because it preserves the all-Rust
architecture and its public API covers the required program families. Do not
commit to it until the Linux probes show correct load/attach behavior, usable
diagnostics, and portable CO-RE behavior. If Aya fails a required probe,
evaluate libbpf-rs against the identical acceptance suite before changing the
architecture.

## Required next environment

Run the probes in two disposable Linux environments:

| Architecture | Kernel/configuration | Required checks |
| --- | --- | --- |
| x86_64 | mainstream BTF-enabled kernel with BPF LSM enabled | all seven probes |
| arm64 | mainstream BTF-enabled kernel with BPF LSM enabled | all seven probes |

The kernel-fallback spike will add an LSM-disabled configuration and define the
policy subset that can remain enforceable there.

## Sources

- Aya program API: <https://docs.rs/aya/0.14.0/aya/programs/>
- Aya LSM macro requirements: <https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.lsm.html>
- Aya project overview: <https://github.com/aya-rs/aya>
- libbpf-rs workflow: <https://docs.rs/libbpf-rs/0.27.1/libbpf_rs/>
- Linux BPF documentation: <https://docs.kernel.org/bpf/>
