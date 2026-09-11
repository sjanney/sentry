# Sentry

Sentry is a Linux runtime least-privilege sensor for AI-agent processes. It is
Apache-2.0 licensed and currently an MVP foundation: the policy, evidence,
kernel capability probes, and safety contracts are implemented, while live
CLI-to-kernel enforcement wiring remains a release blocker.

## Three-minute local walkthrough

On Linux with Rust 1.92:

```sh
git clone https://github.com/sjanney/sentry.git
cd sentry
cargo build --release -p sentry-cli
target/release/sentry capabilities
```

The binary reports the current capability limitations. `sentry run -- COMMAND`
preserves command exit status and signals. `sentry observe --audit-log LOG --
COMMAND` adds redacted command start/outcome audit records, which can be checked
with `sentry audit verify LOG`, on a supported Linux host. `attach PID` is intentionally unavailable until runtime
process attachment is integrated.

Use `sentry generate --run-id demo-1 --workspace "$PWD" --domain
api.example.test` to render a review-only candidate from one explicitly supplied
complete trusted observation. It does not activate policy.

Use `sentry dry-run --allow-domain api.example.test --domain api.example.test
--secret` to evaluate the compiled policy and print its hash, matched rule, and
would-deny explanation. It is a local policy-semantic command; it does not
activate kernel enforcement.

Run the host-safe verification suite with `bash scripts/verify.sh`. On a
native arm64 Linux Docker host, run
`bash tests/vm/kernel-capabilities/probe-arm64-container.sh` for the privileged
BPF LSM, cgroup, and seccomp probes. It installs no persistent kernel policy.

## Architecture and policy

The CLI launches an agent command; the daemon model owns process attribution,
event normalization, DNS evidence, redaction, policy lifecycle, and audit
records. `sentry-policy` defines deterministic default-deny, information-flow,
dry-run, candidate, and bounded compilation semantics. The BPF artifacts in
the test matrix prove individual hook capabilities in disposable processes.

Read [policy v0](docs/policy-reference-v0.md),
[information-flow semantics](docs/decisions/0003-information-flow-and-domain-egress-semantics.md),
and [audit contract](docs/verification/audit-log-contract.md) before writing a
policy. Credential classes are SSH keys, cloud credentials, `.env` files,
keyrings, and token caches; audit records retain a class only, never secret
content or credential paths.

## Threat model and support

Sentry is designed to contain agent-triggered credential reads and new outbound
connections, including indirect prompt-injection attempts. It does not claim
byte-level information-flow tracking, pre-existing or inherited socket control,
inherited descriptors, mmap coverage, proxy attribution, encrypted-DNS
attribution, or domain proof from TLS SNI/HTTP Host.

| Target | Primary hook evidence | Fallback | Status |
| --- | --- | --- | --- |
| Native arm64 Linux | BPF LSM `file_open`; cgroup IPv4/IPv6 TCP/UDP | seccomp socket deny | Probe passes |
| Native x86_64 Linux | Not yet run | Not yet run | Unsupported |
| macOS/Windows | None | None | Unsupported |

The fallback supports only launch-time default-deny egress with no allowed
network destinations. It cannot attach to a running process.

## Install, uninstall, and recovery

Build with `cargo build --release -p sentry-cli`; copy `target/release/sentry`
to a directory in `PATH`. Remove that binary to uninstall. Today there is no
installer, background service, persistent BPF pin, or configuration state.

The eventual primary path requires Linux capabilities sufficient to load the
declared BPF programs and attach them to the target cgroup; the exact minimal
capability set is a release-matrix item. The seccomp fallback requires only a
new child process and `no_new_privs`.

In enforce mode, the lifecycle model refuses new runs after daemon death,
event loss, audit failure, disk full, map exhaustion, or shutdown. Operators
must terminate or isolate an affected process through its supervisor, fix the
fault, and restart a healthy runtime. No current command exposes environment
variables or file contents in audit output; future event wiring must preserve
that redaction boundary.

See the [security matrix](docs/verification/security-matrix.md),
[failure lifecycle](docs/verification/failure-lifecycle.md), and
[real-agent protocol](docs/verification/real-agent-exfiltration-protocol.md)
for the remaining release gates.
