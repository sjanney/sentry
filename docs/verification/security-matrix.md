# Security matrix execution contract

Run `bash scripts/run_security_matrix.sh` on each Linux target. It writes the
runner OS/kernel, probe architecture, primary BPF LSM/cgroup, and seccomp
fallback output to an artifact. The privileged probe is parameterized for
arm64 and x86_64 kernels; each cell must retain its own runtime evidence.
Cross-build output is not runtime evidence for either architecture.

The matrix result must also record launch and attach behavior plus the
adversarial and legitimate corpus runs after live Sentry wiring exists. Those
cells are presently unsupported, not passing, because the runtime does not yet
connect CLI launch, policy maps, ingestion, and audit records.
