# Security matrix execution contract

Run `bash scripts/run_security_matrix.sh` on each native Linux target. It writes
machine, kernel, primary BPF LSM/cgroup, and seccomp fallback output to an
artifact. The same privileged probe supports native arm64 and x86_64 kernels;
each cell must retain its own evidence. Cross-build output is not runtime
evidence for either architecture.

The matrix result must also record launch and attach behavior plus the
adversarial and legitimate corpus runs after live Sentry wiring exists. Those
cells are presently unsupported, not passing, because the runtime does not yet
connect CLI launch, policy maps, ingestion, and audit records.
