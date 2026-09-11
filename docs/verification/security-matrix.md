# Security matrix execution contract

Run `bash scripts/run_security_matrix.sh` on each native Linux target. It writes
machine, kernel, primary BPF LSM/cgroup, and seccomp fallback output to an
artifact. The current native arm64 cell runs the full privileged probe. The
x86_64 runtime cell is explicitly unsupported until it has a native BPF compile
and attach probe; the existing cross-build is not evidence for this gate.

The matrix result must also record launch and attach behavior plus the
adversarial and legitimate corpus runs after live Sentry wiring exists. Those
cells are presently unsupported, not passing, because the runtime does not yet
connect CLI launch, policy maps, ingestion, and audit records.
