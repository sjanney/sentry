# MVP release checklist

Status: **not a demo candidate**. This checklist is a release-blocker record.

| Required outcome | Evidence | Status |
| --- | --- | --- |
| Observe | CLI command audit records, event and filesystem models, adversarial corpus | Partial: no kernel observation wiring |
| Profile | Deterministic trusted-run profile tests | Passes in library |
| Generate | CLI review-only candidate from an explicit trusted observation | Partial: not derived from observed kernel events |
| Dry-run | CLI compiled-policy verdict plus parity tests | Partial: no live kernel-policy map |
| Enforce | Native arm64 BPF LSM/cgroup/seccomp hook probes | Partial: no live policy map/CLI path |
| Verify | CLI SHA-256 audit verification and Python verifier | Partial: no live kernel event emission |

The host-safe suite, policy fixtures, adversarial corpus, and native arm64 hook
probe pass. The native x86_64 probe is implemented but has not yet produced
runtime evidence on an x86_64 kernel. The performance artifact keeps the <2%
gate open because live observe, dry-run, enforce, and audit modes are not
measured.

No tag is permitted until a clean supported Linux environment demonstrates the
complete `observe → profile → generate → dry-run → enforce → verify` flow and
retains reproducible demo and benchmark artifacts. Open blockers are runtime
wiring and matrix cells. No deferred product features are included.

## Current reproducible evidence

- Host-safe checks: `scripts/verify.sh` on commit `beef26e`.
- Native arm64 hook probes: `tests/vm/kernel-capabilities/probe-linux-container.sh`
  on Docker Desktop Linux 6.12.54 (`aarch64`).
- Wrapper benchmark artifact:
  `artifacts/overhead-baseline-linux-docker.json` (schema v1, five warmups,
  20 repetitions, raw samples and p95 deltas).
- GitHub CI is the cross-build and host-safe gate; it does not replace native
  x86_64 or LSM-disabled runtime evidence.
