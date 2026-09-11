# MVP release checklist

Status: **not a demo candidate**. This checklist is a release-blocker record.

| Required outcome | Evidence | Status |
| --- | --- | --- |
| Observe | Event and filesystem models, adversarial corpus | Partial: not wired to CLI |
| Profile | Deterministic trusted-run profile tests | Passes in library |
| Generate | Review-only candidate rendering tests | Passes in library |
| Dry-run | Compiled-policy verdict parity tests | Passes in library |
| Enforce | Native arm64 BPF LSM/cgroup/seccomp hook probes | Partial: no live policy map/CLI path |
| Verify | SHA-256 audit-chain and Python verifier | Partial: no live event emission |

The host-safe suite, policy fixtures, adversarial corpus, and native arm64 hook
probe pass. The x86_64 runtime cell is unsupported. The performance artifact
keeps the <2% gate open because live observe, dry-run, enforce, and audit modes
are not measured.

No tag is permitted until a clean supported Linux environment demonstrates the
complete `observe → profile → generate → dry-run → enforce → verify` flow and
retains reproducible demo and benchmark artifacts. Open blockers are runtime
wiring and matrix cells. No deferred product features are included.
