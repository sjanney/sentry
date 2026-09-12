# Kernel capability matrix and non-LSM fallback

Status: proposed

## Decision

Sentry discovers kernel capabilities at daemon startup and reports the active
enforcement tier in every policy result and audit record. A missing capability
never causes a policy to be silently broadened or a protection claim to remain
enabled.

The CLI preflight reports whether BTF is readable, `bpf` is active in the LSM
list, and cgroup v2 exposes its controllers. These are discovery facts only:
the daemon must still load and attach each selected program before it can claim
the corresponding enforcement tier.

File-operation denial requires a verified BPF LSM attachment. Network egress
denial requires a verified cgroup-v2 BPF attachment. For launch-managed
agents, seccomp-BPF is the mandatory non-LSM fallback for syscall-level
restrictions. It cannot express pathname-based file policy, so it must never
be represented as a substitute for BPF LSM file denial. A readable BTF blob is
a prerequisite for the CO-RE-based sensor object. The daemon must test the
program family it intends to use; the presence of a configuration file or LSM
name alone is evidence for preflight only.

## Startup capability matrix

| Capability | Startup evidence | Enables | Behavior when unavailable |
| --- | --- | --- | --- |
| BTF | `/sys/kernel/btf/vmlinux` is readable | CO-RE sensor loading | Do not load the CO-RE sensor; report the host unsupported for this MVP. |
| Process observation | tracepoint + ring-buffer object loads and attaches | Observe and Profile | Do not claim process observation or profile completeness. |
| BPF LSM | `bpf` is listed in active LSMs and the selected LSM program loads and attaches | File-access enforcement | Reject file-deny rules. Preserve only observation and independently verified network controls. |
| cgroup v2 | `cgroup.controllers` exists and the selected cgroup program attaches to the target cgroup | Egress enforcement | Reject egress-deny rules. Do not substitute DNS, proxy, or userspace enforcement. |
| seccomp-BPF | a synthetic filter installs before agent exec and blocks its target syscall | Launch-time syscall restrictions | Do not claim syscall restriction for attach-mode agents or when the filter cannot install. |
| Verifier diagnostics | intentionally invalid object produces retained verifier output | actionable operator failure | Keep the host usable only for successful policies; surface an explicit diagnostic limitation. |

## Enforcement tiers

| Tier | Required verified capabilities | Permitted Sentry behavior |
| --- | --- | --- |
| Unsupported | BTF or process observation missing | Installation may inspect and report; it must not present a protected agent. |
| Observe | BTF and process observation | Emit runtime events and build profiles. No deny claim. |
| Launch constrain | Observe plus verified seccomp-BPF installed before agent exec | Apply only the documented syscall restrictions. No pathname or inherited-FD protection claim. |
| Network enforce | Observe plus cgroup-v2 BPF attachment | Block only policy egress rules attached to the target cgroup. |
| Full enforce | Network enforce plus BPF LSM attachment; seccomp where the launch mode supports it | Enforce file and network policy for the verified scope. |

## Mandatory non-LSM fallback

When the BPF LSM is absent, disabled at boot, rejected by the verifier, or
fails to attach, Sentry must select the strongest independently verified
fallback: **Launch constrain**, **Network enforce**, or both. It must:

1. Mark every file-deny rule as unsupported before activation.
2. Refuse an enforce-mode policy whose required file controls are unsupported.
3. Emit a capability result that names the unavailable BPF LSM attachment.
4. Write the active tier and unsupported rules into the audit chain.
5. Avoid presenting a “full enforcement” or pathname-based credential-
   protection outcome.

The fallback applies only where it can actually be installed. Seccomp-BPF is
available for Sentry-launched agents before `exec`; it is not retroactive for
an arbitrary already-running agent. Cgroup egress controls apply only to the
verified target cgroup. If neither fallback is available, enforce-mode policy
activation must fail rather than degrade to observation.

Dry-run may still report the file operations that the requested rule would
cover, provided the report is labeled simulated and does not claim a kernel
deny occurred.

## Current arm64 Docker evidence

The Docker Desktop Linux arm64 VM is Linux `6.12.54-linuxkit`. It exposes BTF,
cgroup v2, and `capability,bpf` in the active LSM list. The toolchain spike
has separately verified a tracepoint/ring-buffer object through both Aya and
libbpf-rs. The kernel-capability probe also installed a minimal seccomp-BPF
filter in a disposable process and verified that it denied `getppid` with
`EPERM`. It loaded a BPF LSM `file_open` program that denied a synthetic file
with `EACCES`, and attached a cgroup `connect4` program that denied a synthetic
loopback connection with `EPERM`. This is runtime evidence that the individual
hook mechanisms are available on this arm64 Docker VM. It does not establish
Sentry's Full-enforce tier because the daemon has not yet loaded these programs
for an agent process.

## Open acceptance evidence

- Exercise the same startup path on an LSM-disabled kernel and confirm file
  policy rejection plus the correct lower enforcement tier.
- Repeat the matrix on a real x86_64 BTF-enabled kernel.
