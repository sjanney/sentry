# Sentry non-TEE Linux deployment profile

Status: documented evidence profile, 2026-09-12

This profile describes Sentry on commodity self-hosted Linux without TDX,
SEV-SNP, an H100 confidential VM, or another hardware root. TRACE v0.2 is the
reference format and governance target; this document does not claim that the
current envelope is TRACE-conformant. TRACE identifies `eat_profile` as
`tag:agentrust-io.com,2026:trace-v0.2` and uses EAT/RATS roles for independent
verification ([TRACE schema](https://trace.agentrust-io.com/docs/schema/),
[TRACE specification](https://github.com/agentrust-io/trace-spec/blob/main/spec/trace-v0.2.md)).

## Claims populated

Sentry can populate an evidence record with the policy identity and mode,
kernel release, architecture, capability fingerprint, enforcement path,
execution-domain/process-tree identity, ordered events and loss count,
filesystem and network decision counts, workflow result, and explicit partial
coverage or unsupported-guarantee flags. The repository artifacts are the
[attestation contract](attestation.md), [audit contract](audit-log-contract.md),
and [security matrix](security-matrix.md).

The `runtime` substitute is descriptive kernel evidence: release, architecture,
BTF/LSM/cgroup availability, and the probe result. It is not a TEE measurement
chain and cannot prove that the host booted trusted software. The shell-side
`tool_transcript` substitute is the ordered Sentry event and audit sequence;
protocol-boundary tool calls remain outside that sequence.

## Claims deliberately omitted

The current profile leaves hardware runtime measurements, silicon-rooted key
attestation, model identity, data classification, and build provenance empty.
It also does not claim complete information-flow tracking, inherited-descriptor
control, proxy or encrypted-DNS attribution, or prompt-injection prevention.

## Key and trust model

The eventual signing key is software-rooted on the Linux host and must be
provisioned through the deployment supervisor, kept outside event payloads,
and rotated or revoked by that supervisor. A host compromise before or during
the run can alter Sentry, its key, or the evidence path; this profile therefore
cannot detect that compromise without a hardware root. The declared trust
ceiling is evidence integrity against post-run tampering when the verifier
trusts the software key and the recorded environment, not proof of host
integrity or confidentiality.

## Verification boundary

An independent verifier may check the canonical record, digest, ordered event
coverage, policy identity, environment fields, and explicit limitations from a
clean process. It must reject any claim of complete protection when events are
lost, coverage is partial, required enforcement is unavailable, or the runtime
falls outside the declared kernel and architecture. Until the TRACE governance
and deployment-profile questions are resolved, Sentry ships this as a
documented evidence profile that references TRACE rather than claiming a
standard conformance mark.
