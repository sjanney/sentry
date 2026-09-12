# Procurement requirements coverage matrix

Status: Part A evidence baseline, 2026-09-12

This matrix scores only artifacts that exist in the repository today. `Fully
answered` means a reviewer can run or inspect the linked artifact now;
`Partially answered` means the artifact exists but live daemon wiring or a
deployment profile is still missing; `Unanswerable` means no current artifact
supports the claim. A policy statement alone never receives a full score.

| Primary public questionnaire or assessment | Procurement question extracted | Score | Exact Sentry artifact | Gap or boundary |
| --- | --- | --- | --- | --- |
| [CSA CAIQ v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) | Can the provider show security control evidence and a repeatable assessment record? | Partially answered | [security matrix](security-matrix.md), [audit contract](audit-log-contract.md) | Live event ingestion, signed export, and complete task replay are not wired. |
| [CSA AI-CAIQ v1.1](https://cloudsecurityalliance.org/artifacts/ai-consensus-assessments-initiative-questionnaire-ai-caiq) | Can an AI system’s actions and controls be evidenced for review? | Partially answered | [attestation contract](attestation.md), [adversarial protocol](real-agent-exfiltration-protocol.md) | No real-agent run or TRACE-compatible signed attestation exists yet. |
| [Shared Assessments SIG Lite](https://sharedassessments.org/about-sig/) | Can a customer obtain documented third-party security and operational evidence? | Partially answered | [failure lifecycle](failure-lifecycle.md), [MVP checklist](mvp-release-checklist.md) | No production deployment, support process, or exportable signed evidence. |
| [OWASP APTS Vendor Evaluation Guide](https://owasp.org/APTS/standard/appendix/Vendor_Evaluation_Guide.html) | Can the operator prove scope control, stop behavior, and a basic audit trail for autonomous actions? | Partially answered | [adversarial corpus](real-agent-exfiltration-protocol.md), [process limitations](process-taint-limitations.md) | Corpus and hook probes pass, but the live agent workflow remains unavailable. |
| [NIST agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) | Are agent actions logged in a tamper-evident and verifiable way? | Partially answered | [audit contract](audit-log-contract.md), [attestation contract](attestation.md) | Current audit chain is hash-verified but not software-signed; trust ceiling is non-TEE. |

## Current conclusion

The current artifacts answer a narrow question that generic protocol-boundary
products do not answer by themselves: whether supported Linux kernel hooks can
observe and deny selected filesystem and cgroup operations in a disposable
runtime. This is hook-level evidence, not a complete procurement claim. No
unique advantage over OpenShell, Tetragon, or Harden-Runner has been
demonstrated yet, so this matrix records that result explicitly rather than
inventing a differentiation claim.

Part B still requires stakeholder responses, a complete live workflow, and a
side-by-side protocol-boundary comparison. Those items remain release gates.
