# Execution attestation envelope

`sentry-daemon::attestation::ExecutionAttestation` hashes a canonical,
redacted set of policy, environment, process-tree, event, decision, workflow,
and verifier fields, including the complete ordered event sequence. `verify`
rejects invalid ordering, malformed path evidence, sensitive fields, or
tampering with the expected digest. It separately reports the strongest claim
the validated evidence can support.

The envelope stores identifiers and counts only; it has no credential paths,
secret contents, tokens, or payloads. It is independently verifiable with the
same canonical field encoding exposed by the read-only `canonical_bytes()`
method. Live collection from kernel events and signing
by a trusted runtime are still required before this primitive can support the
complete release attestation.

`claim()` returns `ObservedEvidence` for a valid observe-only record, lost
events, partial coverage, unsupported guarantees, unavailable enforcement,
failed verification, unclassified connections, or a partial/unavailable egress
path. `verify_protection_claim()` requires both valid evidence and
`Protected`. This separation lets a verifier retain an authentic lower-trust
record without mistaking it for proof that Sentry enforced protection.

## Software-rooted signatures

`AttestationSignature` signs the canonical evidence bytes with Ed25519 and a
caller-provided, non-empty key ID. The verifier supplies both the expected key
ID and an independently trusted public key; the signed message includes the
key ID, so changing its label, the evidence, or the signature causes
verification to fail. The current API deliberately does not create, store,
rotate, or discover keys. Those duties remain with the deployment supervisor.

This signature protects evidence integrity only to the extent that the
verifier trusts the selected software key and host. It is not a silicon-rooted
attestation, a key certificate, or a TRACE conformance artifact.

`verify_environment()` separately compares the recorded kernel version,
architecture, and capability fingerprint with the verifier's current host.
`verify_process_identity()` compares the root TGID and procfs start-time ticks,
which detects PID reuse across a run.
`verify()` also applies `validate_redaction()` and rejects path-like or control
character values in identifier fields.

## Four-path egress evidence

The envelope contains one ordered `EgressPathEvidence` record for each common
agent egress path: `mcp_a2a_tool_call`, `shelled_cli`, `improvised_http`, and
`agent_authored_script`. Each record carries a Sentry network-decision count,
a coverage flag (`full`, `partial`, or `unavailable`), and an MCP-boundary
record count. Only the MCP/A2A path may have an MCP-boundary count; the other
three must be zero. This makes the difference between a protocol transcript
and kernel-side evidence machine-checkable.

The four records are not an exhaustive taxonomy. Any observed connection that
does not fit one of them is recorded in
`unclassified_network_decision_count`, and all per-path counts must reconcile
to `network_decision_count`. A complete-protection verification rejects an
unclassified count or any path with partial or unavailable coverage. The live
event pipeline does not yet populate this structure, so it is an attestation
contract and testable verifier boundary, not evidence that a four-path run has
occurred.
