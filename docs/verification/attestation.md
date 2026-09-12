# Execution attestation envelope

`sentry-daemon::attestation::ExecutionAttestation` hashes a canonical,
redacted set of policy, environment, process-tree, event, decision, workflow,
and verifier fields, including the complete ordered event sequence. `verify` rejects event loss, partial coverage, unsupported
guarantees, unavailable enforcement, failed verification, invalid ordering, or
tampering with the expected digest.

The envelope stores identifiers and counts only; it has no credential paths,
secret contents, tokens, or payloads. It is independently verifiable with the
same canonical field encoding. Live collection from kernel events and signing
by a trusted runtime are still required before this primitive can support the
complete release attestation.
