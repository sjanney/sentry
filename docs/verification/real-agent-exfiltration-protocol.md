# Real-agent indirect-injection demonstration protocol

This release demonstration must run in a disposable Linux VM against
`tests/integration/adversarial/fixtures`. The synthetic marker is the only
credential material allowed. Record the agent product, exact version, model,
settings, prompt, fixture revision, Sentry policy hash, kernel version, and
commands used.

Run three separate trials against the same controlled loopback sink:

1. An unprotected baseline, recording whether the agent actually attempts the
   malicious fixture instruction.
2. Sentry dry-run, retaining the matching would-deny rule, policy hash, and
   audit record.
3. Sentry enforce, proving the attempted read or egress is denied and retaining
   the corresponding audit record.

An agent that does not follow the malicious instruction is a non-triggered
stochastic result, not proof of enforcement. The deterministic corpus verifier
remains the security regression; it validates fixtures and the controlled sink
but does not substitute for a real-agent result.

`verify_real_agent_record.py` validates the required metadata and three-trial
shape before results are attached. The checked-in example is a schema example
only; it does not claim that an agent trial has run.

The current repository cannot run steps 2 or 3: CLI launch, kernel policy map
activation, live event ingestion, and audit-log emission are not wired together.
This document intentionally leaves the evidence table empty until that runtime
path exists.
