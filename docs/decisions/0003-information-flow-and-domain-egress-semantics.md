# Information-flow and domain-egress semantics

Status: proposed

## Decision

The MVP uses process-group state keyed by Linux TGID. A protected read sets a
monotonic taint bit before the file-operation hook returns. A later egress
decision reads the current TGID state at the cgroup connect hook. A process
with an applicable deny-on-taint bit must be denied; a domain allow rule never
overrides that deny.

This defines an ordering guarantee for syscalls: a successful protected read
that completes before a `connect` decision taints that decision. It does not
claim a total order across concurrently executing threads. For concurrent
read/connect operations, the enforcement result is the state observed at the
connect hook. The audit record must include the taint mask observed at that
decision.

## Taint classes

| Bit | Set by | Default egress consequence | MVP use |
| --- | --- | --- | --- |
| `secret` | a policy-designated credential or secret read | deny all egress | Required for the credential-exfiltration demo. |
| `untrusted_input` | a policy-designated untrusted input read | policy-selected deny or audit | Supports “no egress after tainted input” without treating every workspace read as hostile. |

Bits only accumulate during an execution domain. A policy may make
`untrusted_input` audit-only, but it may not make a `secret` egress denial
permissive in the MVP. Clearing taint, content inspection, declassification,
and cross-process dataflow inference are out of scope.

## Execution-domain coverage

An execution domain begins when Sentry launches the agent or observes its exec
before policy activation. Child processes inherit the parent domain and taint
state at fork. If Sentry attaches after the process has already read data, it
must mark the domain `partial_coverage`; secret-to-egress guarantees are then
unavailable until a new covered exec begins. The daemon must reject a policy
that requires those guarantees for a partial-coverage domain.

## Domain-based egress

For a policy that specifies allowed domains, an outbound IPv4 or IPv6 connect
is allowed only when all of these are true:

1. The process has no applicable deny-on-taint bit.
2. Sentry observed a DNS response for that execution domain resolving the
   destination IP to an allowed domain.
3. The resolution has not expired according to its DNS TTL.
4. The connect is associated with the same execution domain as the observed
   resolution.

Direct-IP connections do not satisfy a domain rule. A hostname supplied only
through TLS SNI, HTTP Host, `/etc/hosts`, DNS-over-HTTPS, or a resolver cache
not observed by Sentry does not satisfy it either. Such traffic needs an
explicit IP/CIDR capability or is denied in enforce mode. These limits are
reported in generated policy and audit records.

## Atomic implementation requirements

- Store taint in a per-TGID BPF map and update it with an atomic bitwise OR.
- Read the taint mask once at the start of the cgroup connect decision and
  include that exact value in its emitted event.
- Keep DNS IP/domain/expiry bindings per execution domain; do not use a global
  host cache.
- Remove process state only after the exit event is recorded. PID reuse must
  not inherit a previous domain’s state.
- Treat unavailable attribution or DNS correlation as a deny for an enforce
  rule that depends on it, and as an explicit `unknown` outcome in dry-run.

## Reference cases

`tests/semantics/ifc-egress-cases.json` specifies the MVP’s normative
transitions. Its verifier tests the decision table independently of kernel
hooks, so later BPF and daemon implementations have one shared expected
behavior.

## Open implementation evidence

- Verify BPF atomic bit updates and TGID cleanup under concurrent fork, read,
  exit, and connect workloads.
- Verify DNS response attribution for UDP and TCP DNS on both target
  architectures.
- Verify a protected read followed by a local synthetic connect is denied and
  audit-correlated end to end.
