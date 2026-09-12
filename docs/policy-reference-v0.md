# Sentry policy v0 reference

Policy v0 is JSON. Every document has `schema_version: 1`; unknown schema
versions are rejected with `POLICY_UNSUPPORTED_SCHEMA`. Unknown fields are
rejected with `POLICY_UNKNOWN_FIELD`, missing required fields with
`POLICY_MISSING_FIELD`, and values outside the enumerations below with
`POLICY_INVALID_VALUE`. The loader must never silently ignore an input.

## Top-level schema

```json
{
  "schema_version": 1,
  "mode": "dry_run",
  "default_action": "deny",
  "workspace": { "roots": ["/work/project"] },
  "credential_classes": ["ssh_key", "cloud_credential", "dotenv", "keyring", "token_cache"],
  "destinations": { "allowed_domains": ["api.example.test"], "allowed_cidrs": [] },
  "taint": { "secret": "deny", "untrusted_input": "audit" },
  "required_capabilities": ["bpf_lsm", "cgroup_v2", "dns_observation"]
}
```

`mode` is `dry_run` or `enforce`. `default_action` is `deny` in v0. Workspace
roots identify project data and do not by themselves create a taint. The five
credential classes are recognized sensitive reads and set `secret` taint.
`untrusted_input` is set by configured untrusted sources and may be `audit` or
`deny`; `secret` must be `deny`. Both taint bits are monotonic within an
execution domain. There is no declassification or content inspection in v0.

Destination classes are an allowed DNS domain, an explicit CIDR, and unknown.
An allowed domain requires same-domain, unexpired observed DNS evidence. An
explicit CIDR is a separate capability rule. Direct IP, an unobserved resolver
answer, an expired answer, or a DNS answer from another execution domain is
`unknown`; it is denied by the v0 default action in enforce mode and recorded
as a would-deny result in dry-run mode. A secret taint deny takes precedence
over every destination allow; an untrusted deny follows it. An empty
destination allowlist is also deny-by-default. CIDRs must use a valid IPv4 or
IPv6 address and prefix length; malformed entries are rejected during
compilation rather than treated as a permissive unknown.

## Kernel requirements and unsupported cases

`bpf_lsm` is required for protected-read tainting, `cgroup_v2` for connection
enforcement, and `dns_observation` for domain rules. A policy requiring a
missing capability is rejected before enforcement with
`POLICY_CAPABILITY_UNAVAILABLE`; it must not degrade to a claimed enforcement
mode. Attach coverage is partial until a covered exec and cannot satisfy a
policy requiring secret-to-egress guarantees.

Allowed domains are exact, non-wildcard names. Empty, control-character, or
whitespace-containing domain rules are rejected during compilation.

Encrypted DNS, proxies, shared IP addresses, `/etc/hosts`, resolver cache
hits, TLS SNI, HTTP Host, Unix sockets, and cross-process dataflow are not
domain evidence in v0. Use an explicit CIDR where appropriate or accept the
default-deny result. Policy v0 has no wildcard domains, port rules,
declassification, or dynamic updates.

## Behavioral profiles

Profiles merge only complete, trusted runs. Their workspace paths, domains, and
credential classes are sorted sets, and every admitted value retains the IDs of
the runs that contributed it. This makes merge and diff output deterministic.
Partial-coverage runs and untrusted observations are retained as profile
issues, but add no grant. In particular, a malicious observation cannot teach
the product that credential access is normal. A generated profile remains a
review artifact; it does not automatically alter an enforcing policy.

The policy library also exposes `diff_profiles`, which returns sorted added and
removed permission keys plus a machine-readable `Pass`, `Fail`, or
`Inconclusive` verdict. Any incomplete or untrusted profile issue forces the
inconclusive result; a changed permission set is reported as drift rather than
silently merged.

## Candidate generation

`render_policy_candidate` produces a human-readable review artifact with stable
sorted sections for workspace paths, domains, and credential classes. Every
admitted line names the trusted complete runs that observed it. The rendered
candidate fixes `mode` to `dry_run`, `default_action` to `deny`, and
`activation` to `false`; a reviewer must explicitly translate and apply an
approved candidate. Incomplete and untrusted runs appear only as excluded
issues, so their observations do not appear as proposed grants.

When runtime evidence is available, `render_policy_candidate_with_context`
also records the tested kernel version, architecture, and enforcement mode in
the candidate header. The context remains descriptive; it cannot activate the
candidate or turn incomplete replay evidence into a pass.

## Bounded compilation and activation

Before activation, policy compilation rejects unsupported schema versions,
non-deny defaults, zero policy versions, empty domains, unavailable kernel
capabilities, and configured map or serialized-size limits. It produces sorted
domain and CIDR slots plus a stable identity hash over the policy’s semantics.
The compiled state is built before the active-policy pointer is replaced, so a
validation failure leaves the previous policy in place. The current activation
boundary is userspace state; connecting those bounded slots to eBPF maps is
still required before an enforce-mode kernel claim can be made.

The policy identity is derived from a length-delimited canonical encoding and
SHA-256; the public API retains the first 64 bits for compact event fields.

The Rust runtime currently exposes strict JSON decoding for the bounded compiler
spec (`sentry_policy::compiler::load_policy_spec_json`), including unknown-field
rejection. The v0 document-to-compiler adapter is now implemented and covered
by Rust tests; full runtime activation and kernel map wiring remain open. The
Python fixture validator is not treated as the adapter.

## Dry-run verdicts

Dry-run calls the same compiled egress decision as enforce mode and records the
result, `would_deny`, the matched rule ID, policy version, policy hash, and an
explanation. A dry-run record never blocks the current execution. That means a
would-denied process can continue, read more inputs, and issue later requests;
its subsequent behavior can differ from an enforce-mode execution that was
actually stopped. Review dry-run evidence as a counterfactual, not proof that
the resulting process trace would be identical under enforcement.

## Example behavior

The included [policy fixture](../examples/policy-v0.json) permits an observed,
unexpired `api.example.test` DNS binding only while no deny taint is present.
A read of an SSH key wins over this allow and produces a deny. The fixture’s
validator lives at `tests/semantics/verify_policy_v0.py`.
