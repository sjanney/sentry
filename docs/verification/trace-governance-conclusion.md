# TRACE governance conclusion for Sentry

Status: decision record, 2026-09-12

## Decision

Sentry may describe its current Linux evidence record as **TRACE-informed** or
as a documented profile that references TRACE. It must not describe that record
as TRACE-conformant, use the `TRACE-conformant` mark, or set the TRACE v0.2
`eat_profile` identifier merely because the record has similar fields.

The current non-TEE Linux profile is therefore a Sentry deployment profile,
not a TRACE hardware-attestation profile. It records software-observed kernel
and enforcement context plus explicit limitations. It does not supply the
silicon-rooted runtime measurement chain that TRACE v0.2 describes.

## Evidence reviewed

The [TRACE v0.2 draft](https://github.com/agentrust-io/trace-spec/blob/main/spec/trace-v0.2.md)
calls itself a pre-ratification draft, describes TRACE as a
hardware-attested record rooted in silicon attestation, and requires the exact
`tag:agentrust-io.com,2026:trace-v0.2` profile URI for a v0.2 record.

The [TRACE technical charter](https://trace.agentrust-io.com/CHARTER/) says
that its governance terms and conformance-mark ownership are proposed until
v1.0 ratification. It permits a TRACE conformance claim only after a passing
published conformance-test run at the claimed level, with the test-suite
version and link to that run. The charter also identifies vendor platform
annexes as vendor-co-authored claim mappings for silicon and cloud attestation
surfaces.

The [Linux Foundation announcement](https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads?hs_amp=true)
confirms the project contribution, but it does not turn an untested deployment
profile into a conformance claim.

## Product consequences

The product may keep a field map to TRACE vocabulary, provide independently
verifiable Sentry audit and policy records, and publish the documented
limitations of its software-rooted evidence. It must label those artifacts as
Sentry evidence and keep the non-TEE limits visible to a verifier.

Before adding a TRACE conformance claim, release work must establish all of
the following:

1. a ratified applicable TRACE version and a production-stable governance
   basis;
2. an applicable runtime or deployment profile, including a claim mapping for
   the selected Linux evidence source;
3. an implementation of every required wire, signing, and verification rule;
4. a passing published conformance-suite run for the exact claimed level and
   version; and
5. a review that verifies the product language, profile URI, and verifier
   behavior match that result.

Until then, future work on a signed envelope or hardware attestation is an
integration investigation, not authorization to call Sentry TRACE-conformant.

## Re-evaluation trigger

Revisit this decision when TRACE v1.0 is ratified, when an applicable Linux
runtime profile or vendor annex is published, or when Sentry has a complete
implementation and reproducible passing conformance evidence.
