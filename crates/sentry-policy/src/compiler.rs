// SPDX-License-Identifier: Apache-2.0
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, net::IpAddr, sync::RwLock};

use crate::{Destination, EgressDecision, EgressPolicy, TaintMask, decide_egress};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum KernelCapability {
    BpfLsm,
    CgroupV2,
    DnsObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    DryRun,
    Enforce,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    pub schema_version: u32,
    pub policy_version: u64,
    pub mode: PolicyMode,
    pub default_deny: bool,
    pub deny_untrusted_egress: bool,
    pub allowed_domains: BTreeSet<String>,
    pub allowed_cidrs: BTreeSet<String>,
    pub required_capabilities: BTreeSet<KernelCapability>,
}

/// Strictly decodes the bounded compiler input used by the runtime boundary.
///
/// # Errors
///
/// Returns a JSON error for malformed input, unknown fields, or invalid enum
/// values. Semantic and capability checks still run in `compile_kernel_policy`.
pub fn load_policy_spec_json(input: &str) -> Result<PolicySpec, serde_json::Error> {
    serde_json::from_str(input)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyV0Error {
    Json(String),
    UnsupportedSchema(u32),
    InvalidDefaultAction,
    SecretTaintMustDeny,
    InvalidCredentialClass(String),
    InvalidWorkspaceRoot,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV0Document {
    schema_version: u32,
    mode: PolicyMode,
    default_action: String,
    workspace: PolicyV0Workspace,
    credential_classes: Vec<String>,
    destinations: PolicyV0Destinations,
    taint: PolicyV0Taint,
    required_capabilities: BTreeSet<KernelCapability>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV0Workspace {
    roots: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV0Destinations {
    allowed_domains: BTreeSet<String>,
    allowed_cidrs: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV0Taint {
    secret: String,
    untrusted_input: String,
}

/// Adapts the documented v0 JSON policy into the bounded compiler shape.
///
/// # Errors
///
/// Returns a typed error for malformed JSON or any v0 schema/semantic mismatch.
pub fn load_policy_v0_json(input: &str) -> Result<PolicySpec, PolicyV0Error> {
    let document: PolicyV0Document =
        serde_json::from_str(input).map_err(|error| PolicyV0Error::Json(error.to_string()))?;
    if document.schema_version != 1 {
        return Err(PolicyV0Error::UnsupportedSchema(document.schema_version));
    }
    if document.default_action != "deny" {
        return Err(PolicyV0Error::InvalidDefaultAction);
    }
    if document.taint.secret != "deny" {
        return Err(PolicyV0Error::SecretTaintMustDeny);
    }
    for root in document.workspace.roots {
        if root.is_empty() || root.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(PolicyV0Error::InvalidWorkspaceRoot);
        }
    }
    for class in document.credential_classes {
        if !matches!(
            class.as_str(),
            "ssh_key" | "cloud_credential" | "dotenv" | "keyring" | "token_cache"
        ) {
            return Err(PolicyV0Error::InvalidCredentialClass(class));
        }
    }
    Ok(PolicySpec {
        schema_version: 1,
        policy_version: 1,
        mode: document.mode,
        default_deny: true,
        deny_untrusted_egress: document.taint.untrusted_input == "deny",
        allowed_domains: document.destinations.allowed_domains,
        allowed_cidrs: document.destinations.allowed_cidrs,
        required_capabilities: document.required_capabilities,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelPolicyLimits {
    pub max_domains: usize,
    pub max_cidrs: usize,
    pub max_serialized_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyCompileError {
    UnsupportedSchema { found: u32 },
    NonDenyDefault,
    ZeroPolicyVersion,
    EmptyDomain,
    InvalidDomain { domain: String },
    InvalidCidr { cidr: String },
    TooManyDomains { limit: usize, found: usize },
    TooManyCidrs { limit: usize, found: usize },
    PolicyTooLarge { limit: usize, found: usize },
    MissingCapability { capability: KernelCapability },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledKernelPolicy {
    policy_version: u64,
    policy_hash: u64,
    mode: PolicyMode,
    default_deny: bool,
    deny_untrusted_egress: bool,
    domain_slots: Vec<String>,
    cidr_slots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleId {
    SecretTaintDeny,
    UntrustedTaintDeny,
    UnattributedDestinationDeny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    Poisoned,
    VersionRegression,
    VersionConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackPolicyError {
    UnsupportedMode,
    NonDenyDefault,
    DomainRulesUnsupported,
    CidrRulesUnsupported,
    CapabilityRequired { capability: KernelCapability },
}

/// Validates the deliberately small policy subset supported by the seccomp
/// fallback when BPF-LSM and cgroup enforcement are unavailable.
///
/// The fallback can enforce launch-time socket creation denial only. It must
/// reject policies containing controls it cannot represent before starting the
/// workload, rather than claiming equivalent coverage.
///
/// # Errors
///
/// Returns a typed error when the policy requests a mode, destination rule,
/// or kernel capability outside the fallback subset.
pub fn validate_seccomp_fallback(policy: &PolicySpec) -> Result<(), FallbackPolicyError> {
    if policy.mode != PolicyMode::Enforce {
        return Err(FallbackPolicyError::UnsupportedMode);
    }
    if !policy.default_deny {
        return Err(FallbackPolicyError::NonDenyDefault);
    }
    if !policy.allowed_domains.is_empty() {
        return Err(FallbackPolicyError::DomainRulesUnsupported);
    }
    if !policy.allowed_cidrs.is_empty() {
        return Err(FallbackPolicyError::CidrRulesUnsupported);
    }
    if let Some(capability) = policy.required_capabilities.iter().next().copied() {
        return Err(FallbackPolicyError::CapabilityRequired { capability });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunVerdict {
    pub decision: EgressDecision,
    pub would_deny: bool,
    pub rule_id: Option<RuleId>,
    pub policy_version: u64,
    pub policy_hash: u64,
    pub explanation: &'static str,
}

/// Validates a policy and creates the complete bounded kernel state off-path.
///
/// The returned value has no side effects. Call `PolicyActivation::activate`
/// only after this succeeds, so invalid policies cannot partially activate.
///
/// # Errors
///
/// Returns a typed error for schema, semantic, capacity, or capability failure.
pub fn compile_kernel_policy(
    policy: &PolicySpec,
    available: &BTreeSet<KernelCapability>,
    limits: KernelPolicyLimits,
) -> Result<CompiledKernelPolicy, PolicyCompileError> {
    if policy.schema_version != 1 {
        return Err(PolicyCompileError::UnsupportedSchema {
            found: policy.schema_version,
        });
    }
    if !policy.default_deny {
        return Err(PolicyCompileError::NonDenyDefault);
    }
    if policy.policy_version == 0 {
        return Err(PolicyCompileError::ZeroPolicyVersion);
    }
    for domain in &policy.allowed_domains {
        if domain.is_empty() {
            return Err(PolicyCompileError::EmptyDomain);
        }
        if domain.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(PolicyCompileError::InvalidDomain {
                domain: domain.clone(),
            });
        }
    }
    for cidr in &policy.allowed_cidrs {
        if !is_valid_cidr(cidr) {
            return Err(PolicyCompileError::InvalidCidr { cidr: cidr.clone() });
        }
    }
    if policy.allowed_domains.len() > limits.max_domains {
        return Err(PolicyCompileError::TooManyDomains {
            limit: limits.max_domains,
            found: policy.allowed_domains.len(),
        });
    }
    if policy.allowed_cidrs.len() > limits.max_cidrs {
        return Err(PolicyCompileError::TooManyCidrs {
            limit: limits.max_cidrs,
            found: policy.allowed_cidrs.len(),
        });
    }
    let mut required_capabilities = policy.required_capabilities.clone();
    if policy.mode == PolicyMode::Enforce {
        required_capabilities.insert(KernelCapability::CgroupV2);
    }
    if !policy.allowed_domains.is_empty() {
        required_capabilities.insert(KernelCapability::DnsObservation);
    }
    for capability in required_capabilities {
        if !available.contains(&capability) {
            return Err(PolicyCompileError::MissingCapability { capability });
        }
    }
    let serialized_bytes = policy
        .allowed_domains
        .iter()
        .chain(&policy.allowed_cidrs)
        .map(String::len)
        .sum();
    if serialized_bytes > limits.max_serialized_bytes {
        return Err(PolicyCompileError::PolicyTooLarge {
            limit: limits.max_serialized_bytes,
            found: serialized_bytes,
        });
    }
    let domain_slots: Vec<_> = policy.allowed_domains.iter().cloned().collect();
    let cidr_slots: Vec<_> = policy.allowed_cidrs.iter().cloned().collect();
    Ok(CompiledKernelPolicy {
        policy_version: policy.policy_version,
        policy_hash: policy_hash(policy),
        mode: policy.mode,
        default_deny: policy.default_deny,
        deny_untrusted_egress: policy.deny_untrusted_egress,
        domain_slots,
        cidr_slots,
    })
}

impl CompiledKernelPolicy {
    #[must_use]
    pub fn decide_egress(&self, taint: TaintMask, destination: Destination<'_>) -> EgressDecision {
        let allowed_domains: Vec<_> = self.domain_slots.iter().map(String::as_str).collect();
        let allowed_cidrs: Vec<_> = self.cidr_slots.iter().map(String::as_str).collect();
        decide_egress(
            taint,
            destination,
            EgressPolicy {
                allowed_domains: &allowed_domains,
                allowed_cidrs: &allowed_cidrs,
                deny_untrusted_egress: self.deny_untrusted_egress,
            },
        )
    }

    #[must_use]
    pub fn dry_run_egress(&self, taint: TaintMask, destination: Destination<'_>) -> DryRunVerdict {
        let decision = self.decide_egress(taint, destination);
        let (would_deny, rule_id, explanation) = match decision {
            EgressDecision::Allow => (false, None, "would allow: no deny rule matched"),
            EgressDecision::DenySecretTaint => (
                true,
                Some(RuleId::SecretTaintDeny),
                "would deny: protected credential data tainted this execution domain",
            ),
            EgressDecision::DenyUntrustedTaint => (
                true,
                Some(RuleId::UntrustedTaintDeny),
                "would deny: untrusted input egress is denied by policy",
            ),
            EgressDecision::DenyUnattributedDestination => (
                true,
                Some(RuleId::UnattributedDestinationDeny),
                "would deny: destination lacks matching unexpired DNS evidence",
            ),
        };
        DryRunVerdict {
            decision,
            would_deny,
            rule_id,
            policy_version: self.policy_version,
            policy_hash: self.policy_hash,
            explanation,
        }
    }
}

/// A policy pointer replaced in one write only after complete compilation.
pub struct PolicyActivation {
    active: RwLock<Option<CompiledKernelPolicy>>,
}

impl PolicyActivation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: RwLock::new(None),
        }
    }

    /// Atomically installs a validated policy without version rollback.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned, the version regresses, or a
    /// same-version policy has a different identity hash.
    pub fn activate(&self, policy: CompiledKernelPolicy) -> Result<(), ActivationError> {
        let mut active = self.active.write().map_err(|_| ActivationError::Poisoned)?;
        if let Some(current) = active.as_ref() {
            if policy.policy_version < current.policy_version {
                return Err(ActivationError::VersionRegression);
            }
            if policy.policy_version == current.policy_version
                && policy.policy_hash != current.policy_hash
            {
                return Err(ActivationError::VersionConflict);
            }
        }
        *active = Some(policy);
        Ok(())
    }

    #[must_use]
    pub fn active(&self) -> Option<CompiledKernelPolicy> {
        self.active.read().ok().and_then(|active| active.clone())
    }

    /// Reads the active policy without collapsing lock failure into “none”.
    /// Enforcement callers should use this method and refuse work on error.
    ///
    /// # Errors
    ///
    /// Returns `ActivationError::Poisoned` if the policy lock is poisoned.
    pub fn active_checked(&self) -> Result<Option<CompiledKernelPolicy>, ActivationError> {
        self.active
            .read()
            .map(|active| active.clone())
            .map_err(|_| ActivationError::Poisoned)
    }
}

impl Default for PolicyActivation {
    fn default() -> Self {
        Self::new()
    }
}

fn policy_hash(policy: &PolicySpec) -> u64 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&policy.schema_version.to_le_bytes());
    bytes.extend_from_slice(&policy.policy_version.to_le_bytes());
    bytes.push(u8::from(policy.default_deny));
    bytes.push(u8::from(policy.deny_untrusted_egress));
    bytes.push(match policy.mode {
        PolicyMode::DryRun => 0,
        PolicyMode::Enforce => 1,
    });
    bytes.extend_from_slice(b"capabilities\0");
    for capability in &policy.required_capabilities {
        bytes.push(match capability {
            KernelCapability::BpfLsm => 0,
            KernelCapability::CgroupV2 => 1,
            KernelCapability::DnsObservation => 2,
        });
    }
    bytes.extend_from_slice(b"domains\0");
    for value in &policy.allowed_domains {
        append_length_delimited(&mut bytes, value.as_bytes());
    }
    bytes.extend_from_slice(b"cidrs\0");
    for value in &policy.allowed_cidrs {
        append_length_delimited(&mut bytes, value.as_bytes());
    }
    let digest = Sha256::digest(bytes);
    u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest is at least 8 bytes"),
    )
}

fn is_valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix
        <= match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
}

fn append_length_delimited(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PolicySpec {
        PolicySpec {
            schema_version: 1,
            policy_version: 4,
            mode: PolicyMode::Enforce,
            default_deny: true,
            deny_untrusted_egress: false,
            allowed_domains: BTreeSet::from(["api.example.test".to_owned()]),
            allowed_cidrs: BTreeSet::new(),
            required_capabilities: BTreeSet::from([
                KernelCapability::BpfLsm,
                KernelCapability::CgroupV2,
                KernelCapability::DnsObservation,
            ]),
        }
    }

    fn limits() -> KernelPolicyLimits {
        KernelPolicyLimits {
            max_domains: 2,
            max_cidrs: 2,
            max_serialized_bytes: 100,
        }
    }

    #[test]
    fn compiler_is_stable_bounded_and_matches_egress_decisions() {
        let capabilities = policy().required_capabilities.clone();
        let compiled = compile_kernel_policy(&policy(), &capabilities, limits()).unwrap();
        let same = compile_kernel_policy(&policy(), &capabilities, limits()).unwrap();
        assert_eq!(compiled.policy_hash, same.policy_hash);
        assert_eq!(
            compiled.decide_egress(
                TaintMask::default(),
                Destination {
                    ip: None,
                    domain: Some("api.example.test"),
                    dns_observed: true,
                    ttl_valid: true,
                    same_execution_domain: true,
                },
            ),
            EgressDecision::Allow
        );
    }

    #[test]
    fn compiler_fails_closed_for_invalid_or_unsupported_input() {
        let mut spec = policy();
        let capabilities = BTreeSet::new();
        assert_eq!(
            compile_kernel_policy(&spec, &capabilities, limits()),
            Err(PolicyCompileError::MissingCapability {
                capability: KernelCapability::BpfLsm
            })
        );
        spec.required_capabilities.clear();
        spec.default_deny = false;
        assert_eq!(
            compile_kernel_policy(&spec, &capabilities, limits()),
            Err(PolicyCompileError::NonDenyDefault)
        );
        spec.default_deny = true;
        spec.allowed_domains.insert("one.example.test".to_owned());
        spec.allowed_domains.insert("two.example.test".to_owned());
        assert_eq!(
            compile_kernel_policy(&spec, &capabilities, limits()),
            Err(PolicyCompileError::TooManyDomains { limit: 2, found: 3 })
        );
    }

    #[test]
    fn compiler_rejects_ambiguous_domains_and_invalid_cidrs() {
        let capabilities = policy().required_capabilities.clone();
        let mut spec = policy();
        spec.allowed_domains = BTreeSet::from(["api\u{0}example.test".to_owned()]);
        assert_eq!(
            compile_kernel_policy(&spec, &capabilities, limits()),
            Err(PolicyCompileError::InvalidDomain {
                domain: "api\u{0}example.test".to_owned()
            })
        );
        spec.allowed_domains.clear();
        spec.allowed_cidrs = BTreeSet::from(["198.51.100.7/40".to_owned()]);
        assert_eq!(
            compile_kernel_policy(&spec, &capabilities, limits()),
            Err(PolicyCompileError::InvalidCidr {
                cidr: "198.51.100.7/40".to_owned()
            })
        );
        spec.allowed_cidrs =
            BTreeSet::from(["198.51.100.0/24".to_owned(), "2001:db8::/32".to_owned()]);
        assert!(compile_kernel_policy(&spec, &capabilities, limits()).is_ok());
    }

    #[test]
    fn cidr_only_policies_deny_unmatched_destinations() {
        let mut spec = policy();
        spec.allowed_domains.clear();
        spec.allowed_cidrs = BTreeSet::from(["198.51.100.0/24".to_owned()]);
        let compiled = compile_kernel_policy(&spec, &spec.required_capabilities, limits()).unwrap();
        let allowed = Destination {
            ip: Some("198.51.100.7".parse().unwrap()),
            domain: None,
            dns_observed: false,
            ttl_valid: false,
            same_execution_domain: false,
        };
        let denied = Destination {
            ip: Some("203.0.113.7".parse().unwrap()),
            ..allowed
        };
        assert_eq!(
            compiled.decide_egress(TaintMask::default(), allowed),
            EgressDecision::Allow
        );
        assert_eq!(
            compiled.decide_egress(TaintMask::default(), denied),
            EgressDecision::DenyUnattributedDestination
        );
    }

    #[test]
    fn enforced_policies_require_cgroup_capability_even_when_omitted() {
        let mut spec = policy();
        spec.allowed_domains.clear();
        spec.required_capabilities.clear();
        assert_eq!(
            compile_kernel_policy(&spec, &BTreeSet::new(), limits()),
            Err(PolicyCompileError::MissingCapability {
                capability: KernelCapability::CgroupV2
            })
        );
    }

    #[test]
    fn activation_replaces_only_complete_compiled_policy() {
        let activation = PolicyActivation::new();
        assert_eq!(activation.active(), None);
        let spec = policy();
        let compiled = compile_kernel_policy(&spec, &spec.required_capabilities, limits()).unwrap();
        activation.activate(compiled.clone()).unwrap();
        assert_eq!(activation.active(), Some(compiled));
    }

    #[test]
    fn activation_rejects_downgrades_and_same_version_conflicts() {
        let activation = PolicyActivation::new();
        let capabilities = policy().required_capabilities.clone();
        activation
            .activate(compile_kernel_policy(&policy(), &capabilities, limits()).unwrap())
            .unwrap();
        let mut older = policy();
        older.policy_version = 3;
        let older = compile_kernel_policy(&older, &capabilities, limits()).unwrap();
        assert_eq!(
            activation.activate(older),
            Err(ActivationError::VersionRegression)
        );
        let mut conflict = policy();
        conflict.deny_untrusted_egress = true;
        let conflict = compile_kernel_policy(&conflict, &capabilities, limits()).unwrap();
        assert_eq!(
            activation.activate(conflict),
            Err(ActivationError::VersionConflict)
        );
    }

    #[test]
    fn checked_active_read_preserves_empty_state_and_policy_identity() {
        let activation = PolicyActivation::new();
        assert_eq!(activation.active_checked(), Ok(None));
        let spec = policy();
        let compiled = compile_kernel_policy(&spec, &spec.required_capabilities, limits()).unwrap();
        activation.activate(compiled.clone()).unwrap();
        assert_eq!(activation.active_checked(), Ok(Some(compiled)));
    }

    #[test]
    fn dry_run_verdicts_have_enforce_parity_and_explain_would_deny() {
        let spec = policy();
        let compiled = compile_kernel_policy(&spec, &spec.required_capabilities, limits()).unwrap();
        let destination = Destination {
            ip: None,
            domain: Some("api.example.test"),
            dns_observed: true,
            ttl_valid: true,
            same_execution_domain: true,
        };
        let taint = TaintMask {
            secret: true,
            untrusted_input: false,
        };
        let enforce = compiled.decide_egress(taint, destination);
        let dry_run = compiled.dry_run_egress(taint, destination);
        assert_eq!(dry_run.decision, enforce);
        assert!(dry_run.would_deny);
        assert_eq!(dry_run.rule_id, Some(RuleId::SecretTaintDeny));
        assert_eq!(dry_run.policy_hash, compiled.policy_hash);
        assert!(dry_run.explanation.contains("credential"));
    }

    #[test]
    fn seccomp_fallback_rejects_unrepresentable_controls() {
        let mut spec = policy();
        assert_eq!(
            validate_seccomp_fallback(&spec),
            Err(FallbackPolicyError::DomainRulesUnsupported)
        );
        spec.allowed_domains.clear();
        spec.allowed_cidrs.insert("198.51.100.0/24".to_owned());
        assert_eq!(
            validate_seccomp_fallback(&spec),
            Err(FallbackPolicyError::CidrRulesUnsupported)
        );
        spec.allowed_cidrs.clear();
        spec.required_capabilities.clear();
        assert_eq!(validate_seccomp_fallback(&spec), Ok(()));
        spec.mode = PolicyMode::DryRun;
        assert_eq!(
            validate_seccomp_fallback(&spec),
            Err(FallbackPolicyError::UnsupportedMode)
        );
    }

    #[test]
    fn json_loader_rejects_unknown_fields_and_decodes_strictly() {
        let spec = load_policy_spec_json(
            r#"{"schema_version":1,"policy_version":4,"mode":"enforce","default_deny":true,"deny_untrusted_egress":false,"allowed_domains":[],"allowed_cidrs":[],"required_capabilities":["cgroup_v2"]}"#,
        )
        .unwrap();
        assert_eq!(spec.mode, PolicyMode::Enforce);
        assert!(
            spec.required_capabilities
                .contains(&KernelCapability::CgroupV2)
        );
        assert!(load_policy_spec_json(
            r#"{"schema_version":1,"policy_version":4,"mode":"enforce","default_deny":true,"deny_untrusted_egress":false,"allowed_domains":[],"allowed_cidrs":[],"required_capabilities":[],"unexpected":true}"#,
        )
        .is_err());
    }

    #[test]
    fn v0_loader_validates_documented_schema_and_maps_taint_action() {
        let policy = load_policy_v0_json(
            r#"{"schema_version":1,"mode":"enforce","default_action":"deny","workspace":{"roots":["/work/project"]},"credential_classes":["ssh_key"],"destinations":{"allowed_domains":["api.example.test"],"allowed_cidrs":[]},"taint":{"secret":"deny","untrusted_input":"deny"},"required_capabilities":["bpf_lsm","cgroup_v2","dns_observation"]}"#,
        )
        .unwrap();
        assert!(policy.default_deny && policy.deny_untrusted_egress);
        assert_eq!(policy.allowed_domains.len(), 1);
        assert!(load_policy_v0_json(
            r#"{"schema_version":1,"mode":"enforce","default_action":"allow","workspace":{"roots":[]},"credential_classes":[],"destinations":{"allowed_domains":[],"allowed_cidrs":[]},"taint":{"secret":"deny","untrusted_input":"audit"},"required_capabilities":[]}"#,
        )
        .is_err());
    }
}
