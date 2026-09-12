// SPDX-License-Identifier: Apache-2.0
use std::{collections::BTreeSet, net::IpAddr, sync::RwLock};

use crate::{Destination, EgressDecision, EgressPolicy, TaintMask, decide_egress};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KernelCapability {
    BpfLsm,
    CgroupV2,
    DnsObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyMode {
    DryRun,
    Enforce,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySpec {
    pub schema_version: u32,
    pub policy_version: u64,
    pub mode: PolicyMode,
    pub default_deny: bool,
    pub allowed_domains: BTreeSet<String>,
    pub allowed_cidrs: BTreeSet<String>,
    pub required_capabilities: BTreeSet<KernelCapability>,
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
    pub policy_version: u64,
    pub policy_hash: u64,
    pub mode: PolicyMode,
    pub default_deny: bool,
    pub domain_slots: Vec<String>,
    pub cidr_slots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleId {
    SecretTaintDeny,
    UntrustedTaintDeny,
    UnattributedDestinationDeny,
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
                deny_untrusted_egress: true,
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

    pub fn activate(&self, policy: CompiledKernelPolicy) {
        if let Ok(mut active) = self.active.write() {
            *active = Some(policy);
        }
    }

    #[must_use]
    pub fn active(&self) -> Option<CompiledKernelPolicy> {
        self.active.read().ok().and_then(|active| active.clone())
    }
}

impl Default for PolicyActivation {
    fn default() -> Self {
        Self::new()
    }
}

fn policy_hash(policy: &PolicySpec) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    hash_bytes(&mut hash, &policy.schema_version.to_le_bytes());
    hash_bytes(&mut hash, &policy.policy_version.to_le_bytes());
    hash_bytes(&mut hash, &[u8::from(policy.default_deny)]);
    hash_bytes(
        &mut hash,
        &[match policy.mode {
            PolicyMode::DryRun => 0,
            PolicyMode::Enforce => 1,
        }],
    );
    hash_bytes(&mut hash, b"capabilities");
    for capability in &policy.required_capabilities {
        hash_bytes(
            &mut hash,
            &[match capability {
                KernelCapability::BpfLsm => 0,
                KernelCapability::CgroupV2 => 1,
                KernelCapability::DnsObservation => 2,
            }],
        );
    }
    hash_bytes(&mut hash, b"domains");
    for value in &policy.allowed_domains {
        hash_bytes(&mut hash, value.as_bytes());
    }
    hash_bytes(&mut hash, b"cidrs");
    for value in &policy.allowed_cidrs {
        hash_bytes(&mut hash, value.as_bytes());
    }
    hash
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

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes.iter().copied().chain(std::iter::once(0)) {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
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
        activation.activate(compiled.clone());
        assert_eq!(activation.active(), Some(compiled));
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
}
