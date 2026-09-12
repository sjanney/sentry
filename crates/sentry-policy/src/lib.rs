// SPDX-License-Identifier: Apache-2.0
//! Policy semantics shared by generation, dry-run, and enforcement.

pub mod compiler;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use sentry_types::EventKind;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaintMask {
    pub secret: bool,
    pub untrusted_input: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Destination<'a> {
    pub ip: Option<IpAddr>,
    pub domain: Option<&'a str>,
    pub dns_observed: bool,
    pub ttl_valid: bool,
    pub same_execution_domain: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressPolicy<'a> {
    pub allowed_domains: &'a [&'a str],
    pub allowed_cidrs: &'a [&'a str],
    pub deny_untrusted_egress: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressDecision {
    Allow,
    DenySecretTaint,
    DenyUntrustedTaint,
    DenyUnattributedDestination,
}

#[must_use]
pub fn decide_egress(
    taint: TaintMask,
    destination: Destination<'_>,
    policy: EgressPolicy<'_>,
) -> EgressDecision {
    if taint.secret {
        return EgressDecision::DenySecretTaint;
    }
    if taint.untrusted_input && policy.deny_untrusted_egress {
        return EgressDecision::DenyUntrustedTaint;
    }
    if policy.allowed_domains.is_empty() && policy.allowed_cidrs.is_empty() {
        return EgressDecision::DenyUnattributedDestination;
    }
    {
        let attributed_domain = destination.domain.filter(|domain| {
            destination.dns_observed
                && destination.ttl_valid
                && destination.same_execution_domain
                && policy.allowed_domains.contains(domain)
        });
        let cidr_allowed = destination.ip.is_some_and(|ip| {
            policy
                .allowed_cidrs
                .iter()
                .any(|cidr| cidr_contains(cidr, ip))
        });
        if attributed_domain.is_none() && !cidr_allowed {
            return EgressDecision::DenyUnattributedDestination;
        }
    }
    EgressDecision::Allow
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (network.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(network)), IpAddr::V4(ip)) if prefix <= 32 => {
            let shift = 32 - u32::from(prefix);
            u32::from(network) >> shift == u32::from(ip) >> shift
        }
        (Ok(IpAddr::V6(network)), IpAddr::V6(ip)) if prefix <= 128 => {
            let shift = 128 - u32::from(prefix);
            u128::from(network) >> shift == u128::from(ip) >> shift
        }
        _ => false,
    }
}

#[must_use]
pub const fn decision_event_kind() -> EventKind {
    EventKind::EnforcementDecision
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileCredentialClass {
    SshKey,
    CloudCredential,
    DotEnv,
    Keyring,
    TokenCache,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCompleteness {
    Complete,
    PartialCoverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationTrust {
    Trusted,
    Untrusted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunObservation {
    pub run_id: String,
    pub completeness: RunCompleteness,
    pub trust: ObservationTrust,
    pub workspace_paths: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub credential_classes: BTreeSet<ProfileCredentialClass>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileIssue {
    IncompleteRun { run_id: String },
    UntrustedRun { run_id: String },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BehavioralProfile {
    pub workspace_paths: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub credential_classes: BTreeSet<ProfileCredentialClass>,
    pub provenance: BTreeMap<String, BTreeSet<String>>,
    pub issues: Vec<ProfileIssue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileVerdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDiff {
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
    pub verdict: ProfileVerdict,
}

/// Computes a deterministic, machine-readable drift result between profiles.
/// Any profile issue makes the result inconclusive; otherwise a changed set of
/// observed permissions is a fail and an identical set is a pass.
#[must_use]
pub fn diff_profiles(before: &BehavioralProfile, after: &BehavioralProfile) -> ProfileDiff {
    let before_values = profile_values(before);
    let after_values = profile_values(after);
    let added: BTreeSet<String> = after_values.difference(&before_values).cloned().collect();
    let removed: BTreeSet<String> = before_values.difference(&after_values).cloned().collect();
    let verdict = if !before.issues.is_empty() || !after.issues.is_empty() {
        ProfileVerdict::Inconclusive
    } else if added.is_empty() && removed.is_empty() {
        ProfileVerdict::Pass
    } else {
        ProfileVerdict::Fail
    };
    ProfileDiff {
        added,
        removed,
        verdict,
    }
}

fn profile_values(profile: &BehavioralProfile) -> BTreeSet<String> {
    profile
        .workspace_paths
        .iter()
        .map(|value| format!("workspace:{value}"))
        .chain(
            profile
                .domains
                .iter()
                .map(|value| format!("domain:{value}")),
        )
        .chain(
            profile
                .credential_classes
                .iter()
                .map(|value| format!("credential:{value:?}")),
        )
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileError {
    DuplicateRunId { run_id: String },
}

/// Merges complete, trusted observations into a stable behavioral profile.
///
/// Incomplete and untrusted runs remain visible through `issues` but cannot
/// add permissions. Each admitted field retains the contributing run IDs.
///
/// # Errors
///
/// Returns `DuplicateRunId` when callers provide ambiguous provenance.
pub fn merge_profile(
    runs: impl IntoIterator<Item = RunObservation>,
) -> Result<BehavioralProfile, ProfileError> {
    let mut profile = BehavioralProfile::default();
    let mut seen_run_ids = BTreeSet::new();
    for run in runs {
        if !seen_run_ids.insert(run.run_id.clone()) {
            return Err(ProfileError::DuplicateRunId { run_id: run.run_id });
        }
        if run.completeness != RunCompleteness::Complete {
            profile
                .issues
                .push(ProfileIssue::IncompleteRun { run_id: run.run_id });
            continue;
        }
        if run.trust != ObservationTrust::Trusted {
            profile
                .issues
                .push(ProfileIssue::UntrustedRun { run_id: run.run_id });
            continue;
        }
        add_profile_values(
            &mut profile.workspace_paths,
            &mut profile.provenance,
            "workspace:",
            run.workspace_paths,
            &run.run_id,
        );
        add_profile_values(
            &mut profile.domains,
            &mut profile.provenance,
            "domain:",
            run.domains,
            &run.run_id,
        );
        for credential in run.credential_classes {
            profile.credential_classes.insert(credential);
            profile
                .provenance
                .entry(format!("credential:{credential:?}"))
                .or_default()
                .insert(run.run_id.clone());
        }
    }
    profile.issues.sort_by_key(|issue| match issue {
        ProfileIssue::IncompleteRun { run_id } | ProfileIssue::UntrustedRun { run_id } => {
            run_id.clone()
        }
    });
    Ok(profile)
}

/// Renders a deterministic, review-only policy candidate from trusted profile data.
#[must_use]
pub fn render_policy_candidate(profile: &BehavioralProfile) -> String {
    let mut output = String::from(
        "# Sentry policy candidate v0\n# Review required: this file is not active policy.\n\
         schema_version = 1\nmode = \"dry_run\"\ndefault_action = \"deny\"\nactivation = false\n\n",
    );
    append_candidate_section(
        &mut output,
        "workspace paths",
        "workspace:",
        &profile.workspace_paths,
        &profile.provenance,
    );
    append_candidate_section(
        &mut output,
        "allowed domains",
        "domain:",
        &profile.domains,
        &profile.provenance,
    );
    output.push_str("[credential classes]\n");
    for class in &profile.credential_classes {
        let key = format!("credential:{class:?}");
        append_candidate_value(
            &mut output,
            &format!("{class:?}"),
            &key,
            &profile.provenance,
        );
    }
    if profile.credential_classes.is_empty() {
        output.push_str("# No credential classes were learned.\n");
    }
    output.push_str("\n[profile issues]\n");
    if profile.issues.is_empty() {
        output.push_str("# No incomplete or untrusted runs were supplied.\n");
    } else {
        for issue in &profile.issues {
            match issue {
                ProfileIssue::IncompleteRun { run_id } => {
                    output.push_str("# incomplete run excluded: ");
                    output.push_str(run_id);
                    output.push('\n');
                }
                ProfileIssue::UntrustedRun { run_id } => {
                    output.push_str("# untrusted run excluded: ");
                    output.push_str(run_id);
                    output.push('\n');
                }
            }
        }
    }
    output
}

fn append_candidate_section(
    output: &mut String,
    heading: &str,
    prefix: &str,
    values: &BTreeSet<String>,
    provenance: &BTreeMap<String, BTreeSet<String>>,
) {
    output.push('[');
    output.push_str(heading);
    output.push_str("]\n");
    if values.is_empty() {
        output.push_str("# No values were learned.\n");
    }
    for value in values {
        append_candidate_value(output, value, &format!("{prefix}{value}"), provenance);
    }
    output.push('\n');
}

fn append_candidate_value(
    output: &mut String,
    value: &str,
    key: &str,
    provenance: &BTreeMap<String, BTreeSet<String>>,
) {
    let runs = provenance.get(key).map_or_else(String::new, |runs| {
        runs.iter().cloned().collect::<Vec<_>>().join(", ")
    });
    output.push_str(value);
    output.push_str(" # observed in runs: ");
    output.push_str(&runs);
    output.push('\n');
}

fn add_profile_values(
    destination: &mut BTreeSet<String>,
    provenance: &mut BTreeMap<String, BTreeSet<String>>,
    prefix: &str,
    values: BTreeSet<String>,
    run_id: &str,
) {
    for value in values {
        destination.insert(value.clone());
        provenance
            .entry(format!("{prefix}{value}"))
            .or_default()
            .insert(run_id.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API: &str = "api.example.test";
    const ALLOWED: [&str; 1] = [API];

    fn destination(domain: Option<&str>, observed: bool, ttl_valid: bool) -> Destination<'_> {
        Destination {
            ip: None,
            domain,
            dns_observed: observed,
            ttl_valid,
            same_execution_domain: true,
        }
    }

    #[test]
    fn secret_taint_overrides_a_resolved_allowed_domain() {
        assert_eq!(
            decide_egress(
                TaintMask {
                    secret: true,
                    untrusted_input: false,
                },
                destination(Some(API), true, true),
                EgressPolicy {
                    allowed_cidrs: &[],
                    allowed_domains: &ALLOWED,
                    deny_untrusted_egress: false,
                },
            ),
            EgressDecision::DenySecretTaint
        );
    }

    #[test]
    fn secret_taint_overrides_an_explicit_cidr_allow() {
        let allowed_cidrs = ["198.51.100.0/24"];
        assert_eq!(
            decide_egress(
                TaintMask {
                    secret: true,
                    untrusted_input: false,
                },
                Destination {
                    ip: Some("198.51.100.7".parse().unwrap()),
                    domain: None,
                    dns_observed: false,
                    ttl_valid: false,
                    same_execution_domain: false,
                },
                EgressPolicy {
                    allowed_domains: &[],
                    allowed_cidrs: &allowed_cidrs,
                    deny_untrusted_egress: false,
                },
            ),
            EgressDecision::DenySecretTaint
        );
    }

    #[test]
    fn untrusted_taint_is_policy_controlled() {
        let taint = TaintMask {
            secret: false,
            untrusted_input: true,
        };
        let destination = destination(Some(API), true, true);
        assert_eq!(
            decide_egress(
                taint,
                destination,
                EgressPolicy {
                    allowed_cidrs: &[],
                    allowed_domains: &ALLOWED,
                    deny_untrusted_egress: true,
                }
            ),
            EgressDecision::DenyUntrustedTaint
        );
        assert_eq!(
            decide_egress(
                taint,
                destination,
                EgressPolicy {
                    allowed_cidrs: &[],
                    allowed_domains: &ALLOWED,
                    deny_untrusted_egress: false,
                }
            ),
            EgressDecision::Allow
        );
    }

    #[test]
    fn direct_or_expired_resolution_is_rejected() {
        let policy = EgressPolicy {
            allowed_cidrs: &[],
            allowed_domains: &ALLOWED,
            deny_untrusted_egress: false,
        };
        assert_eq!(
            decide_egress(
                TaintMask::default(),
                destination(None, false, false),
                policy
            ),
            EgressDecision::DenyUnattributedDestination
        );
        assert_eq!(
            decide_egress(
                TaintMask::default(),
                destination(Some(API), true, false),
                policy
            ),
            EgressDecision::DenyUnattributedDestination
        );
    }

    fn observation(
        run_id: &str,
        completeness: RunCompleteness,
        trust: ObservationTrust,
        paths: &[&str],
        domains: &[&str],
        credentials: &[ProfileCredentialClass],
    ) -> RunObservation {
        RunObservation {
            run_id: run_id.to_owned(),
            completeness,
            trust,
            workspace_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
            credential_classes: credentials.iter().copied().collect(),
        }
    }

    #[test]
    fn trusted_complete_runs_merge_stably_and_retain_provenance() {
        let first = observation(
            "run-1",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &["/work/a"],
            &["api.example.test"],
            &[ProfileCredentialClass::TokenCache],
        );
        let second = observation(
            "run-2",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &["/work/b"],
            &["logs.example.test"],
            &[],
        );
        let forward = merge_profile([first.clone(), second.clone()]).unwrap();
        let reverse = merge_profile([second, first]).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward.provenance.get("domain:api.example.test"),
            Some(&BTreeSet::from(["run-1".to_owned()]))
        );
    }

    #[test]
    fn profile_diff_is_deterministic_and_marks_drift_or_incomplete_evidence() {
        let before = merge_profile([observation(
            "run-1",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &["/work/a"],
            &["api.example.test"],
            &[],
        )])
        .unwrap();
        let after = merge_profile([observation(
            "run-2",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &["/work/a", "/work/b"],
            &["api.example.test"],
            &[],
        )])
        .unwrap();
        let diff = diff_profiles(&before, &after);
        assert_eq!(diff.verdict, ProfileVerdict::Fail);
        assert_eq!(diff.added, BTreeSet::from(["workspace:/work/b".to_owned()]));
        assert!(diff.removed.is_empty());

        let incomplete = merge_profile([observation(
            "partial",
            RunCompleteness::PartialCoverage,
            ObservationTrust::Trusted,
            &[],
            &[],
            &[],
        )])
        .unwrap();
        assert_eq!(
            diff_profiles(&before, &incomplete).verdict,
            ProfileVerdict::Inconclusive
        );
    }

    #[test]
    fn incomplete_and_untrusted_observations_cannot_create_grants() {
        let incomplete = observation(
            "partial",
            RunCompleteness::PartialCoverage,
            ObservationTrust::Trusted,
            &["/work/partial"],
            &["partial.example.test"],
            &[ProfileCredentialClass::SshKey],
        );
        let malicious = observation(
            "malicious",
            RunCompleteness::Complete,
            ObservationTrust::Untrusted,
            &["/work/claimed"],
            &["attacker.example.test"],
            &[ProfileCredentialClass::CloudCredential],
        );
        let profile = merge_profile([incomplete, malicious]).unwrap();
        assert!(profile.workspace_paths.is_empty());
        assert!(profile.domains.is_empty());
        assert!(profile.credential_classes.is_empty());
        assert_eq!(
            profile.issues,
            vec![
                ProfileIssue::UntrustedRun {
                    run_id: "malicious".to_owned()
                },
                ProfileIssue::IncompleteRun {
                    run_id: "partial".to_owned()
                },
            ]
        );
    }

    #[test]
    fn duplicate_run_ids_are_rejected() {
        let run = observation(
            "run-1",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &[],
            &[],
            &[],
        );
        assert_eq!(
            merge_profile([run.clone(), run]),
            Err(ProfileError::DuplicateRunId {
                run_id: "run-1".to_owned()
            })
        );
    }

    #[test]
    fn policy_candidate_is_review_only_stable_and_explains_its_sources() {
        let trusted = observation(
            "run-1",
            RunCompleteness::Complete,
            ObservationTrust::Trusted,
            &["/work/project"],
            &["api.example.test"],
            &[ProfileCredentialClass::TokenCache],
        );
        let untrusted = observation(
            "attacker",
            RunCompleteness::Complete,
            ObservationTrust::Untrusted,
            &[],
            &["attacker.example.test"],
            &[ProfileCredentialClass::SshKey],
        );
        let candidate = render_policy_candidate(&merge_profile([trusted, untrusted]).unwrap());
        assert!(candidate.starts_with("# Sentry policy candidate v0"));
        assert!(candidate.contains("mode = \"dry_run\""));
        assert!(candidate.contains("default_action = \"deny\""));
        assert!(candidate.contains("activation = false"));
        assert!(candidate.contains("api.example.test # observed in runs: run-1"));
        assert!(candidate.contains("untrusted run excluded: attacker"));
        assert!(!candidate.contains("attacker.example.test"));
        assert!(!candidate.contains("SshKey # observed"));
    }
}
