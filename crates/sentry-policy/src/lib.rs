// SPDX-License-Identifier: Apache-2.0
//! Policy semantics shared by generation, dry-run, and enforcement.

use std::collections::{BTreeMap, BTreeSet};

use sentry_types::EventKind;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaintMask {
    pub secret: bool,
    pub untrusted_input: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Destination<'a> {
    pub domain: Option<&'a str>,
    pub dns_observed: bool,
    pub ttl_valid: bool,
    pub same_execution_domain: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressPolicy<'a> {
    pub allowed_domains: &'a [&'a str],
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
    if !policy.allowed_domains.is_empty() {
        let attributed_domain = destination.domain.filter(|domain| {
            destination.dns_observed
                && destination.ttl_valid
                && destination.same_execution_domain
                && policy.allowed_domains.contains(domain)
        });
        if attributed_domain.is_none() {
            return EgressDecision::DenyUnattributedDestination;
        }
    }
    EgressDecision::Allow
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
                    allowed_domains: &ALLOWED,
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
}
