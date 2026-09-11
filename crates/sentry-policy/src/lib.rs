// SPDX-License-Identifier: Apache-2.0
//! Policy semantics shared by generation, dry-run, and enforcement.

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
}
