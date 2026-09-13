// SPDX-License-Identifier: Apache-2.0
//! Redacted, independently verifiable execution-attestation envelope.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The common agent egress paths Sentry reports independently.
///
/// This taxonomy does not claim to be exhaustive. Connections outside these
/// paths are counted separately as unclassified network decisions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPath {
    McpA2aToolCall,
    ShelledCli,
    ImprovisedHttp,
    AgentAuthoredScript,
}

impl EgressPath {
    const ALL: [Self; 4] = [
        Self::McpA2aToolCall,
        Self::ShelledCli,
        Self::ImprovisedHttp,
        Self::AgentAuthoredScript,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::McpA2aToolCall => "mcp_a2a_tool_call",
            Self::ShelledCli => "shelled_cli",
            Self::ImprovisedHttp => "improvised_http",
            Self::AgentAuthoredScript => "agent_authored_script",
        }
    }
}

/// Whether Sentry's evidence source could observe a path on this run's host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPathCoverage {
    Full,
    Partial,
    Unavailable,
}

/// Redacted, per-path counts and coverage. Script contents and paths are never
/// included; provenance for authored scripts belongs in a separate digest-only
/// event record once live collection is wired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPathEvidence {
    pub path: EgressPath,
    pub coverage: EgressPathCoverage,
    pub sentry_network_decision_count: u64,
    pub mcp_boundary_record_count: u64,
}

// These independent flags are serialized evidence dimensions; collapsing
// them would hide which specific completeness condition failed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttestation {
    pub policy_hash: u64,
    pub policy_revision: u64,
    pub policy_mode: String,
    pub enforcement_path: String,
    pub kernel_version: String,
    pub architecture: String,
    pub capability_fingerprint: String,
    pub execution_domain_id: String,
    pub process_tree_id: String,
    pub root_tgid: u32,
    pub root_start_time_ticks: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub event_sequences: Vec<u64>,
    pub event_loss_count: u64,
    pub filesystem_decision_count: u64,
    pub credential_class_decision_count: u64,
    pub network_decision_count: u64,
    pub egress_path_evidence: Vec<EgressPathEvidence>,
    pub unclassified_network_decision_count: u64,
    pub dns_decision_count: u64,
    pub workflow_result: String,
    pub partial_coverage: bool,
    pub unsupported_guarantees: bool,
    pub enforcement_available: bool,
    pub verifier_version: String,
    pub verification_result: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationError {
    InvalidSequence,
    InvalidEgressPathEvidence,
    IncompleteEvidence,
    EnvironmentMismatch,
    SensitiveField,
    IntegrityMismatch,
}

impl ExecutionAttestation {
    /// Returns the canonical SHA-256 identity of this redacted envelope.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Returns the canonical, redacted bytes covered by `digest`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_encoding()
    }

    /// Serializes the redacted envelope for independent verification.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if encoding fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Strictly decodes a redacted envelope from JSON.
    ///
    /// # Errors
    ///
    /// Returns a JSON error for malformed input or unknown fields.
    pub fn from_json(input: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(input)
    }

    /// Verifies that the attestation is complete enough to claim protection.
    ///
    /// # Errors
    ///
    /// Returns an error when event ordering is invalid, evidence is incomplete,
    /// or the supplied digest does not match the canonical envelope.
    pub fn verify(&self, expected_digest: &[u8; 32]) -> Result<(), AttestationError> {
        self.validate_redaction()?;
        self.validate_egress_path_evidence()?;
        if self.last_event_sequence < self.first_event_sequence {
            return Err(AttestationError::InvalidSequence);
        }
        if self.event_sequences.first().copied() != Some(self.first_event_sequence)
            || self.event_sequences.last().copied() != Some(self.last_event_sequence)
            || self
                .event_sequences
                .windows(2)
                .any(|pair| pair[1] != pair[0].saturating_add(1))
        {
            return Err(AttestationError::InvalidSequence);
        }
        if self.event_loss_count != 0
            || self.partial_coverage
            || self.unsupported_guarantees
            || !self.enforcement_available
            || !self.verification_result
            || self.unclassified_network_decision_count != 0
            || self
                .egress_path_evidence
                .iter()
                .any(|evidence| evidence.coverage != EgressPathCoverage::Full)
        {
            return Err(AttestationError::IncompleteEvidence);
        }
        if &self.digest() != expected_digest {
            return Err(AttestationError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Rejects values that look like paths or multiline payloads in fields
    /// intended to contain identifiers and redacted summaries.
    ///
    /// # Errors
    ///
    /// Returns `SensitiveField` when a field contains a path separator or
    /// control character.
    pub fn validate_redaction(&self) -> Result<(), AttestationError> {
        let values = [
            &self.policy_mode,
            &self.enforcement_path,
            &self.kernel_version,
            &self.architecture,
            &self.capability_fingerprint,
            &self.execution_domain_id,
            &self.process_tree_id,
            &self.workflow_result,
            &self.verifier_version,
        ];
        if values.iter().any(|value| {
            value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
        }) {
            return Err(AttestationError::SensitiveField);
        }
        Ok(())
    }

    /// Verifies that every common egress path has a distinct coverage flag and
    /// that protocol-boundary records are never invented for non-protocol
    /// paths. The four paths are deliberately not treated as exhaustive.
    ///
    /// # Errors
    ///
    /// Returns `InvalidEgressPathEvidence` for missing, reordered, duplicated,
    /// or contradictory per-path records.
    pub fn validate_egress_path_evidence(&self) -> Result<(), AttestationError> {
        if self.egress_path_evidence.len() != EgressPath::ALL.len()
            || self
                .egress_path_evidence
                .iter()
                .zip(EgressPath::ALL)
                .any(|(evidence, expected)| evidence.path != expected)
        {
            return Err(AttestationError::InvalidEgressPathEvidence);
        }

        let classified_count = self
            .egress_path_evidence
            .iter()
            .try_fold(0_u64, |total, evidence| {
                total.checked_add(evidence.sentry_network_decision_count)
            });
        if classified_count
            .and_then(|count| count.checked_add(self.unclassified_network_decision_count))
            != Some(self.network_decision_count)
        {
            return Err(AttestationError::InvalidEgressPathEvidence);
        }

        for evidence in &self.egress_path_evidence {
            let protocol_path = evidence.path == EgressPath::McpA2aToolCall;
            if (!protocol_path && evidence.mcp_boundary_record_count != 0)
                || evidence.mcp_boundary_record_count > evidence.sentry_network_decision_count
            {
                return Err(AttestationError::InvalidEgressPathEvidence);
            }
        }
        Ok(())
    }

    /// Checks that the verifier observed the same host identity recorded by
    /// the attestation.
    ///
    /// # Errors
    ///
    /// Returns `EnvironmentMismatch` if any supplied identity differs.
    pub fn verify_environment(
        &self,
        kernel_version: &str,
        architecture: &str,
        capability_fingerprint: &str,
    ) -> Result<(), AttestationError> {
        if self.kernel_version != kernel_version
            || self.architecture != architecture
            || self.capability_fingerprint != capability_fingerprint
        {
            return Err(AttestationError::EnvironmentMismatch);
        }
        Ok(())
    }

    /// Verifies the root process identity, including its start time so PID
    /// reuse cannot be mistaken for the original execution.
    ///
    /// # Errors
    ///
    /// Returns `EnvironmentMismatch` if either identity component differs.
    pub fn verify_process_identity(
        &self,
        root_tgid: u32,
        root_start_time_ticks: u64,
    ) -> Result<(), AttestationError> {
        if self.root_tgid != root_tgid || self.root_start_time_ticks != root_start_time_ticks {
            return Err(AttestationError::EnvironmentMismatch);
        }
        Ok(())
    }

    fn canonical_encoding(&self) -> Vec<u8> {
        format!(
            "v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.policy_hash,
            self.policy_revision,
            hex(self.policy_mode.as_bytes()),
            hex(self.enforcement_path.as_bytes()),
            hex(self.kernel_version.as_bytes()),
            hex(self.architecture.as_bytes()),
            hex(self.capability_fingerprint.as_bytes()),
            hex(self.execution_domain_id.as_bytes()),
            hex(self.process_tree_id.as_bytes()),
            self.root_tgid,
            self.root_start_time_ticks,
            self.first_event_sequence,
            self.last_event_sequence,
            self.event_sequences
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.event_loss_count,
            self.filesystem_decision_count,
            self.credential_class_decision_count,
            self.network_decision_count,
            self.egress_path_evidence
                .iter()
                .map(|evidence| format!(
                    "{}:{}:{}:{}",
                    evidence.path.as_str(),
                    match evidence.coverage {
                        EgressPathCoverage::Full => "full",
                        EgressPathCoverage::Partial => "partial",
                        EgressPathCoverage::Unavailable => "unavailable",
                    },
                    evidence.sentry_network_decision_count,
                    evidence.mcp_boundary_record_count,
                ))
                .collect::<Vec<_>>()
                .join(","),
            self.unclassified_network_decision_count,
            self.dns_decision_count,
            hex(self.workflow_result.as_bytes()),
            self.partial_coverage,
            self.unsupported_guarantees,
            self.enforcement_available,
            hex(self.verifier_version.as_bytes()),
            self.verification_result,
        )
        .into_bytes()
    }
}

fn hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> ExecutionAttestation {
        ExecutionAttestation {
            policy_hash: 7,
            policy_revision: 3,
            policy_mode: "enforce".to_owned(),
            enforcement_path: "bpf_lsm+cgroup".to_owned(),
            kernel_version: "6.12.54".to_owned(),
            architecture: "aarch64".to_owned(),
            capability_fingerprint: "caps-v1".to_owned(),
            execution_domain_id: "domain-1".to_owned(),
            process_tree_id: "tree-1".to_owned(),
            root_tgid: 100,
            root_start_time_ticks: 12345,
            first_event_sequence: 1,
            last_event_sequence: 4,
            event_sequences: vec![1, 2, 3, 4],
            event_loss_count: 0,
            filesystem_decision_count: 1,
            credential_class_decision_count: 1,
            network_decision_count: 4,
            egress_path_evidence: vec![
                EgressPathEvidence {
                    path: EgressPath::McpA2aToolCall,
                    coverage: EgressPathCoverage::Full,
                    sentry_network_decision_count: 1,
                    mcp_boundary_record_count: 1,
                },
                EgressPathEvidence {
                    path: EgressPath::ShelledCli,
                    coverage: EgressPathCoverage::Full,
                    sentry_network_decision_count: 1,
                    mcp_boundary_record_count: 0,
                },
                EgressPathEvidence {
                    path: EgressPath::ImprovisedHttp,
                    coverage: EgressPathCoverage::Full,
                    sentry_network_decision_count: 1,
                    mcp_boundary_record_count: 0,
                },
                EgressPathEvidence {
                    path: EgressPath::AgentAuthoredScript,
                    coverage: EgressPathCoverage::Full,
                    sentry_network_decision_count: 1,
                    mcp_boundary_record_count: 0,
                },
            ],
            unclassified_network_decision_count: 0,
            dns_decision_count: 1,
            workflow_result: "passed".to_owned(),
            partial_coverage: false,
            unsupported_guarantees: false,
            enforcement_available: true,
            verifier_version: "sentry-attestation-v1".to_owned(),
            verification_result: true,
        }
    }

    #[test]
    fn complete_attestation_verifies_and_tampering_is_detected() {
        let mut attestation = complete();
        let digest = attestation.digest();
        assert_eq!(attestation.verify(&digest), Ok(()));
        attestation.policy_revision += 1;
        assert_eq!(
            attestation.verify(&digest),
            Err(AttestationError::IntegrityMismatch)
        );
    }

    #[test]
    fn incomplete_evidence_cannot_claim_protection() {
        let mut attestation = complete();
        attestation.event_loss_count = 1;
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::IncompleteEvidence)
        );
        attestation.event_loss_count = 0;
        attestation.partial_coverage = true;
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::IncompleteEvidence)
        );
    }

    #[test]
    fn path_evidence_distinguishes_protocol_from_kernel_observation() {
        let attestation = complete();
        assert_eq!(attestation.validate_egress_path_evidence(), Ok(()));

        let mut invalid = attestation.clone();
        invalid.egress_path_evidence[1].mcp_boundary_record_count = 1;
        assert_eq!(
            invalid.verify(&invalid.digest()),
            Err(AttestationError::InvalidEgressPathEvidence)
        );

        let mut partial = attestation;
        partial.egress_path_evidence[3].coverage = EgressPathCoverage::Partial;
        assert_eq!(
            partial.verify(&partial.digest()),
            Err(AttestationError::IncompleteEvidence)
        );

        let mut overflow = complete();
        overflow.egress_path_evidence[0].sentry_network_decision_count = u64::MAX;
        overflow.egress_path_evidence[1].sentry_network_decision_count = 1;
        assert_eq!(
            overflow.verify(&overflow.digest()),
            Err(AttestationError::InvalidEgressPathEvidence)
        );
    }

    #[test]
    fn reordered_or_truncated_event_sequences_are_rejected() {
        let mut attestation = complete();
        attestation.event_sequences = vec![1, 3, 2, 4];
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::InvalidSequence)
        );
        attestation.event_sequences = vec![1, 2, 3];
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::InvalidSequence)
        );
        attestation.event_sequences = vec![1, 3, 4];
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::InvalidSequence)
        );
    }

    #[test]
    fn delimiter_characters_have_unambiguous_canonical_encoding() {
        let first = complete();
        let mut second = complete();
        second.policy_mode = "enforce|bpf".to_owned();
        assert_ne!(first.digest(), second.digest());
        second = first.clone();
        second.verifier_version = "sentry|attestation-v1".to_owned();
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn environment_mismatch_is_rejected() {
        let attestation = complete();
        assert_eq!(
            attestation.verify_environment("6.12.54", "aarch64", "caps-v1"),
            Ok(())
        );
        assert_eq!(
            attestation.verify_environment("6.12.55", "aarch64", "caps-v1"),
            Err(AttestationError::EnvironmentMismatch)
        );
        assert_eq!(attestation.verify_process_identity(100, 12345), Ok(()));
        assert_eq!(
            attestation.verify_process_identity(100, 12346),
            Err(AttestationError::EnvironmentMismatch)
        );
    }

    #[test]
    fn path_like_redacted_values_are_rejected() {
        let mut attestation = complete();
        attestation.process_tree_id = "/proc/100".to_owned();
        assert_eq!(
            attestation.verify(&attestation.digest()),
            Err(AttestationError::SensitiveField)
        );
    }

    #[test]
    fn json_round_trip_is_strict_and_preserves_digest() {
        let attestation = complete();
        let json = attestation.to_json().unwrap();
        let decoded = ExecutionAttestation::from_json(&json).unwrap();
        assert_eq!(decoded, attestation);
        assert_eq!(decoded.digest(), attestation.digest());
        let mut tampered = json.trim_end_matches('}').to_owned();
        tampered.push_str(",\"unexpected\":true}");
        assert!(ExecutionAttestation::from_json(&tampered).is_err());
    }
}
