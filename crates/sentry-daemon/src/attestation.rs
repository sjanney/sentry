// SPDX-License-Identifier: Apache-2.0
//! Redacted, independently verifiable execution-attestation envelope.

use sha2::{Digest, Sha256};

// These independent flags are serialized evidence dimensions; collapsing
// them would hide which specific completeness condition failed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub event_sequences: Vec<u64>,
    pub event_loss_count: u64,
    pub filesystem_decision_count: u64,
    pub credential_class_decision_count: u64,
    pub network_decision_count: u64,
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
    IncompleteEvidence,
    IntegrityMismatch,
}

impl ExecutionAttestation {
    /// Returns the canonical SHA-256 identity of this redacted envelope.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Verifies that the attestation is complete enough to claim protection.
    ///
    /// # Errors
    ///
    /// Returns an error when event ordering is invalid, evidence is incomplete,
    /// or the supplied digest does not match the canonical envelope.
    pub fn verify(&self, expected_digest: &[u8; 32]) -> Result<(), AttestationError> {
        if self.last_event_sequence < self.first_event_sequence {
            return Err(AttestationError::InvalidSequence);
        }
        if self.event_sequences.first().copied() != Some(self.first_event_sequence)
            || self.event_sequences.last().copied() != Some(self.last_event_sequence)
            || self
                .event_sequences
                .windows(2)
                .any(|pair| pair[1] <= pair[0])
        {
            return Err(AttestationError::InvalidSequence);
        }
        if self.event_loss_count != 0
            || self.partial_coverage
            || self.unsupported_guarantees
            || !self.enforcement_available
            || !self.verification_result
        {
            return Err(AttestationError::IncompleteEvidence);
        }
        if &self.digest() != expected_digest {
            return Err(AttestationError::IntegrityMismatch);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.policy_hash,
            self.policy_revision,
            self.policy_mode,
            self.enforcement_path,
            self.kernel_version,
            self.architecture,
            self.capability_fingerprint,
            self.execution_domain_id,
            self.process_tree_id,
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
            self.dns_decision_count,
            self.workflow_result,
            self.partial_coverage,
            self.unsupported_guarantees,
            self.enforcement_available,
            self.verifier_version,
            self.verification_result,
        )
        .into_bytes()
    }
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
            first_event_sequence: 1,
            last_event_sequence: 4,
            event_sequences: vec![1, 2, 3, 4],
            event_loss_count: 0,
            filesystem_decision_count: 1,
            credential_class_decision_count: 1,
            network_decision_count: 1,
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
    }
}
