// SPDX-License-Identifier: Apache-2.0
pub mod attestation;
pub mod audit;
pub mod capability;
pub mod lifecycle;
pub mod process_snapshot;

#[cfg(target_os = "linux")]
pub mod kernel_events;

use std::{
    collections::{HashMap, VecDeque},
    fs,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::Path,
};

use sentry_policy::TaintMask;
use sentry_types::EventHeader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedEvent {
    header: EventHeader,
    target: RedactedTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedactedTarget {
    Public(String),
    Redacted { class: &'static str },
}

impl RedactedTarget {
    #[must_use]
    pub fn from_observation(value: &str, sensitive_class: Option<&'static str>) -> Self {
        match sensitive_class {
            Some(class) => Self::Redacted { class },
            None => Self::Public(value.to_owned()),
        }
    }

    fn is_safe(&self) -> bool {
        let value: &str = match self {
            Self::Public(value) => value,
            Self::Redacted { class } => class,
        };
        !value.is_empty()
            && !value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Accepted { sequence: u64 },
    Dropped { total_dropped: u64 },
    Malformed { total_malformed: u64 },
    RedactionRejected { total_rejected: u64 },
    SequenceExhausted,
}

pub struct EventIngestor {
    capacity: usize,
    next_sequence: u64,
    dropped: u64,
    malformed: u64,
    redaction_rejected: u64,
    events: VecDeque<NormalizedEvent>,
}

impl EventIngestor {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_sequence: 1,
            dropped: 0,
            malformed: 0,
            redaction_rejected: 0,
            events: VecDeque::with_capacity(capacity),
        }
    }

    pub fn ingest(&mut self, bytes: &[u8], target: RedactedTarget) -> IngestOutcome {
        let Ok(mut header) = EventHeader::decode(bytes) else {
            self.malformed = self.malformed.saturating_add(1);
            return IngestOutcome::Malformed {
                total_malformed: self.malformed,
            };
        };
        if !target.is_safe() {
            self.redaction_rejected = self.redaction_rejected.saturating_add(1);
            return IngestOutcome::RedactionRejected {
                total_rejected: self.redaction_rejected,
            };
        }
        if self.events.len() == self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return IngestOutcome::Dropped {
                total_dropped: self.dropped,
            };
        }
        if self.next_sequence == u64::MAX {
            return IngestOutcome::SequenceExhausted;
        }
        header.sequence = self.next_sequence;
        self.next_sequence += 1;
        self.events.push_back(NormalizedEvent { header, target });
        IngestOutcome::Accepted {
            sequence: header.sequence,
        }
    }

    #[must_use]
    pub const fn dropped_count(&self) -> u64 {
        self.dropped
    }

    #[must_use]
    pub const fn malformed_count(&self) -> u64 {
        self.malformed
    }

    #[must_use]
    pub const fn redaction_rejected_count(&self) -> u64 {
        self.redaction_rejected
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessKey {
    pub tgid: u32,
    pub start_time_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Coverage {
    Launch,
    AttachPartial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessRecord {
    run_id: u64,
    parent: Option<ProcessKey>,
    coverage: Coverage,
    taint: TaintMask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackerError {
    Capacity,
    Cycle,
    DuplicateProcess,
    UnknownChild,
    UnknownParent,
}

pub struct ProcessTracker {
    capacity: usize,
    processes: HashMap<ProcessKey, ProcessRecord>,
}

impl ProcessTracker {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            processes: HashMap::with_capacity(capacity),
        }
    }

    /// # Errors
    ///
    /// Returns `DuplicateProcess` or `Capacity` when the identity cannot be tracked.
    pub fn register_launch(&mut self, key: ProcessKey, run_id: u64) -> Result<(), TrackerError> {
        self.insert(
            key,
            ProcessRecord {
                run_id,
                parent: None,
                coverage: Coverage::Launch,
                taint: TaintMask::default(),
            },
        )
    }

    /// # Errors
    ///
    /// Returns `DuplicateProcess` or `Capacity` when the identity cannot be tracked.
    pub fn register_attach(&mut self, key: ProcessKey, run_id: u64) -> Result<(), TrackerError> {
        self.insert(
            key,
            ProcessRecord {
                run_id,
                parent: None,
                coverage: Coverage::AttachPartial,
                taint: TaintMask::default(),
            },
        )
    }

    /// # Errors
    ///
    /// Returns `UnknownParent`, `DuplicateProcess`, or `Capacity` when attribution fails.
    pub fn fork(&mut self, parent: ProcessKey, child: ProcessKey) -> Result<(), TrackerError> {
        let parent_record = self
            .processes
            .get(&parent)
            .copied()
            .ok_or(TrackerError::UnknownParent)?;
        self.insert(
            child,
            ProcessRecord {
                run_id: parent_record.run_id,
                parent: Some(parent),
                coverage: parent_record.coverage,
                taint: parent_record.taint,
            },
        )
    }

    /// # Errors
    ///
    /// Returns `UnknownChild` or `UnknownParent` when either live identity is absent.
    pub fn reparent(
        &mut self,
        child: ProcessKey,
        new_parent: ProcessKey,
    ) -> Result<(), TrackerError> {
        if !self.processes.contains_key(&new_parent) {
            return Err(TrackerError::UnknownParent);
        }
        if !self.processes.contains_key(&child) {
            return Err(TrackerError::UnknownChild);
        }
        let mut cursor = Some(new_parent);
        while let Some(key) = cursor {
            if key == child {
                return Err(TrackerError::Cycle);
            }
            cursor = self.processes.get(&key).and_then(|record| record.parent);
        }
        let Some(child_record) = self.processes.get_mut(&child) else {
            return Err(TrackerError::UnknownChild);
        };
        child_record.parent = Some(new_parent);
        Ok(())
    }

    #[must_use]
    pub fn exit(&mut self, key: ProcessKey) -> bool {
        self.processes.remove(&key).is_some()
    }

    #[must_use]
    pub fn coverage(&self, key: ProcessKey) -> Option<Coverage> {
        self.processes.get(&key).map(|record| record.coverage)
    }

    #[must_use]
    pub fn can_claim_full_coverage(&self, key: ProcessKey) -> bool {
        self.coverage(key) == Some(Coverage::Launch)
    }

    /// Applies a monotonic taint transition before the caller evaluates egress.
    ///
    /// # Errors
    ///
    /// Returns `UnknownChild` when the process identity is no longer live.
    pub fn taint(
        &mut self,
        key: ProcessKey,
        transition: TaintMask,
    ) -> Result<TaintMask, TrackerError> {
        let record = self
            .processes
            .get_mut(&key)
            .ok_or(TrackerError::UnknownChild)?;
        record.taint.secret |= transition.secret;
        record.taint.untrusted_input |= transition.untrusted_input;
        Ok(record.taint)
    }

    /// Returns the taint that an immediate subsequent egress decision must read.
    #[must_use]
    pub fn taint_at_egress(&self, key: ProcessKey) -> Option<TaintMask> {
        self.processes.get(&key).map(|record| record.taint)
    }

    /// Records exec without clearing taint or changing coverage.
    ///
    /// # Errors
    ///
    /// Returns `UnknownChild` when the process identity is no longer live.
    pub fn exec(&mut self, key: ProcessKey) -> Result<(), TrackerError> {
        self.processes
            .contains_key(&key)
            .then_some(())
            .ok_or(TrackerError::UnknownChild)
    }

    fn insert(&mut self, key: ProcessKey, record: ProcessRecord) -> Result<(), TrackerError> {
        if self.processes.contains_key(&key) {
            return Err(TrackerError::DuplicateProcess);
        }
        if self.processes.len() == self.capacity {
            return Err(TrackerError::Capacity);
        }
        self.processes.insert(key, record);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialClass {
    SshKey,
    CloudCredential,
    DotEnv,
    Keyring,
    TokenCache,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileAccessOutcome {
    Attempted,
    Succeeded,
    Denied { errno: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedTarget {
    Public(String),
    Credential(CredentialClass),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAccessObservation {
    pub target: ObservedTarget,
    pub identity: Option<FileIdentity>,
    pub outcome: FileAccessOutcome,
}

pub struct CredentialCatalog {
    known: HashMap<FileIdentity, CredentialClass>,
}

impl CredentialCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    #[must_use]
    pub fn observe(&mut self, path: &Path, outcome: FileAccessOutcome) -> FileAccessObservation {
        let resolved = fs::canonicalize(path).ok();
        let identity = resolved
            .as_deref()
            .and_then(|resolved_path| fs::metadata(resolved_path).ok())
            .map(|metadata| FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        let classified = classify_path(path)
            .or_else(|| resolved.as_deref().and_then(classify_path))
            .or_else(|| identity.and_then(|identity| self.known.get(&identity).copied()));
        if let (Some(identity), Some(class)) = (identity, classified) {
            self.known.insert(identity, class);
        }
        let target = match classified {
            Some(class) => ObservedTarget::Credential(class),
            None => ObservedTarget::Public(path.display().to_string()),
        };
        FileAccessObservation {
            target,
            identity,
            outcome,
        }
    }
}

impl Default for CredentialCatalog {
    fn default() -> Self {
        Self::new()
    }
}

fn classify_path(path: &Path) -> Option<CredentialClass> {
    let text = path.to_string_lossy();
    let file_name = path.file_name()?.to_string_lossy();
    let in_ssh_directory = path
        .components()
        .any(|component| component.as_os_str() == ".ssh");
    if in_ssh_directory && file_name.starts_with("id_") {
        Some(CredentialClass::SshKey)
    } else if text.ends_with("/.aws/credentials")
        || text.contains("/gcloud/")
        || text.contains("/.azure/")
    {
        Some(CredentialClass::CloudCredential)
    } else if file_name == ".env" || file_name.starts_with(".env.") {
        Some(CredentialClass::DotEnv)
    } else if text.contains("keyring") {
        Some(CredentialClass::Keyring)
    } else if file_name.contains("token") || text.contains("token-cache") {
        Some(CredentialClass::TokenCache)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverProvenance {
    SystemResolver,
    AgentObserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsEvidence {
    pub domain: String,
    pub resolver: IpAddr,
    pub provenance: ResolverProvenance,
    pub expires_at_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionTarget {
    DnsCorrelated {
        domain: String,
        resolver: IpAddr,
        provenance: ResolverProvenance,
    },
    UnknownDestination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionObservation {
    pub run_id: u64,
    pub destination: IpAddr,
    pub protocol: TransportProtocol,
    pub target: ConnectionTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsCacheError {
    Capacity,
}

/// Bounded, run-scoped evidence for relating observed DNS answers to connects.
pub struct DnsEvidenceCache {
    capacity: usize,
    evidence: HashMap<(u64, IpAddr), DnsEvidence>,
}

impl DnsEvidenceCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            evidence: HashMap::with_capacity(capacity),
        }
    }

    /// # Errors
    ///
    /// Returns `Capacity` when an unexpired entry cannot be retained.
    pub fn record(
        &mut self,
        run_id: u64,
        destination: IpAddr,
        evidence: DnsEvidence,
        now_ns: u64,
    ) -> Result<(), DnsCacheError> {
        self.expire(now_ns);
        let key = (run_id, destination);
        if !self.evidence.contains_key(&key) && self.evidence.len() == self.capacity {
            return Err(DnsCacheError::Capacity);
        }
        self.evidence.insert(key, evidence);
        Ok(())
    }

    #[must_use]
    pub fn observe_connect(
        &mut self,
        run_id: u64,
        destination: IpAddr,
        protocol: TransportProtocol,
        now_ns: u64,
    ) -> ConnectionObservation {
        self.expire(now_ns);
        let target = self.evidence.get(&(run_id, destination)).map_or(
            ConnectionTarget::UnknownDestination,
            |evidence| ConnectionTarget::DnsCorrelated {
                domain: evidence.domain.clone(),
                resolver: evidence.resolver,
                provenance: evidence.provenance,
            },
        );
        ConnectionObservation {
            run_id,
            destination,
            protocol,
            target,
        }
    }

    fn expire(&mut self, now_ns: u64) {
        self.evidence
            .retain(|_, evidence| evidence.expires_at_ns > now_ns);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use sentry_types::{EVENT_HEADER_SIZE, EVENT_HEADER_SIZE_U32, EventKind, ProcessIdentity};

    fn encoded_exec() -> [u8; EVENT_HEADER_SIZE] {
        EventHeader::new(
            EventKind::Exec,
            EVENT_HEADER_SIZE_U32,
            0,
            1,
            ProcessIdentity {
                run_id: 2,
                tgid: 3,
                tid: 4,
                parent_tgid: 0,
            },
        )
        .encode()
    }

    #[test]
    fn ingestion_assigns_sequences_and_never_evicts_evidence() {
        let mut ingestor = EventIngestor::new(1);
        assert_eq!(
            ingestor.ingest(
                &encoded_exec(),
                RedactedTarget::Public("source_file".to_owned())
            ),
            IngestOutcome::Accepted { sequence: 1 }
        );
        assert_eq!(
            ingestor.ingest(
                &encoded_exec(),
                RedactedTarget::Public("source_library".to_owned())
            ),
            IngestOutcome::Dropped { total_dropped: 1 }
        );
        assert_eq!(ingestor.event_count(), 1);
        assert_eq!(ingestor.dropped_count(), 1);
    }

    #[test]
    fn malformed_and_secret_targets_are_explicit() {
        let mut ingestor = EventIngestor::new(1);
        assert_eq!(
            ingestor.ingest(&[], RedactedTarget::Public("ignored".to_owned())),
            IngestOutcome::Malformed { total_malformed: 1 }
        );
        assert_eq!(
            RedactedTarget::from_observation("/home/user/.aws/credentials", Some("credential")),
            RedactedTarget::Redacted {
                class: "credential"
            }
        );
        assert_eq!(
            ingestor.ingest(
                &encoded_exec(),
                RedactedTarget::Public("/home/user/.aws/credentials".to_owned())
            ),
            IngestOutcome::RedactionRejected { total_rejected: 1 }
        );
        assert_eq!(ingestor.redaction_rejected_count(), 1);
    }

    #[test]
    fn malformed_events_do_not_consume_local_sequence_numbers() {
        let mut ingestor = EventIngestor::new(2);
        assert_eq!(
            ingestor.ingest(
                &[0; EVENT_HEADER_SIZE - 1],
                RedactedTarget::Public("bad".to_owned())
            ),
            IngestOutcome::Malformed { total_malformed: 1 }
        );
        assert_eq!(
            ingestor.ingest(&encoded_exec(), RedactedTarget::Public("ok".to_owned())),
            IngestOutcome::Accepted { sequence: 1 }
        );
    }

    fn key(tgid: u32, start_time_ns: u64) -> ProcessKey {
        ProcessKey {
            tgid,
            start_time_ns,
        }
    }

    #[test]
    fn launch_tree_inherits_coverage_and_cleans_up_short_lived_children() {
        let root = key(10, 100);
        let child = key(11, 101);
        let mut tracker = ProcessTracker::new(2);
        tracker.register_launch(root, 7).unwrap();
        tracker.fork(root, child).unwrap();
        assert!(tracker.can_claim_full_coverage(child));
        assert!(tracker.exit(child));
        assert!(!tracker.exit(child));
        assert_eq!(tracker.coverage(child), None);
    }

    #[test]
    fn pid_reuse_is_not_the_same_process() {
        let old = key(42, 100);
        let replacement = key(42, 200);
        let mut tracker = ProcessTracker::new(2);
        tracker.register_launch(old, 1).unwrap();
        assert!(tracker.exit(old));
        tracker.register_attach(replacement, 2).unwrap();
        assert_eq!(tracker.coverage(old), None);
        assert_eq!(tracker.coverage(replacement), Some(Coverage::AttachPartial));
    }

    #[test]
    fn reparenting_preserves_run_and_attach_coverage_limit() {
        let attached = key(10, 100);
        let child = key(11, 101);
        let adopted_parent = key(1, 1);
        let mut tracker = ProcessTracker::new(3);
        tracker.register_attach(attached, 7).unwrap();
        tracker.register_launch(adopted_parent, 8).unwrap();
        tracker.fork(attached, child).unwrap();
        tracker.reparent(child, adopted_parent).unwrap();
        assert!(!tracker.can_claim_full_coverage(child));
    }

    #[test]
    fn reparenting_rejects_cycles_and_unknown_children() {
        let parent = key(1, 1);
        let child = key(2, 2);
        let mut tracker = ProcessTracker::new(2);
        tracker.register_launch(parent, 1).unwrap();
        tracker.fork(parent, child).unwrap();
        assert_eq!(tracker.reparent(parent, child), Err(TrackerError::Cycle));
        assert_eq!(
            tracker.reparent(key(3, 3), parent),
            Err(TrackerError::UnknownChild)
        );
    }

    #[test]
    fn capacity_and_unknown_parent_are_explicit_failures() {
        let root = key(10, 100);
        let child = key(11, 101);
        let mut tracker = ProcessTracker::new(1);
        assert_eq!(tracker.fork(root, child), Err(TrackerError::UnknownParent));
        tracker.register_launch(root, 1).unwrap();
        assert_eq!(tracker.fork(root, child), Err(TrackerError::Capacity));
    }

    #[test]
    fn taint_is_monotonic_and_inherited_before_egress() {
        let parent = key(10, 100);
        let child = key(11, 101);
        let mut tracker = ProcessTracker::new(2);
        tracker.register_launch(parent, 1).unwrap();
        let taint = tracker
            .taint(
                parent,
                TaintMask {
                    secret: true,
                    untrusted_input: false,
                },
            )
            .unwrap();
        assert!(taint.secret);
        tracker.fork(parent, child).unwrap();
        tracker.exec(child).unwrap();
        assert_eq!(tracker.taint_at_egress(child), Some(taint));
        assert_eq!(
            tracker.taint(
                child,
                TaintMask {
                    secret: false,
                    untrusted_input: true,
                }
            ),
            Ok(TaintMask {
                secret: true,
                untrusted_input: true,
            })
        );
        assert!(tracker.exit(child));
        assert_eq!(tracker.taint_at_egress(child), None);
    }

    #[test]
    fn exec_preserves_taint_for_the_next_egress_decision() {
        let process = key(42, 4200);
        let mut tracker = ProcessTracker::new(1);
        tracker.register_launch(process, 9).unwrap();
        tracker
            .taint(
                process,
                TaintMask {
                    secret: false,
                    untrusted_input: true,
                },
            )
            .unwrap();

        tracker.exec(process).unwrap();

        assert_eq!(
            tracker.taint_at_egress(process),
            Some(TaintMask {
                secret: false,
                untrusted_input: true,
            })
        );
    }

    #[test]
    fn credential_catalog_redacts_paths_and_keeps_identity_across_aliases_and_renames() {
        use std::{fs, os::unix::fs::symlink};

        let root = std::env::temp_dir().join(format!("sentry-files-{}", std::process::id()));
        let ssh = root.join(".ssh/id_ed25519");
        let hardlink = root.join("hard-linked-key");
        let symlink_path = root.join("alias");
        let renamed = root.join("renamed-key");
        fs::create_dir_all(ssh.parent().unwrap()).unwrap();
        fs::write(&ssh, "fixture-only").unwrap();
        fs::hard_link(&ssh, &hardlink).unwrap();
        symlink(&ssh, &symlink_path).unwrap();

        let mut catalog = CredentialCatalog::new();
        let first = catalog.observe(&ssh, FileAccessOutcome::Succeeded);
        let via_hardlink = catalog.observe(&hardlink, FileAccessOutcome::Succeeded);
        let via_symlink = catalog.observe(&symlink_path, FileAccessOutcome::Succeeded);
        fs::rename(&ssh, &renamed).unwrap();
        let via_rename = catalog.observe(&renamed, FileAccessOutcome::Succeeded);
        assert_eq!(
            first.target,
            ObservedTarget::Credential(CredentialClass::SshKey)
        );
        assert_eq!(
            via_hardlink.target,
            ObservedTarget::Credential(CredentialClass::SshKey)
        );
        assert_eq!(
            via_symlink.target,
            ObservedTarget::Credential(CredentialClass::SshKey)
        );
        assert_eq!(first.identity, via_hardlink.identity);
        assert_eq!(first.identity, via_rename.identity);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_catalog_recognizes_each_fixture_class_without_storing_content() {
        use std::fs;

        let root =
            std::env::temp_dir().join(format!("sentry-credential-fixtures-{}", std::process::id()));
        let fixtures = [
            (
                root.join(".aws/credentials"),
                CredentialClass::CloudCredential,
            ),
            (root.join(".env.production"), CredentialClass::DotEnv),
            (
                root.join("keyrings/login.keyring"),
                CredentialClass::Keyring,
            ),
            (
                root.join(".cache/token-cache/tokens.json"),
                CredentialClass::TokenCache,
            ),
        ];
        let mut catalog = CredentialCatalog::new();

        for (path, class) in fixtures {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "fixture-only").unwrap();
            let observation = catalog.observe(&path, FileAccessOutcome::Attempted);
            assert_eq!(observation.target, ObservedTarget::Credential(class));
            assert_eq!(observation.outcome, FileAccessOutcome::Attempted);
            assert!(observation.identity.is_some());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_classifier_handles_relative_ssh_paths() {
        let observation = CredentialCatalog::new()
            .observe(Path::new(".ssh/id_rsa"), FileAccessOutcome::Attempted);
        assert_eq!(
            observation.target,
            ObservedTarget::Credential(CredentialClass::SshKey)
        );
    }

    fn dns_evidence(domain: &str, resolver: &str, expires_at_ns: u64) -> DnsEvidence {
        DnsEvidence {
            domain: domain.to_owned(),
            resolver: resolver.parse().unwrap(),
            provenance: ResolverProvenance::SystemResolver,
            expires_at_ns,
        }
    }

    #[test]
    fn dns_evidence_correlates_tcp_ipv4_and_udp_ipv6_within_a_run() {
        let mut cache = DnsEvidenceCache::new(2);
        let ipv4 = "203.0.113.7".parse().unwrap();
        let ipv6 = "2001:db8::7".parse().unwrap();
        cache
            .record(5, ipv4, dns_evidence("api.example", "192.0.2.53", 10), 1)
            .unwrap();
        cache
            .record(5, ipv6, dns_evidence("dns.example", "2001:db8::53", 10), 1)
            .unwrap();

        let tcp = cache.observe_connect(5, ipv4, TransportProtocol::Tcp, 2);
        let udp = cache.observe_connect(5, ipv6, TransportProtocol::Udp, 2);
        assert_eq!(tcp.protocol, TransportProtocol::Tcp);
        assert_eq!(udp.protocol, TransportProtocol::Udp);
        assert!(matches!(
            tcp.target,
            ConnectionTarget::DnsCorrelated { ref domain, .. } if domain == "api.example"
        ));
        assert!(matches!(
            udp.target,
            ConnectionTarget::DnsCorrelated { ref domain, .. } if domain == "dns.example"
        ));
    }

    #[test]
    fn dns_evidence_is_run_scoped_expires_and_is_bounded() {
        let mut cache = DnsEvidenceCache::new(1);
        let destination = "203.0.113.9".parse().unwrap();
        cache
            .record(
                1,
                destination,
                dns_evidence("short.example", "192.0.2.53", 5),
                1,
            )
            .unwrap();
        assert_eq!(
            cache.record(
                1,
                "203.0.113.10".parse().unwrap(),
                dns_evidence("other.example", "192.0.2.53", 6),
                1
            ),
            Err(DnsCacheError::Capacity)
        );
        assert_eq!(
            cache
                .observe_connect(2, destination, TransportProtocol::Tcp, 2)
                .target,
            ConnectionTarget::UnknownDestination
        );
        assert_eq!(
            cache
                .observe_connect(1, destination, TransportProtocol::Tcp, 5)
                .target,
            ConnectionTarget::UnknownDestination
        );
        cache
            .record(
                1,
                "203.0.113.10".parse().unwrap(),
                dns_evidence("other.example", "192.0.2.53", 10),
                5,
            )
            .unwrap();
    }

    #[test]
    fn denied_credential_attempt_never_exposes_the_path() {
        let mut catalog = CredentialCatalog::new();
        let observation = catalog.observe(
            Path::new("/home/agent/.aws/credentials"),
            FileAccessOutcome::Denied { errno: 13 },
        );
        assert_eq!(
            observation.target,
            ObservedTarget::Credential(CredentialClass::CloudCredential)
        );
        assert_eq!(observation.outcome, FileAccessOutcome::Denied { errno: 13 });
    }
}
