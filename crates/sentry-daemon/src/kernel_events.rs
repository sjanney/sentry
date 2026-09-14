// SPDX-License-Identifier: Apache-2.0
//! Linux tracepoint collection for the Sentry event ABI.
//!
//! This module observes process exec, fork, and exit through the MVP probe
//! object. It deliberately does not load policy maps or make an enforcement
//! claim. Lifecycle observations are not applied to [`crate::ProcessTracker`]
//! because this ABI does not yet carry the start-time identity needed to avoid
//! PID reuse errors.

use std::{
    collections::HashMap as StdHashMap,
    error::Error,
    fmt, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use aya::{
    Btf, Ebpf,
    maps::{HashMap, MapData, RingBuf},
    programs::{Lsm, RawTracePoint, TracePoint},
};
use sentry_types::{CredentialClass, EventHeader, EventKind, FileAccessStatus, FileOpenEvent};

use crate::{
    EventIngestor, FileAccessObservation, FileAccessOutcome, FileIdentity, IngestOutcome,
    ObservedTarget, RedactedTarget,
};

const EXEC_TARGET: &str = "process_exec";
const FORK_TARGET: &str = "process_fork";
const EXIT_TARGET: &str = "process_exit";
const UNKNOWN_TARGET: &str = "process_event";

#[derive(Debug)]
pub struct KernelEventError(String);

impl fmt::Display for KernelEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for KernelEventError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelDrain {
    pub read: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub malformed: u64,
    pub redaction_rejected: u64,
    pub sequence_exhausted: u64,
    pub exec: u64,
    pub fork: u64,
    pub exit: u64,
}

/// Owns the loaded eBPF object, its tracepoint link, and the `events` ring buffer.
pub struct ProcessEventReader {
    events: RingBuf<MapData>,
    // The loaded object retains the attached tracepoint program and link.
    _ebpf: Ebpf,
}

impl ProcessEventReader {
    /// Loads the supplied BPF object and attaches its process lifecycle programs.
    ///
    /// # Errors
    ///
    /// Returns an error when the object, tracepoint program, or `events` map is
    /// unavailable, or when the kernel rejects loading or attaching the program.
    pub fn load(object_path: &Path) -> Result<Self, KernelEventError> {
        let object = fs::read(object_path)
            .map_err(|error| KernelEventError(format!("read BPF object: {error}")))?;
        let mut ebpf = Ebpf::load(&object)
            .map_err(|error| KernelEventError(format!("load BPF object: {error}")))?;
        for (program_name, tracepoint_name) in [
            ("capture_exec", "sched_process_exec"),
            ("capture_fork", "sched_process_fork"),
            ("capture_exit", "sched_process_exit"),
        ] {
            let program: &mut TracePoint = ebpf
                .program_mut(program_name)
                .ok_or_else(|| KernelEventError(format!("{program_name} program not found")))?
                .try_into()
                .map_err(|error| {
                    KernelEventError(format!("open {program_name} program: {error}"))
                })?;
            program.load().map_err(|error| {
                KernelEventError(format!("load {program_name} program: {error}"))
            })?;
            program.attach("sched", tracepoint_name).map_err(|error| {
                KernelEventError(format!("attach {program_name} tracepoint: {error}"))
            })?;
        }
        let events = RingBuf::try_from(
            ebpf.take_map("events")
                .ok_or_else(|| KernelEventError("events map not found".to_owned()))?,
        )
        .map_err(|error| KernelEventError(format!("open events ring buffer: {error}")))?;
        Ok(Self {
            events,
            _ebpf: ebpf,
        })
    }

    /// Drains at most `maximum` records into the bounded userspace ingestor.
    ///
    /// The BPF program emits kernel identity and timestamp fields. The ingestor
    /// assigns a local sequence and owns the redacted target label.
    pub fn drain(&mut self, ingestor: &mut EventIngestor, maximum: usize) -> KernelDrain {
        let mut result = KernelDrain::default();
        for _ in 0..maximum {
            let Some(event) = self.events.next() else {
                break;
            };
            result.read = result.read.saturating_add(1);
            let kind = EventHeader::decode(&event).ok().map(|header| header.kind);
            let target = match kind {
                Some(EventKind::Exec) => EXEC_TARGET,
                Some(EventKind::Fork) => FORK_TARGET,
                Some(EventKind::Exit) => EXIT_TARGET,
                _ => UNKNOWN_TARGET,
            };
            match ingestor.ingest(&event, RedactedTarget::Public(target.to_owned())) {
                IngestOutcome::Accepted { .. } => {
                    result.accepted = result.accepted.saturating_add(1);
                    match kind {
                        Some(EventKind::Exec) => result.exec = result.exec.saturating_add(1),
                        Some(EventKind::Fork) => result.fork = result.fork.saturating_add(1),
                        Some(EventKind::Exit) => result.exit = result.exit.saturating_add(1),
                        _ => {}
                    }
                }
                IngestOutcome::Dropped { .. } => result.dropped = result.dropped.saturating_add(1),
                IngestOutcome::Malformed { .. } => {
                    result.malformed = result.malformed.saturating_add(1);
                }
                IngestOutcome::RedactionRejected { .. } => {
                    result.redaction_rejected = result.redaction_rejected.saturating_add(1);
                }
                IngestOutcome::SequenceExhausted => {
                    result.sequence_exhausted = result.sequence_exhausted.saturating_add(1);
                }
            }
        }
        result
    }
}

/// Backward-compatible name for callers of the original exec-only reader.
pub type ExecEventReader = ProcessEventReader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRule {
    pub path: PathBuf,
    pub class: CredentialClass,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemDrain {
    pub read: u64,
    pub accepted: u64,
    pub attempted: u64,
    pub succeeded: u64,
    pub denied: u64,
    pub dropped: u64,
    pub malformed: u64,
    pub sequence_exhausted: u64,
}

/// Owns an identity-scoped BPF LSM observer and its file-open result stream.
pub struct FilesystemEventReader {
    events: RingBuf<MapData>,
    _ebpf: Ebpf,
}

impl FilesystemEventReader {
    /// Loads a BPF object, resolves each configured path to a stable Linux
    /// device/inode identity, and attaches observation-only file hooks.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable rules, conflicting classes for one
    /// identity, missing maps/programs, or rejected BPF attachment.
    pub fn load(object_path: &Path, rules: &[CredentialRule]) -> Result<Self, KernelEventError> {
        if rules.is_empty() {
            return Err(KernelEventError(
                "at least one credential rule is required".to_owned(),
            ));
        }
        let mut resolved = StdHashMap::new();
        for rule in rules {
            let metadata = fs::metadata(&rule.path)
                .map_err(|error| KernelEventError(format!("resolve credential rule: {error}")))?;
            let identity = FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            if let Some(existing) = resolved.insert(identity, rule.class)
                && existing != rule.class
            {
                return Err(KernelEventError(
                    "one file identity cannot have multiple credential classes".to_owned(),
                ));
            }
        }

        let object = fs::read(object_path)
            .map_err(|error| KernelEventError(format!("read BPF object: {error}")))?;
        let mut ebpf = Ebpf::load(&object)
            .map_err(|error| KernelEventError(format!("load BPF object: {error:?}")))?;
        {
            let map = ebpf
                .map_mut("credential_inodes")
                .ok_or_else(|| KernelEventError("credential_inodes map not found".to_owned()))?;
            let mut identities = HashMap::<_, [u64; 2], u8>::try_from(map).map_err(|error| {
                KernelEventError(format!("open credential identity map: {error}"))
            })?;
            for (identity, class) in resolved {
                identities
                    .insert([identity.device, identity.inode], class as u8, 0)
                    .map_err(|error| {
                        KernelEventError(format!("configure credential identity: {error}"))
                    })?;
            }
        }

        for (program_name, tracepoint_name) in [
            ("capture_open_enter", "sys_enter"),
            ("capture_open_exit", "sys_exit"),
        ] {
            let program: &mut RawTracePoint = ebpf
                .program_mut(program_name)
                .ok_or_else(|| KernelEventError(format!("{program_name} program not found")))?
                .try_into()
                .map_err(|error| {
                    KernelEventError(format!("open {program_name} program: {error}"))
                })?;
            program.load().map_err(|error| {
                KernelEventError(format!("load {program_name} program: {error}"))
            })?;
            program
                .attach(tracepoint_name)
                .map_err(|error| KernelEventError(format!("attach {program_name}: {error}")))?;
        }
        let btf = Btf::from_sys_fs()
            .map_err(|error| KernelEventError(format!("load kernel BTF: {error}")))?;
        let program: &mut Lsm = ebpf
            .program_mut("capture_credential_open")
            .ok_or_else(|| {
                KernelEventError("capture_credential_open program not found".to_owned())
            })?
            .try_into()
            .map_err(|error| KernelEventError(format!("open file_open LSM program: {error}")))?;
        program
            .load("file_open", &btf)
            .map_err(|error| KernelEventError(format!("load file_open LSM program: {error}")))?;
        program
            .attach()
            .map_err(|error| KernelEventError(format!("attach file_open LSM program: {error}")))?;

        let events = RingBuf::try_from(
            ebpf.take_map("events")
                .ok_or_else(|| KernelEventError("events map not found".to_owned()))?,
        )
        .map_err(|error| KernelEventError(format!("open events ring buffer: {error}")))?;
        Ok(Self {
            events,
            _ebpf: ebpf,
        })
    }

    /// Drains at most `maximum` records, returning their redacted semantic
    /// observations. No path or content is present in the kernel record.
    pub fn drain(
        &mut self,
        ingestor: &mut EventIngestor,
        maximum: usize,
    ) -> (FilesystemDrain, Vec<FileAccessObservation>) {
        let mut drain = FilesystemDrain::default();
        let mut observations = Vec::new();
        for _ in 0..maximum {
            let Some(bytes) = self.events.next() else {
                break;
            };
            drain.read = drain.read.saturating_add(1);
            let Ok(event) = FileOpenEvent::decode(&bytes) else {
                drain.malformed = drain.malformed.saturating_add(1);
                continue;
            };
            let (target_class, outcome) = match event.status {
                FileAccessStatus::Attempted => {
                    drain.attempted = drain.attempted.saturating_add(1);
                    (
                        credential_class_name(event.credential_class),
                        FileAccessOutcome::Attempted,
                    )
                }
                FileAccessStatus::Succeeded => {
                    drain.succeeded = drain.succeeded.saturating_add(1);
                    (
                        credential_class_name(event.credential_class),
                        FileAccessOutcome::Succeeded,
                    )
                }
                FileAccessStatus::Denied => {
                    drain.denied = drain.denied.saturating_add(1);
                    (
                        credential_class_name(event.credential_class),
                        FileAccessOutcome::Denied { errno: event.errno },
                    )
                }
            };
            match ingestor.ingest(
                &bytes,
                RedactedTarget::Redacted {
                    class: target_class,
                },
            ) {
                IngestOutcome::Accepted { .. } => {
                    drain.accepted = drain.accepted.saturating_add(1);
                    observations.push(FileAccessObservation {
                        target: ObservedTarget::Credential(event.credential_class),
                        identity: Some(FileIdentity {
                            device: event.device,
                            inode: event.inode,
                        }),
                        outcome,
                    });
                }
                IngestOutcome::Dropped { .. } => drain.dropped = drain.dropped.saturating_add(1),
                IngestOutcome::Malformed { .. } | IngestOutcome::RedactionRejected { .. } => {
                    drain.malformed = drain.malformed.saturating_add(1);
                }
                IngestOutcome::SequenceExhausted => {
                    drain.sequence_exhausted = drain.sequence_exhausted.saturating_add(1);
                }
            }
        }
        (drain, observations)
    }
}

const fn credential_class_name(class: CredentialClass) -> &'static str {
    match class {
        CredentialClass::SshKey => "ssh_key",
        CredentialClass::CloudCredential => "cloud_credential",
        CredentialClass::DotEnv => "dotenv",
        CredentialClass::Keyring => "keyring",
        CredentialClass::TokenCache => "token_cache",
    }
}
