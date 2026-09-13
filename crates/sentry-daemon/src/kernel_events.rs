// SPDX-License-Identifier: Apache-2.0
//! Linux tracepoint collection for the Sentry event ABI.
//!
//! This module observes process exec, fork, and exit through the MVP probe
//! object. It deliberately does not load policy maps or make an enforcement
//! claim. Lifecycle observations are not applied to [`crate::ProcessTracker`]
//! because this ABI does not yet carry the start-time identity needed to avoid
//! PID reuse errors.

use std::{error::Error, fmt, fs, path::Path};

use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::TracePoint,
};
use sentry_types::{EventHeader, EventKind};

use crate::{EventIngestor, IngestOutcome, RedactedTarget};

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
