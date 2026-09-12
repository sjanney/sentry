// SPDX-License-Identifier: Apache-2.0
//! Best-effort Linux `/proc` snapshots used before a live attach sensor exists.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotProcess {
    pub tgid: u32,
    pub parent_tgid: u32,
    /// Linux `/proc/<pid>/stat` start time in clock ticks, used to detect PID reuse.
    pub start_time_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTreeSnapshot {
    pub root: SnapshotProcess,
    pub processes: Vec<SnapshotProcess>,
    /// Numeric procfs entries that could not be read or parsed during the scan.
    pub skipped_processes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    InvalidPid,
    RootUnavailable,
    RootChanged,
    InconsistentTree,
}

/// Reads the current descendants of an existing Linux process.
///
/// The result is an attach-time snapshot only. Processes may fork or exit after
/// this read, and all returned processes have permanent partial coverage:
/// pre-attach reads, inherited descriptors, and connections remain unknown.
///
/// # Errors
///
/// Returns `InvalidPid` for zero and `RootUnavailable` when the root cannot be
/// read consistently from the supplied procfs root. A root identity change or
/// impossible parent/child start-time ordering rejects the snapshot.
pub fn snapshot_process_tree(
    procfs_root: &Path,
    root_tgid: u32,
) -> Result<ProcessTreeSnapshot, SnapshotError> {
    if root_tgid == 0 {
        return Err(SnapshotError::InvalidPid);
    }
    let initial_root =
        read_process(procfs_root, root_tgid).ok_or(SnapshotError::RootUnavailable)?;
    let mut processes = BTreeMap::from([(root_tgid, initial_root)]);
    let mut skipped_processes = 0;
    let entries = fs::read_dir(procfs_root).map_err(|_| SnapshotError::RootUnavailable)?;
    for entry in entries {
        let Ok(entry) = entry else {
            // A concurrent process exit or procfs access failure means the
            // result cannot describe a complete point-in-time tree.
            skipped_processes += 1;
            continue;
        };
        let Ok(tgid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(process) = read_process(procfs_root, tgid) else {
            skipped_processes += 1;
            continue;
        };
        processes.insert(tgid, process);
    }
    let root = read_process(procfs_root, root_tgid).ok_or(SnapshotError::RootUnavailable)?;
    if root != initial_root {
        return Err(SnapshotError::RootChanged);
    }
    processes.insert(root_tgid, root);
    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    for process in processes.values() {
        children
            .entry(process.parent_tgid)
            .or_default()
            .push(process.tgid);
    }
    let mut pending = vec![root_tgid];
    let mut included = BTreeSet::new();
    while let Some(tgid) = pending.pop() {
        if !included.insert(tgid) {
            continue;
        }
        if let Some(descendants) = children.get(&tgid) {
            pending.extend(descendants.iter().copied());
        }
    }
    let processes: Vec<_> = included
        .into_iter()
        .filter_map(|tgid| processes.get(&tgid).copied())
        .collect();
    let by_tgid: BTreeMap<_, _> = processes
        .iter()
        .map(|process| (process.tgid, process))
        .collect();
    if processes.iter().any(|process| {
        by_tgid
            .get(&process.parent_tgid)
            .is_some_and(|parent| parent.start_time_ticks > process.start_time_ticks)
    }) {
        return Err(SnapshotError::InconsistentTree);
    }
    Ok(ProcessTreeSnapshot {
        root,
        processes,
        skipped_processes,
    })
}

fn read_process(procfs_root: &Path, tgid: u32) -> Option<SnapshotProcess> {
    let stat = fs::read_to_string(procfs_root.join(tgid.to_string()).join("stat")).ok()?;
    parse_stat(tgid, &stat)
}

fn parse_stat(tgid: u32, stat: &str) -> Option<SnapshotProcess> {
    let (_, suffix) = stat.rsplit_once(')')?;
    let fields: Vec<_> = suffix.split_whitespace().collect();
    Some(SnapshotProcess {
        tgid,
        parent_tgid: fields.get(1)?.parse().ok()?,
        start_time_ticks: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sentry-proc-{name}-{}", std::process::id()))
    }

    fn write_stat(root: &Path, pid: u32, parent: u32, start: u64) {
        let directory = root.join(pid.to_string());
        fs::create_dir_all(&directory).unwrap();
        let fields = [
            "S".to_owned(),
            parent.to_string(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            "0".to_owned(),
            start.to_string(),
        ];
        fs::write(
            directory.join("stat"),
            format!("{pid} (agent worker) {}\n", fields.join(" ")),
        )
        .unwrap();
    }

    #[test]
    fn includes_only_the_root_and_current_descendants() {
        let root = fixture("tree");
        write_stat(&root, 100, 1, 10);
        write_stat(&root, 101, 100, 11);
        write_stat(&root, 102, 101, 12);
        write_stat(&root, 200, 1, 13);
        let snapshot = snapshot_process_tree(&root, 100).unwrap();
        assert_eq!(snapshot.root.start_time_ticks, 10);
        assert_eq!(snapshot.skipped_processes, 0);
        assert_eq!(
            snapshot
                .processes
                .iter()
                .map(|process| process.tgid)
                .collect::<Vec<_>>(),
            vec![100, 101, 102]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_and_invalid_roots() {
        let root = fixture("missing");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(
            snapshot_process_tree(&root, 0),
            Err(SnapshotError::InvalidPid)
        );
        assert_eq!(
            snapshot_process_tree(&root, 10),
            Err(SnapshotError::RootUnavailable)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn counts_unreadable_process_entries_without_claiming_a_complete_tree() {
        let root = fixture("skipped");
        write_stat(&root, 100, 1, 10);
        fs::create_dir_all(root.join("200")).unwrap();
        let snapshot = snapshot_process_tree(&root, 100).unwrap();
        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.skipped_processes, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_a_parent_child_edge_that_crosses_a_reused_pid() {
        let root = fixture("inconsistent");
        write_stat(&root, 100, 1, 20);
        write_stat(&root, 101, 100, 10);
        assert_eq!(
            snapshot_process_tree(&root, 100),
            Err(SnapshotError::InconsistentTree)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
