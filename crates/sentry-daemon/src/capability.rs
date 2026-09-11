// SPDX-License-Identifier: Apache-2.0
//! Read-only Linux enforcement preflight checks.

use std::{fs, path::Path};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelPreflight {
    pub btf_readable: bool,
    pub bpf_lsm_active: bool,
    pub cgroup_v2_available: bool,
}

impl KernelPreflight {
    /// Inspects a Linux sysfs root without claiming that a program has attached.
    #[must_use]
    pub fn inspect(root: &Path) -> Self {
        let btf_readable = fs::File::open(root.join("sys/kernel/btf/vmlinux")).is_ok();
        let cgroup_v2_available = root.join("sys/fs/cgroup/cgroup.controllers").exists();
        let bpf_lsm_active = fs::read_to_string(root.join("sys/kernel/security/lsm"))
            .map(|active| active.split(',').any(|name| name.trim() == "bpf"))
            .unwrap_or(false);
        Self {
            btf_readable,
            bpf_lsm_active,
            cgroup_v2_available,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sentry-capability-{name}-{}", std::process::id()))
    }

    #[test]
    fn reports_only_observed_kernel_preflight_facts() {
        let root = fixture("available");
        fs::create_dir_all(root.join("sys/kernel/btf")).unwrap();
        fs::create_dir_all(root.join("sys/kernel/security")).unwrap();
        fs::create_dir_all(root.join("sys/fs/cgroup")).unwrap();
        fs::write(root.join("sys/kernel/btf/vmlinux"), []).unwrap();
        fs::write(
            root.join("sys/kernel/security/lsm"),
            "capability,bpf,landlock\n",
        )
        .unwrap();
        fs::write(
            root.join("sys/fs/cgroup/cgroup.controllers"),
            "cpu memory\n",
        )
        .unwrap();
        assert_eq!(
            KernelPreflight::inspect(&root),
            KernelPreflight {
                btf_readable: true,
                bpf_lsm_active: true,
                cgroup_v2_available: true,
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_or_inactive_features_are_not_inferred() {
        let root = fixture("missing");
        fs::create_dir_all(root.join("sys/kernel/security")).unwrap();
        fs::write(
            root.join("sys/kernel/security/lsm"),
            "capability,landlock\n",
        )
        .unwrap();
        assert_eq!(KernelPreflight::inspect(&root), KernelPreflight::default());
        fs::remove_dir_all(root).unwrap();
    }
}
