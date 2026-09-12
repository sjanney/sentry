// SPDX-License-Identifier: Apache-2.0
//! Read-only Linux enforcement preflight checks.

use std::{collections::BTreeSet, fs, path::Path};

use sentry_policy::compiler::{
    CompiledKernelPolicy, KernelCapability, KernelPolicyLimits, PolicyCompileError, PolicySpec,
    compile_kernel_policy,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelPreflight {
    pub btf_readable: bool,
    pub bpf_lsm_active: bool,
    pub cgroup_v2_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingCapability(pub KernelCapability);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreflightCompileError {
    Missing(MissingCapability),
    InvalidPolicy(PolicyCompileError),
}

impl KernelPreflight {
    /// Inspects a Linux sysfs root without claiming that a program has attached.
    #[must_use]
    pub fn inspect(root: &Path) -> Self {
        let btf_readable = fs::metadata(root.join("sys/kernel/btf/vmlinux"))
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        let cgroup_v2_available = fs::metadata(root.join("sys/fs/cgroup/cgroup.controllers"))
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        let bpf_lsm_active = fs::read_to_string(root.join("sys/kernel/security/lsm"))
            .map(|active| active.split(',').any(|name| name.trim() == "bpf"))
            .unwrap_or(false);
        Self {
            btf_readable,
            bpf_lsm_active,
            cgroup_v2_available,
        }
    }

    /// Returns only policy capabilities directly established by this preflight.
    ///
    /// DNS observation is intentionally absent because this read-only probe does
    /// not inspect or attach a DNS sensor.
    #[must_use]
    pub fn available_capabilities(&self) -> BTreeSet<KernelCapability> {
        let mut capabilities = BTreeSet::new();
        if self.btf_readable && self.bpf_lsm_active {
            capabilities.insert(KernelCapability::BpfLsm);
        }
        if self.cgroup_v2_available {
            capabilities.insert(KernelCapability::CgroupV2);
        }
        capabilities
    }

    /// Checks that every requested policy capability was observed in preflight.
    ///
    /// # Errors
    ///
    /// Returns the first missing capability in deterministic enum order.
    pub fn require(&self, required: &BTreeSet<KernelCapability>) -> Result<(), MissingCapability> {
        let available = self.available_capabilities();
        required
            .iter()
            .find(|capability| !available.contains(capability))
            .copied()
            .map_or(Ok(()), |capability| Err(MissingCapability(capability)))
    }

    /// Performs capability gating and bounded policy compilation before activation.
    ///
    /// # Errors
    ///
    /// Returns a missing-capability error before compilation, or the compiler's
    /// typed policy error when the observed host can represent the policy.
    pub fn compile_policy(
        &self,
        policy: &PolicySpec,
        limits: KernelPolicyLimits,
    ) -> Result<CompiledKernelPolicy, PreflightCompileError> {
        self.require(&policy.required_capabilities)
            .map_err(PreflightCompileError::Missing)?;
        compile_kernel_policy(policy, &self.available_capabilities(), limits)
            .map_err(PreflightCompileError::InvalidPolicy)
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

    #[test]
    fn capability_projection_contains_only_observed_features() {
        let preflight = KernelPreflight {
            btf_readable: true,
            bpf_lsm_active: true,
            cgroup_v2_available: false,
        };
        assert_eq!(
            preflight.available_capabilities(),
            BTreeSet::from([KernelCapability::BpfLsm])
        );
    }

    #[test]
    fn bpf_lsm_without_btf_is_not_projected_as_loadable() {
        let preflight = KernelPreflight {
            btf_readable: false,
            bpf_lsm_active: true,
            cgroup_v2_available: true,
        };
        assert_eq!(
            preflight.available_capabilities(),
            BTreeSet::from([KernelCapability::CgroupV2])
        );
    }

    #[test]
    fn btf_directory_is_not_treated_as_readable_btf() {
        let root = fixture("btf-directory");
        fs::create_dir_all(root.join("sys/kernel/btf/vmlinux")).unwrap();
        assert!(!KernelPreflight::inspect(&root).btf_readable);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cgroup_controller_directory_is_not_treated_as_cgroup_v2() {
        let root = fixture("cgroup-directory");
        fs::create_dir_all(root.join("sys/fs/cgroup/cgroup.controllers")).unwrap();
        assert!(!KernelPreflight::inspect(&root).cgroup_v2_available);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn require_reports_missing_capability_before_activation() {
        let preflight = KernelPreflight {
            btf_readable: true,
            bpf_lsm_active: true,
            cgroup_v2_available: false,
        };
        let required = BTreeSet::from([KernelCapability::BpfLsm, KernelCapability::CgroupV2]);
        assert_eq!(
            preflight.require(&required),
            Err(MissingCapability(KernelCapability::CgroupV2))
        );
    }

    #[test]
    fn compile_policy_gates_capabilities_before_activation() {
        let preflight = KernelPreflight {
            btf_readable: false,
            bpf_lsm_active: true,
            cgroup_v2_available: true,
        };
        let policy = PolicySpec {
            schema_version: 1,
            policy_version: 1,
            mode: sentry_policy::compiler::PolicyMode::Enforce,
            default_deny: true,
            deny_untrusted_egress: false,
            allowed_domains: BTreeSet::new(),
            allowed_cidrs: BTreeSet::new(),
            required_capabilities: BTreeSet::from([KernelCapability::BpfLsm]),
        };
        let limits = KernelPolicyLimits {
            max_domains: 4,
            max_cidrs: 4,
            max_serialized_bytes: 1024,
        };
        assert_eq!(
            preflight.compile_policy(&policy, limits),
            Err(PreflightCompileError::Missing(MissingCapability(
                KernelCapability::BpfLsm
            )))
        );
    }

    #[test]
    fn compile_policy_returns_bounded_policy_when_capabilities_are_observed() {
        let preflight = KernelPreflight {
            btf_readable: true,
            bpf_lsm_active: true,
            cgroup_v2_available: true,
        };
        let policy = PolicySpec {
            schema_version: 1,
            policy_version: 1,
            mode: sentry_policy::compiler::PolicyMode::Enforce,
            default_deny: true,
            deny_untrusted_egress: false,
            allowed_domains: BTreeSet::new(),
            allowed_cidrs: BTreeSet::new(),
            required_capabilities: BTreeSet::from([KernelCapability::BpfLsm]),
        };
        let compiled = preflight
            .compile_policy(
                &policy,
                KernelPolicyLimits {
                    max_domains: 4,
                    max_cidrs: 4,
                    max_serialized_bytes: 1024,
                },
            )
            .expect("observed capabilities should permit bounded compilation");
        assert_eq!(compiled.policy_version(), 1);
    }
}
