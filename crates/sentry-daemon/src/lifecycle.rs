// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementMode {
    DryRun,
    Enforce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    DaemonDeath,
    EventLoss,
    AuditWrite,
    DiskFull,
    MapExhaustion,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    Active,
    AuditIncomplete,
    RefusingNewRuns,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lifecycle {
    mode: EnforcementMode,
    active_policy: Option<u64>,
    previous_policy: Option<u64>,
    state: RuntimeState,
    faults: Vec<Fault>,
}

impl Lifecycle {
    #[must_use]
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            active_policy: None,
            previous_policy: None,
            state: RuntimeState::Active,
            faults: Vec::new(),
        }
    }
    #[must_use]
    pub const fn state(&self) -> RuntimeState {
        self.state
    }
    #[must_use]
    pub fn faults(&self) -> &[Fault] {
        &self.faults
    }
    #[must_use]
    pub const fn active_policy(&self) -> Option<u64> {
        self.active_policy
    }
    /// # Errors
    ///
    /// Returns `RefusingNewRuns` after an enforce-mode fault.
    pub fn activate(&mut self, policy_hash: u64) -> Result<(), RuntimeState> {
        if self.state == RuntimeState::RefusingNewRuns {
            return Err(self.state);
        }
        self.previous_policy = self.active_policy;
        self.active_policy = Some(policy_hash);
        Ok(())
    }
    /// # Errors
    ///
    /// Returns `RefusingNewRuns` after an enforce-mode fault.
    pub fn rollback(&mut self) -> Result<(), RuntimeState> {
        if self.state == RuntimeState::RefusingNewRuns {
            return Err(self.state);
        }
        self.active_policy = self.previous_policy;
        Ok(())
    }
    pub fn report_fault(&mut self, fault: Fault) {
        self.faults.push(fault);
        self.state = match self.mode {
            EnforcementMode::DryRun => RuntimeState::AuditIncomplete,
            EnforcementMode::Enforce => RuntimeState::RefusingNewRuns,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enforce_faults_refuse_new_runs_without_silent_fail_open() {
        for fault in [
            Fault::DaemonDeath,
            Fault::EventLoss,
            Fault::AuditWrite,
            Fault::DiskFull,
            Fault::MapExhaustion,
            Fault::Shutdown,
        ] {
            let mut lifecycle = Lifecycle::new(EnforcementMode::Enforce);
            lifecycle.activate(1).unwrap();
            lifecycle.report_fault(fault);
            assert_eq!(lifecycle.state(), RuntimeState::RefusingNewRuns);
            assert_eq!(lifecycle.activate(2), Err(RuntimeState::RefusingNewRuns));
            assert_eq!(lifecycle.faults(), &[fault]);
        }
    }
    #[test]
    fn dry_run_marks_incomplete_and_policy_reload_can_rollback() {
        let mut lifecycle = Lifecycle::new(EnforcementMode::DryRun);
        lifecycle.activate(1).unwrap();
        lifecycle.activate(2).unwrap();
        lifecycle.rollback().unwrap();
        assert_eq!(lifecycle.active_policy(), Some(1));
        lifecycle.report_fault(Fault::EventLoss);
        assert_eq!(lifecycle.state(), RuntimeState::AuditIncomplete);
    }
}
