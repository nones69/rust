//! Sandbox process abstraction for the IntentOS scheduler.
//!
//! A [`SandboxProcess`] is the kernel's unit of governed execution: every
//! workload that enters the scheduler is wrapped in one so that policy,
//! resource limits, and lifecycle state are always co-located.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Lifecycle state of a sandboxed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    /// Spawned but not yet dispatched to a CPU slot.
    Idle,
    /// Actively consuming CPU.
    Running,
    /// Voluntarily or forcibly paused; can be resumed.
    Suspended,
    /// Execution finished (success or failure) — terminal state.
    Terminated,
}

/// A process running inside an IntentOS sandbox.
///
/// Holds identity, resource limits, and current lifecycle state.
/// The scheduler owns one of these per task; it is cloned into the
/// `Task` so the two structures always stay in sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProcess {
    /// Kernel-assigned opaque handle.
    pub id: Uuid,
    /// Principal that submitted the process (e.g. `"shell"`, `"daemon"`).
    pub owner: String,
    /// Human-readable description of the work being done.
    pub command: String,
    /// Current lifecycle state.
    pub state: SandboxState,
    /// Wall-clock instant the process was created.
    #[serde(skip, default = "SystemTime::now")]
    pub spawned_at: SystemTime,
    /// Peak resident-set bytes reported by the last resource tick.
    pub memory_bytes: u64,
    /// Relative CPU weight (100 = default, higher = more time).
    pub cpu_shares: u32,
}

impl SandboxProcess {
    /// Create a new idle sandbox process.
    pub fn new(owner: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            owner: owner.into(),
            command: command.into(),
            state: SandboxState::Idle,
            spawned_at: SystemTime::now(),
            memory_bytes: 0,
            cpu_shares: 100,
        }
    }

    /// Returns `true` while the process has not yet reached [`SandboxState::Terminated`].
    pub fn is_alive(&self) -> bool {
        self.state != SandboxState::Terminated
    }

    /// Transition to [`SandboxState::Running`].
    pub fn start(&mut self) {
        self.state = SandboxState::Running;
    }

    /// Transition to [`SandboxState::Suspended`].
    pub fn suspend(&mut self) {
        if self.state == SandboxState::Running {
            self.state = SandboxState::Suspended;
        }
    }

    /// Transition to [`SandboxState::Terminated`].
    pub fn terminate(&mut self) {
        self.state = SandboxState::Terminated;
    }

    /// Update the resource snapshot (called by the scheduler on every tick).
    pub fn update_resources(&mut self, memory_bytes: u64, cpu_shares: u32) {
        self.memory_bytes = memory_bytes;
        self.cpu_shares = cpu_shares;
    }
}

impl Default for SandboxProcess {
    fn default() -> Self {
        Self::new("kernel", "idle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_process_is_idle_and_alive() {
        let p = SandboxProcess::new("test", "echo hello");
        assert_eq!(p.state, SandboxState::Idle);
        assert!(p.is_alive());
    }

    #[test]
    fn start_transitions_to_running() {
        let mut p = SandboxProcess::new("test", "work");
        p.start();
        assert_eq!(p.state, SandboxState::Running);
        assert!(p.is_alive());
    }

    #[test]
    fn terminate_is_not_alive() {
        let mut p = SandboxProcess::new("test", "work");
        p.start();
        p.terminate();
        assert_eq!(p.state, SandboxState::Terminated);
        assert!(!p.is_alive());
    }

    #[test]
    fn suspend_only_from_running() {
        let mut p = SandboxProcess::new("test", "work");
        p.suspend(); // no-op from Idle
        assert_eq!(p.state, SandboxState::Idle);
        p.start();
        p.suspend();
        assert_eq!(p.state, SandboxState::Suspended);
    }
}
