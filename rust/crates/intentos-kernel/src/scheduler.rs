//! Process Scheduler — IntentOS Option J
//!
//! This module is the backbone of IntentOS as a real operating system.
//! It provides:
//!
//! * **Task manager** — submit, inspect, and enumerate kernel tasks
//! * **Priority scheduler** — three-tier queue (High / Normal / Low)
//! * **Governed execution queue** — only token-bearing tasks may run
//! * **Lifecycle controller** — Queued → Running → Completed / Failed / Killed
//! * **Resource monitor** — per-task memory and CPU-share accounting
//! * **Sandbox integration** — every task wraps a [`SandboxProcess`]
//! * **Remote execution controller** — `RemoteTask` ferry for off-node work
//! * **Scheduler stats** — live counters for operators / dashboards

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;
use uuid::Uuid;

use crate::sandbox_manager::{SandboxProcess, SandboxState};
use crate::token_verifier::VerifiedToken;

// ── Priority ────────────────────────────────────────────────────────────────

/// Execution priority for a [`Task`].
///
/// The scheduler always drains the `High` queue first, then `Normal`, then
/// `Low`. Within a queue tasks are processed in FIFO order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
}

impl Default for TaskPriority {
    fn default() -> Self {
        Self::Normal
    }
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

/// Full lifecycle of a scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    /// Admitted to a priority queue; not yet dispatched.
    Queued,
    /// Dispatched to the CPU; [`SandboxProcess`] is in `Running` state.
    Running,
    /// Finished successfully.
    Completed,
    /// Terminated with an error condition.
    Failed,
    /// Forcibly stopped by an operator or by kernel policy.
    Killed,
}

// ── Task ─────────────────────────────────────────────────────────────────────

/// A single unit of governed work inside the IntentOS scheduler.
#[derive(Debug)]
pub struct Task {
    /// Kernel-assigned opaque identifier.
    pub id: Uuid,
    /// The capability token that authorises this task.
    pub token_id: Uuid,
    /// Scheduling priority.
    pub priority: TaskPriority,
    /// Wall-clock time the task was submitted.
    pub created_at: SystemTime,
    /// The sandboxed process backing this task.
    pub process: SandboxProcess,
    /// Current lifecycle state.
    pub state: TaskState,
    /// Optional human-readable label for dashboards / logs.
    pub label: Option<String>,
    /// Accumulated CPU milliseconds (updated on each [`Scheduler::tick`]).
    pub cpu_ms: u64,
}

impl Task {
    /// Build a new queued task from a verified token and sandbox process.
    pub fn new(
        token: &VerifiedToken,
        priority: TaskPriority,
        process: SandboxProcess,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            token_id: token.id,
            priority,
            created_at: SystemTime::now(),
            process,
            state: TaskState::Queued,
            label: None,
            cpu_ms: 0,
        }
    }

    /// Attach a human-readable label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ── Remote execution ─────────────────────────────────────────────────────────

/// Descriptor for work that must run on a remote node rather than locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTask {
    /// Local task id mirrored on the remote side.
    pub task_id: Uuid,
    /// Token authorising the remote operation.
    pub token_id: Uuid,
    /// Target node address (host:port or node UUID string).
    pub target_node: String,
    /// Serialised payload forwarded to the remote executor.
    pub payload: Vec<u8>,
    /// Whether a result acknowledgement is expected.
    pub expect_ack: bool,
}

// ── Scheduler stats ──────────────────────────────────────────────────────────

/// Point-in-time snapshot of scheduler health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub queued: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub killed: usize,
    pub total_submitted: u64,
}

// ── Scheduler ────────────────────────────────────────────────────────────────

/// The IntentOS kernel process scheduler.
///
/// # Design
///
/// Three separate FIFO queues (High / Normal / Low) back the priority model.
/// `running` holds tasks that have been dispatched.  `finished` is a bounded
/// ring of terminal tasks kept for post-mortem inspection.
///
/// `tick()` is the heartbeat: call it on each scheduler epoch to drain a
/// batch of queued tasks into `running` and update resource counters.
pub struct Scheduler {
    high_queue: VecDeque<Task>,
    normal_queue: VecDeque<Task>,
    low_queue: VecDeque<Task>,
    /// Tasks currently executing, indexed by task id.
    pub running: HashMap<Uuid, Task>,
    /// Finished tasks (completed / failed / killed), capped by `history_limit`.
    finished: VecDeque<Task>,
    /// Maximum number of tasks that can run concurrently.
    pub concurrency_limit: usize,
    /// How many finished tasks to retain for inspection.
    history_limit: usize,
    /// Cumulative submissions across the lifetime of this scheduler.
    total_submitted: u64,
}

impl Scheduler {
    /// Create a scheduler with sensible defaults (8 concurrent tasks, 256
    /// history entries).
    pub fn new() -> Self {
        Self::with_limits(8, 256)
    }

    /// Create a scheduler with explicit concurrency and history limits.
    pub fn with_limits(concurrency_limit: usize, history_limit: usize) -> Self {
        Self {
            high_queue: VecDeque::new(),
            normal_queue: VecDeque::new(),
            low_queue: VecDeque::new(),
            running: HashMap::new(),
            finished: VecDeque::new(),
            concurrency_limit,
            history_limit,
            total_submitted: 0,
        }
    }

    // ── Submission ───────────────────────────────────────────────────────────

    /// Submit a task for scheduling.  Returns the assigned [`Uuid`].
    ///
    /// The task is placed in the queue matching its priority level and
    /// will be dispatched during the next [`tick`](Self::tick) that has a
    /// free concurrency slot.
    pub fn submit(&mut self, task: Task) -> Uuid {
        let id = task.id;
        self.total_submitted += 1;
        match task.priority {
            TaskPriority::High => self.high_queue.push_back(task),
            TaskPriority::Normal => self.normal_queue.push_back(task),
            TaskPriority::Low => self.low_queue.push_back(task),
        }
        id
    }

    // ── Tick / dispatch ──────────────────────────────────────────────────────

    /// Advance the scheduler by one epoch.
    ///
    /// * Dispatches up to `concurrency_limit - running.len()` queued tasks,
    ///   starting with the `High` queue.
    /// * Updates `cpu_ms` for every running task by `elapsed_ms`.
    /// * Returns the ids of newly dispatched tasks.
    pub fn tick(&mut self, elapsed_ms: u64) -> Vec<Uuid> {
        // Update resource counters for tasks already running.
        for task in self.running.values_mut() {
            task.cpu_ms += elapsed_ms;
        }

        let free_slots = self.concurrency_limit.saturating_sub(self.running.len());
        let mut dispatched = Vec::new();

        for _ in 0..free_slots {
            let next = self
                .high_queue
                .pop_front()
                .or_else(|| self.normal_queue.pop_front())
                .or_else(|| self.low_queue.pop_front());

            let Some(mut task) = next else { break };
            task.state = TaskState::Running;
            task.process.start();
            let id = task.id;
            self.running.insert(id, task);
            dispatched.push(id);
        }

        dispatched
    }

    // ── Lifecycle transitions ────────────────────────────────────────────────

    /// Mark a running task as completed successfully.
    pub fn complete(&mut self, task_id: Uuid) -> bool {
        self.finish(task_id, TaskState::Completed, SandboxState::Terminated)
    }

    /// Mark a running task as failed.
    pub fn fail(&mut self, task_id: Uuid) -> bool {
        self.finish(task_id, TaskState::Failed, SandboxState::Terminated)
    }

    /// Kill a running or queued task immediately.
    ///
    /// Returns `true` if the task existed (in any queue or running set).
    pub fn kill(&mut self, task_id: Uuid) -> bool {
        // Check running first.
        if self.running.contains_key(&task_id) {
            return self.finish(task_id, TaskState::Killed, SandboxState::Terminated);
        }
        // Check each priority queue independently to avoid multi-borrow.
        let removed = if let Some(pos) = self.high_queue.iter().position(|t| t.id == task_id) {
            self.high_queue.remove(pos)
        } else if let Some(pos) = self.normal_queue.iter().position(|t| t.id == task_id) {
            self.normal_queue.remove(pos)
        } else if let Some(pos) = self.low_queue.iter().position(|t| t.id == task_id) {
            self.low_queue.remove(pos)
        } else {
            None
        };

        if let Some(mut task) = removed {
            task.state = TaskState::Killed;
            task.process.terminate();
            self.push_finished(task);
            true
        } else {
            false
        }
    }

    // ── Introspection ────────────────────────────────────────────────────────

    /// Returns the number of tasks waiting across all priority queues.
    pub fn queued_len(&self) -> usize {
        self.high_queue.len() + self.normal_queue.len() + self.low_queue.len()
    }

    /// Returns the number of tasks currently running.
    pub fn running_len(&self) -> usize {
        self.running.len()
    }

    /// Snapshot of scheduler health counters.
    pub fn stats(&self) -> SchedulerStats {
        let (mut completed, mut failed, mut killed) = (0usize, 0usize, 0usize);
        for t in &self.finished {
            match t.state {
                TaskState::Completed => completed += 1,
                TaskState::Failed => failed += 1,
                TaskState::Killed => killed += 1,
                _ => {}
            }
        }
        SchedulerStats {
            queued: self.queued_len(),
            running: self.running_len(),
            completed,
            failed,
            killed,
            total_submitted: self.total_submitted,
        }
    }

    /// Read-only view of the finished-task history.
    pub fn history(&self) -> impl Iterator<Item = &Task> {
        self.finished.iter()
    }

    /// Retrieve a running task by id.
    pub fn get_running(&self, task_id: &Uuid) -> Option<&Task> {
        self.running.get(task_id)
    }

    // ── Remote dispatch ──────────────────────────────────────────────────────

    /// Build a [`RemoteTask`] for the given running task id and target node.
    ///
    /// The payload is left empty; callers should populate it before sending.
    pub fn make_remote(&self, task_id: Uuid, target_node: impl Into<String>) -> Option<RemoteTask> {
        let task = self.running.get(&task_id)?;
        Some(RemoteTask {
            task_id,
            token_id: task.token_id,
            target_node: target_node.into(),
            payload: Vec::new(),
            expect_ack: true,
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn finish(
        &mut self,
        task_id: Uuid,
        new_state: TaskState,
        sandbox_state: SandboxState,
    ) -> bool {
        let Some(mut task) = self.running.remove(&task_id) else {
            return false;
        };
        task.state = new_state;
        task.process.state = sandbox_state;
        self.push_finished(task);
        true
    }

    fn push_finished(&mut self, task: Task) {
        if self.finished.len() >= self.history_limit {
            self.finished.pop_front();
        }
        self.finished.push_back(task);
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use std::time::Duration;

    fn make_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test-principal".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    fn make_task(token: &VerifiedToken, priority: TaskPriority) -> Task {
        let proc = SandboxProcess::new("test", "work");
        Task::new(token, priority, proc)
    }

    #[test]
    fn submit_then_tick_dispatches_task() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));

        assert_eq!(sched.queued_len(), 1);
        let dispatched = sched.tick(10);

        assert_eq!(dispatched, vec![id]);
        assert_eq!(sched.running_len(), 1);
        assert_eq!(sched.queued_len(), 0);
    }

    #[test]
    fn high_priority_dispatched_before_low() {
        let mut sched = Scheduler::with_limits(1, 64); // one slot forces ordering
        let token = make_token();

        let low_id = sched.submit(make_task(&token, TaskPriority::Low));
        let high_id = sched.submit(make_task(&token, TaskPriority::High));

        let dispatched = sched.tick(0);
        assert_eq!(dispatched, vec![high_id], "High must beat Low");

        // Complete high task, tick again → low should run
        sched.complete(high_id);
        let dispatched2 = sched.tick(0);
        assert_eq!(dispatched2, vec![low_id]);
    }

    #[test]
    fn concurrency_limit_respected() {
        let mut sched = Scheduler::with_limits(2, 64);
        let token = make_token();

        for _ in 0..5 {
            sched.submit(make_task(&token, TaskPriority::Normal));
        }

        sched.tick(0);
        assert_eq!(sched.running_len(), 2, "No more than concurrency_limit");
        assert_eq!(sched.queued_len(), 3, "Remainder stays queued");
    }

    #[test]
    fn complete_transitions_to_history() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.complete(id));

        assert_eq!(sched.running_len(), 0);
        let found = sched.history().any(|t| t.id == id && t.state == TaskState::Completed);
        assert!(found);
    }

    #[test]
    fn fail_transitions_to_history() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.fail(id));
        let found = sched.history().any(|t| t.id == id && t.state == TaskState::Failed);
        assert!(found);
    }

    #[test]
    fn kill_running_task() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.kill(id));
        assert_eq!(sched.running_len(), 0);
        let found = sched.history().any(|t| t.id == id && t.state == TaskState::Killed);
        assert!(found);
    }

    #[test]
    fn kill_queued_task() {
        let mut sched = Scheduler::with_limits(0, 64); // 0 slots → nothing dispatched
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Low));
        assert_eq!(sched.queued_len(), 1);
        assert!(sched.kill(id));
        assert_eq!(sched.queued_len(), 0);
    }

    #[test]
    fn cpu_ms_accumulates_on_tick() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(50);
        sched.tick(30);
        let task = sched.get_running(&id).unwrap();
        assert_eq!(task.cpu_ms, 30, "First tick dispatches; second tick adds 30ms");
    }

    #[test]
    fn stats_reflect_lifecycle() {
        let mut sched = Scheduler::new();
        let token = make_token();

        let id1 = sched.submit(make_task(&token, TaskPriority::High));
        let id2 = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        sched.complete(id1);
        sched.fail(id2);

        let s = sched.stats();
        assert_eq!(s.completed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.total_submitted, 2);
    }

    #[test]
    fn make_remote_produces_descriptor() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        let remote = sched.make_remote(id, "node-42:9000").unwrap();
        assert_eq!(remote.task_id, id);
        assert_eq!(remote.target_node, "node-42:9000");
        assert!(remote.expect_ack);
    }

    #[test]
    fn history_bounded_by_limit() {
        let limit = 4;
        let mut sched = Scheduler::with_limits(100, limit);
        let token = make_token();

        for _ in 0..(limit + 3) {
            let id = sched.submit(make_task(&token, TaskPriority::Normal));
            sched.tick(0);
            sched.complete(id);
        }

        assert!(sched.history().count() <= limit);
    }
}
