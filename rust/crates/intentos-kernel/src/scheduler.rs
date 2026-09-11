//! Process Scheduler + Task Manager — IntentOS Option J.
//!
//! Provides priority queues, governed task lifecycle, CPU accounting, and a
//! remote-task descriptor for later federation (#25/#26). This module owns an
//! abstract [`SchedProcess`] lifecycle unit; the Option-G host sandbox manager
//! remains separate in [`crate::sandbox_manager`].

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;
use uuid::Uuid;

use crate::token_verifier::VerifiedToken;

/// Lifecycle state of a schedulable work unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedProcessState {
    Idle,
    Running,
    Suspended,
    Terminated,
}

/// Abstract process record owned by the scheduler (not an OS child handle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedProcess {
    pub id: Uuid,
    pub owner: String,
    pub command: String,
    pub state: SchedProcessState,
    #[serde(skip, default = "SystemTime::now")]
    pub spawned_at: SystemTime,
    pub memory_bytes: u64,
    pub cpu_shares: u32,
}

impl SchedProcess {
    pub fn new(owner: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            owner: owner.into(),
            command: command.into(),
            state: SchedProcessState::Idle,
            spawned_at: SystemTime::now(),
            memory_bytes: 0,
            cpu_shares: 100,
        }
    }

    pub fn is_alive(&self) -> bool {
        self.state != SchedProcessState::Terminated
    }

    pub fn start(&mut self) {
        self.state = SchedProcessState::Running;
    }

    pub fn suspend(&mut self) {
        if self.state == SchedProcessState::Running {
            self.state = SchedProcessState::Suspended;
        }
    }

    pub fn terminate(&mut self) {
        self.state = SchedProcessState::Terminated;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum TaskPriority {
    Low,
    #[default]
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Queued,
    Running,
    Completed,
    Failed,
    Killed,
}

#[derive(Debug)]
pub struct Task {
    pub id: Uuid,
    pub token_id: Uuid,
    pub priority: TaskPriority,
    pub created_at: SystemTime,
    pub process: SchedProcess,
    pub state: TaskState,
    pub label: Option<String>,
    pub cpu_ms: u64,
}

impl Task {
    pub fn new(token: &VerifiedToken, priority: TaskPriority, process: SchedProcess) -> Self {
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

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTask {
    pub task_id: Uuid,
    pub token_id: Uuid,
    pub target_node: String,
    pub payload: Vec<u8>,
    pub expect_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub queued: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub killed: usize,
    pub total_submitted: u64,
}

pub struct Scheduler {
    high_queue: VecDeque<Task>,
    normal_queue: VecDeque<Task>,
    low_queue: VecDeque<Task>,
    pub running: HashMap<Uuid, Task>,
    finished: VecDeque<Task>,
    pub concurrency_limit: usize,
    history_limit: usize,
    total_submitted: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::with_limits(8, 256)
    }

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

    pub fn tick(&mut self, elapsed_ms: u64) -> Vec<Uuid> {
        for task in self.running.values_mut() {
            task.cpu_ms = task.cpu_ms.saturating_add(elapsed_ms);
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

    pub fn complete(&mut self, task_id: Uuid) -> bool {
        self.finish(task_id, TaskState::Completed)
    }

    pub fn fail(&mut self, task_id: Uuid) -> bool {
        self.finish(task_id, TaskState::Failed)
    }

    pub fn kill(&mut self, task_id: Uuid) -> bool {
        if self.running.contains_key(&task_id) {
            return self.finish(task_id, TaskState::Killed);
        }
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

    pub fn queued_len(&self) -> usize {
        self.high_queue.len() + self.normal_queue.len() + self.low_queue.len()
    }

    pub fn running_len(&self) -> usize {
        self.running.len()
    }

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

    pub fn history(&self) -> impl Iterator<Item = &Task> {
        self.finished.iter()
    }

    pub fn get_running(&self, task_id: &Uuid) -> Option<&Task> {
        self.running.get(task_id)
    }

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

    fn finish(&mut self, task_id: Uuid, new_state: TaskState) -> bool {
        let Some(mut task) = self.running.remove(&task_id) else {
            return false;
        };
        task.state = new_state;
        task.process.terminate();
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
        Task::new(token, priority, SchedProcess::new("test", "work"))
    }

    #[test]
    fn submit_then_tick_dispatches_task() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        assert_eq!(sched.queued_len(), 1);
        assert_eq!(sched.tick(10), vec![id]);
        assert_eq!(sched.running_len(), 1);
    }

    #[test]
    fn high_priority_dispatched_before_low() {
        let mut sched = Scheduler::with_limits(1, 64);
        let token = make_token();
        let low_id = sched.submit(make_task(&token, TaskPriority::Low));
        let high_id = sched.submit(make_task(&token, TaskPriority::High));
        assert_eq!(sched.tick(0), vec![high_id]);
        sched.complete(high_id);
        assert_eq!(sched.tick(0), vec![low_id]);
    }

    #[test]
    fn concurrency_limit_respected() {
        let mut sched = Scheduler::with_limits(2, 64);
        let token = make_token();
        for _ in 0..5 {
            sched.submit(make_task(&token, TaskPriority::Normal));
        }
        sched.tick(0);
        assert_eq!(sched.running_len(), 2);
        assert_eq!(sched.queued_len(), 3);
    }

    #[test]
    fn complete_and_fail_and_kill() {
        let mut sched = Scheduler::new();
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.complete(id));
        assert!(sched
            .history()
            .any(|t| t.id == id && t.state == TaskState::Completed));

        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.fail(id));

        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        assert!(sched.kill(id));
        assert_eq!(sched.running_len(), 0);
    }

    #[test]
    fn kill_queued_task() {
        let mut sched = Scheduler::with_limits(0, 64);
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Low));
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
        assert_eq!(sched.get_running(&id).unwrap().cpu_ms, 30);
    }

    #[test]
    fn make_remote_and_history_bound() {
        let mut sched = Scheduler::with_limits(100, 4);
        let token = make_token();
        let id = sched.submit(make_task(&token, TaskPriority::Normal));
        sched.tick(0);
        let remote = sched.make_remote(id, "node-42:9000").unwrap();
        assert_eq!(remote.target_node, "node-42:9000");
        for _ in 0..7 {
            let id = sched.submit(make_task(&token, TaskPriority::Normal));
            sched.tick(0);
            sched.complete(id);
        }
        assert!(sched.history().count() <= 4);
    }

    #[test]
    fn sched_process_lifecycle() {
        let mut p = SchedProcess::new("shell", "echo");
        assert!(p.is_alive());
        p.start();
        p.suspend();
        assert_eq!(p.state, SchedProcessState::Suspended);
        p.terminate();
        assert!(!p.is_alive());
    }
}
