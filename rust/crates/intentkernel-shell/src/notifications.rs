//! # Kernel-Backed Notifications + Events
//!
//! A lightweight publish-subscribe bus that routes kernel-level events
//! (token minted, syscall denied, lease expired, app crashed, …) and
//! user-facing notifications to subscribed listeners.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Event types ───────────────────────────────────────────────────────────────

/// The source / urgency level of a notification or event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationLevel {
    /// Informational; no user action required.
    Info,
    /// Something may need attention.
    Warning,
    /// A policy or capability violation occurred.
    Alert,
    /// A critical kernel or security event.
    Critical,
}

/// A notification that may be shown to the user or logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub level: NotificationLevel,
    /// The subsystem that produced this notification.
    pub source: String,
    pub title: String,
    pub body: String,
    pub timestamp_ms: u64,
    /// Whether this notification has been acknowledged.
    pub acknowledged: bool,
}

impl Notification {
    pub fn new(
        level: NotificationLevel,
        source: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            level,
            source: source.into(),
            title: title.into(),
            body: body.into(),
            timestamp_ms: epoch_ms(),
            acknowledged: false,
        }
    }
}

// ── Kernel events ─────────────────────────────────────────────────────────────

/// A structured kernel event that may be forwarded to the notification bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KernelEvent {
    TokenMinted { jti: String, actor: String },
    TokenRevoked { jti: String, actor: String },
    SyscallDenied { actor: String, target: String, reason: String },
    LeaseExpired { pid: u32 },
    AppCrashed { instance_id: Uuid, reason: String },
    PolicyViolation { actor: String, resource: String, action: String },
    CapabilityDenied { window_id: Uuid, capability: String },
}

impl KernelEvent {
    /// Convert the event into a user-facing [`Notification`].
    pub fn to_notification(&self) -> Notification {
        match self {
            KernelEvent::TokenMinted { jti, actor } => Notification::new(
                NotificationLevel::Info,
                "kernel",
                "Token minted",
                format!("actor={actor} jti={jti}"),
            ),
            KernelEvent::TokenRevoked { jti, actor } => Notification::new(
                NotificationLevel::Warning,
                "kernel",
                "Token revoked",
                format!("actor={actor} jti={jti}"),
            ),
            KernelEvent::SyscallDenied { actor, target, reason } => Notification::new(
                NotificationLevel::Alert,
                "kernel",
                "Syscall denied",
                format!("actor={actor} target={target} reason={reason}"),
            ),
            KernelEvent::LeaseExpired { pid } => Notification::new(
                NotificationLevel::Info,
                "lease-manager",
                "Lease expired",
                format!("pid={pid}"),
            ),
            KernelEvent::AppCrashed { instance_id, reason } => Notification::new(
                NotificationLevel::Critical,
                "app-sandbox",
                "Application crashed",
                format!("instance={instance_id} reason={reason}"),
            ),
            KernelEvent::PolicyViolation { actor, resource, action } => Notification::new(
                NotificationLevel::Alert,
                "policy-engine",
                "Policy violation",
                format!("actor={actor} {resource}/{action}"),
            ),
            KernelEvent::CapabilityDenied { window_id, capability } => Notification::new(
                NotificationLevel::Alert,
                "gwm",
                "Capability denied",
                format!("window={window_id} cap={capability}"),
            ),
        }
    }
}

// ── Subscriber callbacks ──────────────────────────────────────────────────────

/// A subscriber that receives notifications.
pub type NotificationSink = Arc<dyn Fn(&Notification) + Send + Sync>;

// ── Notification bus ──────────────────────────────────────────────────────────

/// Kernel-backed notification bus.
///
/// Subsystems push [`KernelEvent`]s or raw [`Notification`]s via [`publish`].
/// Registered sinks are called synchronously.  All notifications are
/// retained in an internal log so the desktop can render a notification
/// centre without external state.
#[derive(Clone)]
pub struct NotificationBus {
    inner: Arc<Mutex<BusState>>,
}

struct BusState {
    log: Vec<Notification>,
    sinks: HashMap<Uuid, NotificationSink>,
}

impl Default for NotificationBus {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BusState {
                log: Vec::new(),
                sinks: HashMap::new(),
            })),
        }
    }

    // ── Subscribers ────────────────────────────────────────────────────────

    /// Register a notification sink; returns a subscription ID that can be
    /// used to unsubscribe later.
    pub fn subscribe(&self, sink: NotificationSink) -> Uuid {
        let id = Uuid::new_v4();
        self.inner.lock().unwrap().sinks.insert(id, sink);
        id
    }

    /// Remove a subscription.
    pub fn unsubscribe(&self, id: Uuid) {
        self.inner.lock().unwrap().sinks.remove(&id);
    }

    // ── Publishing ─────────────────────────────────────────────────────────

    /// Publish a raw notification, routing it to all sinks and appending to
    /// the retained log.
    pub fn publish(&self, notification: Notification) {
        let mut state = self.inner.lock().unwrap();
        for sink in state.sinks.values() {
            sink(&notification);
        }
        state.log.push(notification);
    }

    /// Convert a [`KernelEvent`] into a notification and publish it.
    pub fn emit(&self, event: KernelEvent) {
        self.publish(event.to_notification());
    }

    // ── Log queries ────────────────────────────────────────────────────────

    pub fn log_len(&self) -> usize {
        self.inner.lock().unwrap().log.len()
    }

    pub fn unacknowledged(&self) -> Vec<Notification> {
        self.inner
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|n| !n.acknowledged)
            .cloned()
            .collect()
    }

    pub fn acknowledge(&self, id: Uuid) -> bool {
        let mut state = self.inner.lock().unwrap();
        if let Some(n) = state.log.iter_mut().find(|n| n.id == id) {
            n.acknowledged = true;
            return true;
        }
        false
    }

    pub fn clear_acknowledged(&self) {
        self.inner
            .lock()
            .unwrap()
            .log
            .retain(|n| !n.acknowledged);
    }

    /// Return all notifications at or above `min_level`.
    pub fn by_level(&self, min_level: NotificationLevel) -> Vec<Notification> {
        self.inner
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|n| severity(n.level) >= severity(min_level))
            .cloned()
            .collect()
    }
}

fn severity(level: NotificationLevel) -> u8 {
    match level {
        NotificationLevel::Info => 0,
        NotificationLevel::Warning => 1,
        NotificationLevel::Alert => 2,
        NotificationLevel::Critical => 3,
    }
}

fn epoch_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn publish_reaches_subscriber() {
        let bus = NotificationBus::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        bus.subscribe(Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        bus.publish(Notification::new(
            NotificationLevel::Info,
            "test",
            "hi",
            "body",
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn kernel_event_emitted_to_log() {
        let bus = NotificationBus::new();
        bus.emit(KernelEvent::SyscallDenied {
            actor: "app".into(),
            target: "/etc/passwd".into(),
            reason: "no fs-read scope".into(),
        });
        assert_eq!(bus.log_len(), 1);
        assert!(!bus.unacknowledged().is_empty());
    }

    #[test]
    fn acknowledge_clears_unread() {
        let bus = NotificationBus::new();
        bus.publish(Notification::new(
            NotificationLevel::Warning,
            "kernel",
            "t",
            "b",
        ));
        let unread = bus.unacknowledged();
        assert_eq!(unread.len(), 1);
        bus.acknowledge(unread[0].id);
        assert_eq!(bus.unacknowledged().len(), 0);
    }

    #[test]
    fn by_level_filters_correctly() {
        let bus = NotificationBus::new();
        bus.publish(Notification::new(NotificationLevel::Info, "s", "t", "b"));
        bus.publish(Notification::new(NotificationLevel::Critical, "s", "t", "b"));
        let alerts = bus.by_level(NotificationLevel::Alert);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, NotificationLevel::Critical);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let bus = NotificationBus::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let sub_id = bus.subscribe(Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        bus.unsubscribe(sub_id);
        bus.publish(Notification::new(NotificationLevel::Info, "s", "t", "b"));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
