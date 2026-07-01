use crate::types::{LeaseState, ProcessLease, wall_ms};
use std::collections::HashMap;

/// Native lease manager inside the IntentOS kernel.
pub struct LeaseManager {
    leases: HashMap<String, ProcessLease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRenewError {
    UnknownLease,
    Expired,
    Revoked,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
        }
    }

    pub fn grant(&mut self, pid: u32, ttl_ms: u64) -> ProcessLease {
        let now = wall_ms();
        let lease = ProcessLease {
            lease_id: uuid::Uuid::new_v4().to_string(),
            pid,
            state: LeaseState::Granted,
            granted_at: now,
            expires_at: now + ttl_ms,
        };
        self.leases.insert(lease.lease_id.clone(), lease.clone());
        lease
    }

    pub fn renew(&mut self, lease_id: &str, ttl_ms: u64) -> Result<ProcessLease, LeaseRenewError> {
        let now = wall_ms();
        let lease = self
            .leases
            .get_mut(lease_id)
            .ok_or(LeaseRenewError::UnknownLease)?;
        if lease.state == LeaseState::Revoked {
            return Err(LeaseRenewError::Revoked);
        }
        if lease.state == LeaseState::Expired || lease.expires_at <= now {
            lease.state = LeaseState::Expired;
            return Err(LeaseRenewError::Expired);
        }
        lease.expires_at = now + ttl_ms;
        lease.state = LeaseState::Granted;
        Ok(lease.clone())
    }

    pub fn tick(&mut self) -> Vec<ProcessLease> {
        let now = wall_ms();
        let mut expired = Vec::new();
        for lease in self.leases.values_mut() {
            if lease.expires_at <= now && lease.state != LeaseState::Expired {
                lease.state = LeaseState::Expired;
                expired.push(lease.clone());
            }
        }
        expired
    }

    pub fn list(&self) -> Vec<&ProcessLease> {
        self.leases.values().collect()
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[test]
    fn renewal_extends_live_lease() {
        let mut manager = LeaseManager::new();
        let lease = manager.grant(42, 5);
        thread::sleep(Duration::from_millis(2));

        let renewed = manager.renew(&lease.lease_id, 50).unwrap();

        assert_eq!(renewed.pid, 42);
        assert_eq!(renewed.state, LeaseState::Granted);
        assert!(renewed.expires_at >= lease.expires_at);
    }

    #[test]
    fn tick_before_expiry_keeps_lease_active() {
        // Generous TTL: tick must NOT expire a still-live lease.
        let mut manager = LeaseManager::new();
        let lease = manager.grant(11, 60_000);

        let expired = manager.tick();

        assert!(expired.is_empty());
        let stored = manager
            .list()
            .into_iter()
            .find(|e| e.lease_id == lease.lease_id)
            .unwrap();
        assert_eq!(stored.state, LeaseState::Granted);
    }

    #[test]
    fn tick_after_expiry_marks_expired_once() {
        // 1ms TTL + short sleep crosses the strict `expires_at < now` boundary.
        let mut manager = LeaseManager::new();
        let lease = manager.grant(99, 1);
        thread::sleep(Duration::from_millis(5));

        let first = manager.tick();
        assert_eq!(
            first.iter().map(|lease| lease.pid).collect::<Vec<_>>(),
            vec![99],
            "first tick reports the newly-expired pid"
        );

        let second = manager.tick();
        assert!(second.is_empty(), "tick is idempotent: no double-report");

        let stored = manager
            .list()
            .into_iter()
            .find(|e| e.lease_id == lease.lease_id)
            .unwrap();
        assert_eq!(stored.state, LeaseState::Expired);
    }

    #[test]
    fn renew_unknown_lease_returns_none() {
        let mut manager = LeaseManager::new();
        assert_eq!(
            manager.renew("does-not-exist", 1000),
            Err(LeaseRenewError::UnknownLease)
        );
    }

    #[test]
    fn renew_revives_expired_state_only_via_tick_path() {
        // A lease expired by tick() cannot be renewed (matches code: renew
        // refuses Expired/Revoked). Guards against zombie-lease revival.
        let mut manager = LeaseManager::new();
        let lease = manager.grant(5, 1);
        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            manager.tick().iter().map(|lease| lease.pid).collect::<Vec<_>>(),
            vec![5]
        );

        assert_eq!(
            manager.renew(&lease.lease_id, 60_000),
            Err(LeaseRenewError::Expired)
        );
    }

    #[test]
    fn expired_lease_cannot_be_renewed() {
        let mut manager = LeaseManager::new();
        let lease = manager.grant(7, 1);
        thread::sleep(Duration::from_millis(5));

        let expired = manager.tick();
        let renewed = manager.renew(&lease.lease_id, 50);
        let stored = manager
            .list()
            .into_iter()
            .find(|entry| entry.lease_id == lease.lease_id)
            .unwrap();

        assert_eq!(expired.iter().map(|lease| lease.pid).collect::<Vec<_>>(), vec![7]);
        assert_eq!(renewed, Err(LeaseRenewError::Expired));
        assert_eq!(stored.state, LeaseState::Expired);
    }
}