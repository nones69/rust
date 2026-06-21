use crate::types::{LeaseState, ProcessLease, wall_ms};
use std::collections::HashMap;

/// Native lease manager inside the IntentOS kernel.
pub struct LeaseManager {
    leases: HashMap<String, ProcessLease>,
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

    pub fn renew(&mut self, lease_id: &str, ttl_ms: u64) -> Option<ProcessLease> {
        let now = wall_ms();
        let lease = self.leases.get_mut(lease_id)?;
        if lease.state == LeaseState::Revoked || lease.state == LeaseState::Expired {
            return None;
        }
        lease.expires_at = now + ttl_ms;
        lease.state = LeaseState::Granted;
        Some(lease.clone())
    }

    pub fn tick(&mut self) -> Vec<u32> {
        let now = wall_ms();
        let mut expired = Vec::new();
        for lease in self.leases.values_mut() {
            if lease.expires_at < now && lease.state != LeaseState::Expired {
                lease.state = LeaseState::Expired;
                expired.push(lease.pid);
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

        assert_eq!(expired, vec![7]);
        assert!(renewed.is_none());
        assert_eq!(stored.state, LeaseState::Expired);
    }
}