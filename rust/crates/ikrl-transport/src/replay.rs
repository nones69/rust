//! Replay-protection guard for IPC requests.
//!
//! Rejects requests whose timestamp deviates too far from the server clock, or
//! whose `request_id` has already been seen within the freshness window.  Uses
//! a bucketed sliding-window approach so memory use stays bounded.

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors returned by [`ReplayGuard::check`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ReplayError {
    /// The request timestamp is outside the allowed clock-skew window.
    #[error("stale request: skew {skew_ms} ms exceeds allowed {allowed_ms} ms")]
    Stale { skew_ms: u64, allowed_ms: u64 },

    /// A request with this ID was already accepted.
    #[error("replayed request id: {request_id}")]
    Replay { request_id: String },
}

/// Thread-safe sliding-window guard against replayed or stale requests.
///
/// Call [`ReplayGuard::check`] before accepting any inbound request.  The
/// guard maintains a bucketed set of seen `request_id` values and evicts
/// buckets older than `2 × skew_secs` to keep memory bounded.
pub struct ReplayGuard {
    /// Maximum tolerated clock skew in seconds.
    skew_secs: u64,
    /// Seen request IDs bucketed by seconds-since-epoch.
    seen: BTreeMap<u64, HashSet<String>>,
}

impl ReplayGuard {
    /// Create a new guard with the given clock-skew tolerance (seconds).
    ///
    /// A value of 30 s works well for local IPC; 60 s is reasonable for
    /// slightly-drifted cross-host deployments.
    pub fn new(skew_secs: u64) -> Self {
        Self {
            skew_secs,
            seen: BTreeMap::new(),
        }
    }

    /// Validate a request.
    ///
    /// Returns `Ok(())` when:
    /// - `timestamp_ms` is within `skew_secs * 1000` ms of the server clock, and
    /// - `request_id` has not been seen before within the freshness window.
    ///
    /// On success the `request_id` is recorded so future calls with the same id
    /// are rejected.
    pub fn check(&mut self, request_id: &str, timestamp_ms: u64) -> Result<(), ReplayError> {
        let now_ms = now_ms();
        let skew_ms = (now_ms as i64 - timestamp_ms as i64).unsigned_abs();
        let allowed_ms = self.skew_secs * 1000;

        if skew_ms > allowed_ms {
            return Err(ReplayError::Stale {
                skew_ms,
                allowed_ms,
            });
        }

        let bucket = timestamp_ms / 1000;
        if self
            .seen
            .get(&bucket)
            .is_some_and(|s| s.contains(request_id))
        {
            return Err(ReplayError::Replay {
                request_id: request_id.to_string(),
            });
        }

        self.seen
            .entry(bucket)
            .or_default()
            .insert(request_id.to_string());

        // Evict old buckets to keep memory bounded.
        let now_sec = now_ms / 1000;
        let cutoff = now_sec.saturating_sub(self.skew_secs * 2 + 1);
        self.seen.retain(|&k, _| k >= cutoff);

        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_fresh_unique_requests() {
        let mut guard = ReplayGuard::new(30);
        let ts = now_ms();
        assert!(guard.check("req-1", ts).is_ok());
        assert!(guard.check("req-2", ts).is_ok());
    }

    #[test]
    fn rejects_duplicate_request_id() {
        let mut guard = ReplayGuard::new(30);
        let ts = now_ms();
        assert!(guard.check("dup", ts).is_ok());
        let err = guard.check("dup", ts).unwrap_err();
        assert!(matches!(err, ReplayError::Replay { .. }));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let mut guard = ReplayGuard::new(30);
        let old_ts = now_ms().saturating_sub(60_000); // 60 s in the past
        let err = guard.check("old", old_ts).unwrap_err();
        assert!(matches!(err, ReplayError::Stale { .. }));
    }

    #[test]
    fn rejects_future_timestamp() {
        let mut guard = ReplayGuard::new(30);
        let future_ts = now_ms() + 60_000;
        let err = guard.check("future", future_ts).unwrap_err();
        assert!(matches!(err, ReplayError::Stale { .. }));
    }
}
