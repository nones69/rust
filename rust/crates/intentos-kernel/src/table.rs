use crate::error::KernelError;
use crate::types::{
    CapabilityKind, Handle, SlotEntry, SyscallOp, SyscallRequest, SyscallResult, Token,
    CAP_TABLE_SIZE, handle_checksum, mono_ns,
};
use std::collections::HashSet;

/// In-kernel capability slot table — ground-up implementation.
pub struct CapabilityTable {
    slots: Vec<Option<SlotEntry>>,
    generations: Vec<u16>,
    seen_jtis: HashSet<String>,
}

impl CapabilityTable {
    pub fn new() -> Self {
        Self {
            slots: (0..CAP_TABLE_SIZE).map(|_| None).collect(),
            generations: vec![1; CAP_TABLE_SIZE],
            seen_jtis: HashSet::new(),
        }
    }

    pub fn register(&mut self, token: &Token) -> Result<Handle, KernelError> {
        if !self.seen_jtis.insert(token.jti.clone()) {
            return Err(KernelError::Replay);
        }

        let now_ms = crate::types::wall_ms();
        if token.nbf > now_ms {
            return Err(KernelError::NotYetValid);
        }
        if token.exp < now_ms {
            return Err(KernelError::Expired);
        }
        if token.uses == 0 {
            return Err(KernelError::Exhausted);
        }

        let now = mono_ns();
        let ttl_ns = token.exp.saturating_sub(crate::types::wall_ms()).saturating_mul(1_000_000);
        let kind = CapabilityKind::from_scope(&token.scope.resource, &token.scope.action);

        for (idx, slot) in self.slots.iter_mut().enumerate() {
            let stale = slot.as_ref().map(|e| e.expires_ns < now).unwrap_or(true);
            if !stale {
                continue;
            }

            self.generations[idx] = self.generations[idx].wrapping_add(1);
            let generation = self.generations[idx];
            *slot = Some(SlotEntry {
                generation,
                expires_ns: now + ttl_ns,
                uses_left: token.uses,
                kind,
                scope: token.scope.clone(),
                token_jti: token.jti.clone(),
            });

            let checksum = handle_checksum(idx as u32, generation);
            return Ok(Handle {
                slot: idx as u32,
                generation,
                checksum,
            });
        }

        Err(KernelError::TableFull)
    }

    pub fn syscall(&mut self, handle: Handle, req: &SyscallRequest) -> SyscallResult {
        if handle.slot as usize >= CAP_TABLE_SIZE {
            return SyscallResult::Denied("invalid handle slot".into());
        }
        if handle.checksum != handle_checksum(handle.slot, handle.generation) {
            return SyscallResult::Denied("handle checksum mismatch".into());
        }

        let slot = match self.slots.get_mut(handle.slot as usize) {
            Some(Some(entry)) if entry.generation == handle.generation => entry,
            _ => return SyscallResult::Denied("stale or missing capability".into()),
        };

        let now = mono_ns();
        if slot.expires_ns < now {
            return SyscallResult::Denied("capability expired".into());
        }
        if slot.uses_left == 0 {
            return SyscallResult::Denied("capability exhausted".into());
        }

        if !op_matches_kind(&req.op, slot.kind) {
            return SyscallResult::Denied(format!(
                "syscall {:?} not allowed for capability {:?}",
                req.op, slot.kind
            ));
        }

        slot.uses_left = slot.uses_left.saturating_sub(1);
        if slot.uses_left == 0 {
            slot.expires_ns = 0;
        }

        SyscallResult::Allowed {
            kind: slot.kind,
            remaining_uses: slot.uses_left,
        }
    }

    pub fn slot_count_active(&self) -> usize {
        let now = mono_ns();
        self.slots
            .iter()
            .filter(|s| s.as_ref().map(|e| e.expires_ns >= now && e.uses_left > 0).unwrap_or(false))
            .count()
    }
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self::new()
    }
}

fn op_matches_kind(op: &SyscallOp, kind: CapabilityKind) -> bool {
    matches!(
        (op, kind),
        (SyscallOp::Read, CapabilityKind::FileRead)
            | (SyscallOp::Write, CapabilityKind::FileWrite)
            | (SyscallOp::List, CapabilityKind::DirList)
            | (SyscallOp::Send, CapabilityKind::NetSend)
            | (SyscallOp::Infer, CapabilityKind::AiInfer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;
    use crate::token::TokenBroker;
    use crate::types::{Intent, TrustAnchor, wall_ms};

    fn read_intent() -> Intent {
        Intent {
            actor: "user".into(),
            resource: "file".into(),
            action: "read".into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn register_and_consume() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let mut table = CapabilityTable::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        broker.verify(&token).unwrap();
        let handle = table.register(&token).unwrap();

        let result = table.syscall(
            handle,
            &SyscallRequest {
                op: SyscallOp::Read,
                target: "/tmp/x".into(),
                payload: vec![],
            },
        );
        assert!(matches!(result, SyscallResult::Allowed { .. }));

        let denied = table.syscall(
            handle,
            &SyscallRequest {
                op: SyscallOp::Write,
                target: "/tmp/x".into(),
                payload: vec![],
            },
        );
        assert!(matches!(denied, SyscallResult::Denied(_)));
    }

    #[test]
    fn register_rejects_expired_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let mut table = CapabilityTable::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.exp = wall_ms().saturating_sub(1);

        let err = table.register(&token).unwrap_err();
        assert!(matches!(err, KernelError::Expired));
    }

    #[test]
    fn register_rejects_not_yet_valid_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let mut table = CapabilityTable::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.nbf = wall_ms() + 60_000;

        let err = table.register(&token).unwrap_err();
        assert!(matches!(err, KernelError::NotYetValid));
    }

    #[test]
    fn invalid_handle_checksum_is_denied() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let mut table = CapabilityTable::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        let handle = table.register(&token).unwrap();
        let invalid = Handle {
            checksum: handle.checksum ^ 0x00FF,
            ..handle
        };

        let result = table.syscall(
            invalid,
            &SyscallRequest {
                op: SyscallOp::Read,
                target: "/tmp/x".into(),
                payload: vec![],
            },
        );

        assert_eq!(result, SyscallResult::Denied("handle checksum mismatch".into()));
    }
}