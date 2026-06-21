use crate::crypto::{self, BrokerKeys, SIGNATURE_LEN};
use crate::error::KernelError;
use crate::types::{Intent, PolicyDecision, Token, TokenType, wall_ms};

/// Broker identity and token signing — native IntentOS kernel code.
pub struct TokenBroker {
    keys: BrokerKeys,
    issuer: String,
}

impl TokenBroker {
    pub fn generate(issuer: &str) -> Result<Self, KernelError> {
        Ok(Self {
            keys: crypto::generate_broker_keys()?,
            issuer: issuer.to_string(),
        })
    }

    pub fn mint(
        &self,
        intent: &Intent,
        decision: &PolicyDecision,
    ) -> Result<Token, KernelError> {
        if !decision.allowed {
            return Err(KernelError::PolicyDenied(decision.reason.clone()));
        }

        let now = wall_ms();
        let mut token = Token {
            ver: 1,
            typ: TokenType::Capability,
            anchor: intent.anchor,
            iss: self.issuer.clone(),
            sub: intent.actor.clone(),
            scope: crate::types::CapabilityScope::new(&intent.resource, &intent.action),
            exp: now + decision.ttl_ms,
            nbf: now,
            uses: decision.max_uses,
            jti: uuid::Uuid::new_v4().to_string(),
            signature: Vec::new(),
        };

        let payload = encode_unsigned(&token)?;
        let sig = self.keys.sign(&payload)?;
        token.signature = sig.to_vec();
        Ok(token)
    }

    pub fn verify(&self, token: &Token) -> Result<(), KernelError> {
        let now = wall_ms();
        if token.nbf > now {
            return Err(KernelError::NotYetValid);
        }
        if token.exp < now {
            return Err(KernelError::Expired);
        }
        if token.uses == 0 {
            return Err(KernelError::Exhausted);
        }

        let payload = encode_unsigned(token)?;
        let sig: [u8; SIGNATURE_LEN] = token
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| KernelError::BadSignature)?;
        self.keys
            .verify(&payload, &sig)
            .map_err(|_| KernelError::BadSignature)
    }
}

pub fn encode_unsigned(token: &Token) -> Result<Vec<u8>, KernelError> {
    let mut unsigned = token.clone();
    unsigned.signature.clear();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&unsigned, &mut buf)
        .map_err(|e| KernelError::Serialize(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;
    use crate::types::{Intent, TrustAnchor};

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
    fn verify_rejects_expired_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.exp = wall_ms().saturating_sub(1);

        assert!(matches!(broker.verify(&token), Err(KernelError::Expired)));
    }

    #[test]
    fn verify_rejects_not_yet_valid_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.nbf = wall_ms() + 60_000;

        assert!(matches!(broker.verify(&token), Err(KernelError::NotYetValid)));
    }
}