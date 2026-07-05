use crate::crypto::{self, BrokerKeys, SIGNATURE_LEN, TOKEN_SIG_V1_ED25519};
use crate::error::KernelError;
use crate::types::{Intent, PolicyDecision, Token, TokenType, wall_ms};

/// Broker identity and token signing — native IntentOS kernel code.
pub struct TokenBroker {
    keys: BrokerKeys,
    issuer: String,
    sig_version: u8,
}

impl TokenBroker {
    pub fn generate(issuer: &str) -> Result<Self, KernelError> {
        Ok(Self {
            keys: crypto::generate_broker_keys()?,
            issuer: issuer.to_string(),
            sig_version: TOKEN_SIG_V1_ED25519,
        })
    }

    pub fn set_sig_version(&mut self, ver: u8) {
        self.sig_version = ver;
    }

    pub fn sig_version(&self) -> u8 {
        self.sig_version
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
            ver: self.sig_version,
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
        let sig = self.keys.sign_versioned(&payload, self.sig_version)?;
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
            .verify_versioned(&payload, &sig, token.ver)
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

    #[test]
    fn verify_rejects_exhausted_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.uses = 0;

        assert!(matches!(broker.verify(&token), Err(KernelError::Exhausted)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        // Flip a bit in the raw Ed25519 signature region.
        token.signature[0] ^= 0xFF;

        assert!(matches!(broker.verify(&token), Err(KernelError::BadSignature)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        // Mutate a signed field; signature is over the encoded (unsigned) token,
        // so changing the subject must invalidate it (privilege-escalation attempt).
        token.sub = "attacker".into();

        assert!(matches!(broker.verify(&token), Err(KernelError::BadSignature)));
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let broker = TokenBroker::generate("broker-a").unwrap();
        let attacker = TokenBroker::generate("broker-b").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        // Token minted by a different broker (different key) must not verify
        // against the legitimate broker.
        let token = attacker.mint(&intent, &decision).unwrap();

        assert!(matches!(broker.verify(&token), Err(KernelError::BadSignature)));
    }

    #[test]
    fn pqc_simulation_mint_and_verify() {
        use crate::crypto::TOKEN_SIG_V2_PQC_SIMULATION;
        let mut broker = TokenBroker::generate("pqc-broker").unwrap();
        broker.set_sig_version(TOKEN_SIG_V2_PQC_SIMULATION);
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        assert_eq!(token.ver, TOKEN_SIG_V2_PQC_SIMULATION);
        assert!(broker.verify(&token).is_ok());
    }

    #[test]
    fn verify_rejects_truncated_signature() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.signature.truncate(10);

        assert!(matches!(broker.verify(&token), Err(KernelError::BadSignature)));
    }
}