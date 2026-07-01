use crate::crypto::{self, BrokerKeys, SIGNATURE_LEN, TOKEN_SIG_V1_ED25519};
use crate::error::KernelError;
use crate::revocation::RevocationList;
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
        self.verify_with_revocations(token, &RevocationList::new())
    }

    pub fn verify_with_revocations(
        &self,
        token: &Token,
        revocations: &RevocationList,
    ) -> Result<(), KernelError> {
        self.verify_signature(token)?;
        let now = wall_ms();
        if token.nbf > now {
            return Err(KernelError::NotYetValid);
        }
        if token.exp <= now {
            return Err(KernelError::Expired);
        }
        if revocations.is_revoked(&token.jti) {
            return Err(KernelError::Revoked);
        }
        if token.uses == 0 {
            return Err(KernelError::Exhausted);
        }
        Ok(())
    }

    pub fn verify_for_scope(
        &self,
        token: &Token,
        revocations: &RevocationList,
        resource: &str,
        action: &str,
    ) -> Result<(), KernelError> {
        self.verify_with_revocations(token, revocations)?;
        if token.scope.resource != resource || token.scope.action != action {
            return Err(KernelError::ScopeMismatch);
        }
        Ok(())
    }

    fn verify_signature(&self, token: &Token) -> Result<(), KernelError> {
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

    fn resign(broker: &TokenBroker, token: &mut Token) {
        let payload = encode_unsigned(token).unwrap();
        token.signature = broker
            .keys
            .sign_versioned(&payload, token.ver)
            .unwrap()
            .to_vec();
    }

    #[test]
    fn verify_rejects_expired_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.exp = wall_ms().saturating_sub(1);
        resign(&broker, &mut token);

        assert!(matches!(broker.verify(&token), Err(KernelError::Expired)));
    }

    #[test]
    fn test_reject_expired_token() {
        verify_rejects_expired_token();
    }

    #[test]
    fn test_expiry_boundary_exact_tick() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.exp = wall_ms();
        resign(&broker, &mut token);

        assert!(matches!(broker.verify(&token), Err(KernelError::Expired)));
    }

    #[test]
    fn verify_rejects_not_yet_valid_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.nbf = wall_ms() + 60_000;
        resign(&broker, &mut token);

        assert!(matches!(broker.verify(&token), Err(KernelError::NotYetValid)));
    }

    #[test]
    fn verify_rejects_exhausted_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let mut token = broker.mint(&intent, &decision).unwrap();
        token.uses = 0;
        resign(&broker, &mut token);

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
    fn test_reject_tampered_signature() {
        verify_rejects_tampered_signature();
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
    fn test_reject_wrong_scope_token() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let revocations = RevocationList::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();

        assert!(matches!(
            broker.verify_for_scope(&token, &revocations, "file", "write"),
            Err(KernelError::ScopeMismatch)
        ));
    }

    #[test]
    fn test_reject_replayed_token_after_burn() {
        let broker = TokenBroker::generate("test-broker").unwrap();
        let mut revocations = RevocationList::new();
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        assert!(revocations.revoke(&token.jti));

        assert!(matches!(
            broker.verify_with_revocations(&token, &revocations),
            Err(KernelError::Revoked)
        ));
    }

    #[test]
    fn pqc_hybrid_mint_and_verify() {
        use crate::crypto::TOKEN_SIG_V2_PQC_HYBRID;
        let mut broker = TokenBroker::generate("pqc-broker").unwrap();
        broker.set_sig_version(TOKEN_SIG_V2_PQC_HYBRID);
        let intent = read_intent();
        let decision = PolicyEngine::evaluate(&intent);
        let token = broker.mint(&intent, &decision).unwrap();
        assert_eq!(token.ver, TOKEN_SIG_V2_PQC_HYBRID);
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