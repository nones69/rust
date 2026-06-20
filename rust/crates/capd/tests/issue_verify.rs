//! Integration tests for capd token issue/verify semantics (in-process).

use intentkernel_core::{
    token_from_cbor, CapabilityScope, CapabilityToken, LeaseState, TokenType, TrustAnchor,
    ML_DSA_87_SIGNATURE_LEN,
};
use intentkernel_crypto as crypto;

#[test]
fn mock_pqc_token_roundtrip() {
    let kp = crypto::ml_dsa87_keygen().unwrap();
    let mut token = CapabilityToken {
        ver: 1,
        typ: TokenType::Capability,
        alg: 1,
        anchor: TrustAnchor::UiEvent,
        iss: "capd-test".into(),
        sub: "app".into(),
        ctx: vec![0u8; 48],
        scope: CapabilityScope::new("file", "read"),
        exp: 9_999_999_999_999,
        nbf: 0,
        uses: 1,
        state: LeaseState::Granted,
        jti: "test-jti".into(),
        signature: Vec::new(),
    };
    let cbor = intentkernel_core::token_to_cbor(&token).unwrap();
    let sig = crypto::ml_dsa87_sign(&kp.secret_key, &cbor).unwrap();
    token.signature = sig.to_vec();
    let encoded = intentkernel_core::token_to_cbor(&token).unwrap();
    let decoded = token_from_cbor(&encoded).unwrap();
    assert_eq!(decoded.jti, "test-jti");
    assert_eq!(decoded.signature.len(), ML_DSA_87_SIGNATURE_LEN);
}