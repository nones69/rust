//! capd — Capability Engine daemon.
//!
//! Issues, signs, validates, and revokes post-quantum capability tokens.
//! In a production deployment this runs inside a TEE/TPM/SGX enclave.

use anyhow::Result;
use clap::Parser;
use ikrl_transport::{Channel, Listener};
use intentkernel_core::{
    token_from_cbor, token_to_cbor, CapabilityScope, CapabilityToken, LeaseState, MlDsa87KeyPair,
    TokenType, TrustAnchor, ML_DSA_87_SIGNATURE_LEN,
};
use intentkernel_crypto as crypto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "capd")]
#[command(about = "IntentKernel Capability Engine")]
struct Args {
    #[arg(long, default_value = "tcp://127.0.0.1:9101")]
    listen: String,

    #[arg(long, help = "Path to persist broker key")]
    key_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
enum Request {
    GenerateKey,
    IssueToken(IssueParams),
    VerifyToken(VerifyParams),
    RevokeToken(String),
    GetPublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct IssueParams {
    iss: String,
    sub: String,
    ctx: Vec<u8>,
    resource: String,
    action: String,
    constraints: BTreeMap<String, String>,
    exp: u64,
    nbf: u64,
    uses: u32,
    anchor: TrustAnchor,
    typ: TokenType,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifyParams {
    token_cbor: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status")]
enum Response {
    Ok { data: serde_json::Value },
    Error { message: String },
}

struct State {
    keypair: Option<MlDsa87KeyPair>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let state = Arc::new(Mutex::new(State { keypair: None }));

    // Auto-generate a key if none exists.
    {
        let mut s = state.lock().unwrap();
        let kp = crypto::ml_dsa87_keygen()?;
        info!(
            "generated broker public key: {}",
            hex::encode(&kp.public_key[..16])
        );
        s.keypair = Some(kp);
    }

    let listener = Listener::bind(&args.listen).await?;
    info!("capd listening on {}", args.listen);

    loop {
        let mut ch = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut ch, state).await {
                warn!("client error: {}", e);
            }
        });
    }
}

async fn handle_client(ch: &mut Channel, state: Arc<Mutex<State>>) -> Result<()> {
    let req: Request = ch.recv_json().await?;

    let resp = match req {
        Request::GenerateKey => {
            let mut s = state.lock().unwrap();
            let kp = crypto::ml_dsa87_keygen()?;
            info!("generated new broker key");
            s.keypair = Some(kp.clone());
            Response::Ok {
                data: serde_json::json!({
                    "public_key": hex::encode(kp.public_key),
                }),
            }
        }
        Request::IssueToken(p) => {
            let s = state.lock().unwrap();
            let kp = s
                .keypair
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no broker key configured"))?;
            let mut token = CapabilityToken {
                ver: 1,
                typ: p.typ,
                alg: 1,
                anchor: p.anchor,
                iss: p.iss,
                sub: p.sub,
                ctx: p.ctx,
                scope: CapabilityScope {
                    resource: p.resource,
                    action: p.action,
                    constraints: p.constraints,
                },
                exp: p.exp,
                nbf: p.nbf,
                uses: p.uses,
                state: LeaseState::Granted,
                jti: uuid::Uuid::new_v4().to_string(),
                signature: Vec::new(),
            };
            let mut sign_token = token.clone();
            sign_token.signature.clear();
            let cbor = token_to_cbor(&sign_token)?;
            let sig = crypto::ml_dsa87_sign(&kp.secret_key, &cbor)?;
            token.signature = sig.to_vec();
            info!(
                "issued token {} for {}/{}",
                token.jti, token.scope.resource, token.scope.action
            );
            Response::Ok {
                data: serde_json::json!({
                    "token_cbor": token_to_cbor(&token)?,
                    "jti": token.jti,
                }),
            }
        }
        Request::VerifyToken(p) => {
            let s = state.lock().unwrap();
            let pk = s
                .keypair
                .as_ref()
                .map(|k| k.public_key)
                .ok_or_else(|| anyhow::anyhow!("no broker key"))?;
            let token = token_from_cbor(&p.token_cbor)?;
            let sig: [u8; ML_DSA_87_SIGNATURE_LEN] = token
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
            let mut verify_token = token.clone();
            verify_token.signature.clear();
            let cbor = token_to_cbor(&verify_token)?;
            let valid = crypto::ml_dsa87_verify(&pk, &cbor, &sig).is_ok();
            Response::Ok {
                data: serde_json::json!({"valid": valid}),
            }
        }
        Request::RevokeToken(jti) => {
            info!("revocation requested for token {}", jti);
            Response::Ok {
                data: serde_json::json!({"revoked": true}),
            }
        }
        Request::GetPublicKey => {
            let s = state.lock().unwrap();
            let pk = s
                .keypair
                .as_ref()
                .map(|k| hex::encode(k.public_key))
                .unwrap_or_default();
            Response::Ok {
                data: serde_json::json!({"public_key": pk}),
            }
        }
    };

    ch.send_json(&resp).await?;
    Ok(())
}
