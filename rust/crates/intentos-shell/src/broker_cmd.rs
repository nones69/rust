//! Intent Broker federation shell commands (Phase 2).

use crate::builtins::BuiltinContext;
use crate::parser::ParsedLine;
use anyhow::{Context, Result};
use intentos_audit::AuditEventKind;
use intentos_kernel::{BrokerPeer, wall_ms};
use intentos_kernel::TrustAnchor;
use intentos_utilities::{
    decode_payload_hex, BrokerWireHub, FederationError,
};

impl BuiltinContext<'_> {
    pub fn broker_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");
        match sub {
            "status" | "wire-status" => {
                let session = self.runtime.loom.session();
                let hub = &self.runtime.utilities.lock().unwrap().federation;
                let wire = BrokerWireHub::open_default();
                println!(
                    "broker device={} loom_peers={} hub_peers={} signing_key={} wire_root={}",
                    hub.advertise(),
                    session.broker_peers.len(),
                    hub.peers().len(),
                    if session.signing_public_key_hex.is_empty() {
                        "none"
                    } else {
                        "present"
                    },
                    wire.root().display()
                );
                println!(
                    "wire_version={} sig_version={}",
                    intentos_utilities::BROKER_WIRE_VERSION,
                    self.runtime.kernel().token_sig_version()
                );
            }
            "list" => {
                let session = self.runtime.loom.session();
                for p in &session.broker_peers {
                    println!(
                        "peer={} key={}.. registered={}",
                        p.peer_id,
                        &p.public_key_hex[..p.public_key_hex.len().min(16)],
                        p.registered_at_ms
                    );
                }
                if session.broker_peers.is_empty() {
                    println!("(no peers — `broker register <id> <pubkey_hex>`)");
                }
            }
            "register" => {
                let peer_id = parsed
                    .arg(1)
                    .context("usage: broker register <peer_id> <public_key_hex> [label]")?;
                let pubkey = parsed.arg(2).context(
                    "usage: broker register <peer_id> <public_key_hex> [label]",
                )?;
                let mut peer = BrokerPeer::new(peer_id, pubkey, wall_ms());
                if let Some(label) = parsed.arg(3) {
                    peer.label = label.to_string();
                }
                self.runtime.loom.register_broker_peer(peer.clone())?;
                self.runtime.sync_federation_from_loom();
                let _ = self.runtime.audit.record(
                    AuditEventKind::BrokerPeerRegistered,
                    &self.state.actor,
                    format!("peer={} key_prefix={}", peer.peer_id, &peer.public_key_hex[..16.min(peer.public_key_hex.len())]),
                );
                println!("registered broker peer={}", peer.peer_id);
            }
            "send" => {
                let peer_id = parsed
                    .arg(1)
                    .context("usage: broker send <peer_id> <payload>")?;
                let payload = parsed.rest_from(2);
                if payload.is_empty() {
                    anyhow::bail!("usage: broker send <peer_id> <payload>");
                }
                self.runtime.loom.ensure_signing_keys()?;
                let session = self.runtime.loom.session();
                let peer = session
                    .broker_peers
                    .iter()
                    .find(|p| p.peer_id == peer_id)
                    .cloned()
                    .context("unknown peer — register first")?;
                let secret = self.runtime.loom.signing_secret_key_hex();
                let wire = BrokerWireHub::open_default();
                let mut msg = BrokerWireHub::build_delegate(
                    &session.profile_id,
                    peer_id,
                    payload.as_bytes(),
                    wall_ms(),
                );
                BrokerWireHub::sign_message(&mut msg, &secret)
                    .map_err(|e| anyhow::anyhow!("wire sign: {e}"))?;
                BrokerWireHub::verify_message(&msg, &session.signing_public_key_hex)
                    .map_err(|e| anyhow::anyhow!("local verify failed: {e}"))?;
                wire.enqueue_to_peer(&peer, &msg)
                    .map_err(|e| anyhow::anyhow!("wire enqueue: {e}"))?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::BrokerWireSent,
                    &self.state.actor,
                    format!("peer={peer_id} nonce={} bytes={}", msg.nonce, payload.len()),
                );
                println!("wire sent peer={peer_id} nonce={}", msg.nonce);
            }
            "recv" => {
                let max: usize = parsed.arg(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                self.runtime.loom.ensure_signing_keys()?;
                let device_id = self.runtime.loom.profile_id();
                let secret = self.runtime.loom.signing_secret_key_hex();
                let session = self.runtime.loom.session();
                let wire = BrokerWireHub::open_default();
                let messages = wire
                    .recv_inbox(&device_id, max)
                    .map_err(|e| anyhow::anyhow!("wire recv: {e}"))?;
                if messages.is_empty() {
                    println!("(inbox empty)");
                    return Ok(());
                }
                for msg in &messages {
                    let peer_key = session
                        .broker_peers
                        .iter()
                        .find(|p| p.peer_id == msg.from_device)
                        .map(|p| p.public_key_hex.as_str())
                        .unwrap_or("");
                    if !peer_key.is_empty() {
                        let _ = BrokerWireHub::verify_message(msg, peer_key);
                    }
                    let payload = decode_payload_hex(&msg.payload_b64).unwrap_or_default();
                    println!(
                        "wire {:?} from={} nonce={} payload={}",
                        msg.kind,
                        msg.from_device,
                        msg.nonce,
                        String::from_utf8_lossy(&payload)
                    );
                    let _ = self.runtime.audit.record(
                        AuditEventKind::BrokerWireReceived,
                        &self.state.actor,
                        format!(
                            "from={} kind={:?} nonce={}",
                            msg.from_device, msg.kind, msg.nonce
                        ),
                    );
                    if msg.kind == intentos_utilities::BrokerWireKind::Delegate {
                        let _ = wire.process_delegate_ack(msg, &secret, wall_ms());
                    }
                }
            }
            "delegate" => {
                let peer_id = parsed
                    .arg(1)
                    .context("usage: broker delegate <peer_id> <payload>")?;
                let payload = parsed.rest_from(2);
                if payload.is_empty() {
                    anyhow::bail!("usage: broker delegate <peer_id> <payload>");
                }
                let intent = intentos_kernel::Intent {
                    actor: self.state.actor.clone(),
                    resource: "network".into(),
                    action: "send".into(),
                    anchor: TrustAnchor::UiEvent,
                    timestamp_ms: wall_ms(),
                    metadata: Default::default(),
                };
                let handle = self
                    .runtime
                    .kernel()
                    .intent_to_handle_confirmed(intent, true)?;
                let hub = &self.runtime.utilities.lock().unwrap().federation;
                let out = hub
                    .delegate_to_registered(&self.runtime.kernel(), handle, peer_id, payload.as_bytes())
                    .map_err(|e| match e {
                        FederationError::Denied(r) => anyhow::anyhow!("delegation denied: {r}"),
                        FederationError::UnknownPeer(id) => {
                            anyhow::anyhow!("unknown peer: {id}")
                        }
                    })?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::BrokerDelegated,
                    &self.state.actor,
                    format!("peer={peer_id} bytes={} result_len={}", payload.len(), out.len()),
                );
                println!("{}", String::from_utf8_lossy(&out));
            }
            other => anyhow::bail!(
                "usage: broker status|list|register|send|recv|delegate (got: {other})"
            ),
        }
        Ok(())
    }
}