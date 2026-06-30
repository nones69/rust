//! Intent Broker federation shell commands (Phase 2).

use crate::builtins::BuiltinContext;
use crate::parser::ParsedLine;
use anyhow::{Context, Result};
use intentos_audit::AuditEventKind;
use intentos_kernel::{BrokerPeer, wall_ms};
use intentos_kernel::TrustAnchor;
use intentos_utilities::FederationError;

impl BuiltinContext<'_> {
    pub fn broker_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");
        match sub {
            "status" => {
                let session = self.runtime.loom.session();
                let hub = &self.runtime.utilities.lock().unwrap().federation;
                println!(
                    "broker device={} loom_peers={} hub_peers={} signing_key={}",
                    hub.advertise(),
                    session.broker_peers.len(),
                    hub.peers().len(),
                    if session.signing_public_key_hex.is_empty() {
                        "none"
                    } else {
                        "present"
                    }
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
                "usage: broker status|list|register|delegate (got: {other})"
            ),
        }
        Ok(())
    }
}