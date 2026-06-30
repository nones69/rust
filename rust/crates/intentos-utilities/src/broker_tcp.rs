//! TCP transport for Intent Broker wire messages (newline-delimited JSON).

use crate::broker_wire::{BrokerWireError, BrokerWireHub, BrokerWireMessage};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

const DEFAULT_BROKER_TCP_PORT: u16 = 9710;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpListenManifest {
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub endpoint: String,
}

pub struct BrokerTcpTransport;

impl BrokerTcpTransport {
    pub fn default_port() -> u16 {
        DEFAULT_BROKER_TCP_PORT
    }

    pub fn parse_endpoint(endpoint: &str) -> Result<SocketAddr, BrokerWireError> {
        let trimmed = endpoint.trim();
        let host_port = trimmed
            .strip_prefix("tcp://")
            .ok_or_else(|| BrokerWireError::Protocol(format!("not a tcp endpoint: {endpoint}")))?;
        resolve_addr(host_port)
    }

    pub fn endpoint_for(addr: SocketAddr) -> String {
        format!("tcp://{addr}")
    }

    pub fn write_listen_manifest(
        hub: &BrokerWireHub,
        device_id: &str,
        addr: SocketAddr,
    ) -> Result<TcpListenManifest, BrokerWireError> {
        let manifest = TcpListenManifest {
            device_id: device_id.to_string(),
            host: addr.ip().to_string(),
            port: addr.port(),
            endpoint: Self::endpoint_for(addr),
        };
        let path = hub.root().join("tcp_listen.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
        Ok(manifest)
    }

    pub fn read_listen_manifest(hub: &BrokerWireHub) -> Result<Option<TcpListenManifest>, BrokerWireError> {
        let path = hub.root().join("tcp_listen.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn send_message(addr: SocketAddr, msg: &BrokerWireMessage) -> Result<(), BrokerWireError> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let line = serde_json::to_string(msg)?;
        writeln!(stream, "{line}")?;
        stream.flush()?;
        Ok(())
    }

    /// Bind `127.0.0.1:port` (port `0` = ephemeral) and accept connections.
    pub fn serve(
        hub: &BrokerWireHub,
        device_id: &str,
        port: u16,
        once: bool,
        max_messages: usize,
    ) -> Result<TcpListenManifest, BrokerWireError> {
        let bind_port = if port == 0 { 0 } else { port };
        let listener = TcpListener::bind(("127.0.0.1", bind_port))?;
        let addr = listener.local_addr()?;
        let manifest = Self::write_listen_manifest(hub, device_id, addr)?;
        listener
            .set_nonblocking(false)
            .map_err(BrokerWireError::Io)?;

        let mut accepted = 0usize;
        let mut total_messages = 0usize;
        loop {
            let (stream, peer) = listener.accept()?;
            accepted += 1;
            let n = Self::drain_stream_to_inbox(hub, device_id, stream)?;
            total_messages += n;
            if once || total_messages >= max_messages {
                break;
            }
            if accepted >= 32 {
                break;
            }
            let _ = peer;
        }
        Ok(manifest)
    }

    pub fn drain_stream_to_inbox(
        hub: &BrokerWireHub,
        device_id: &str,
        stream: TcpStream,
    ) -> Result<usize, BrokerWireError> {
        let reader = BufReader::new(stream);
        let mut count = 0usize;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let msg: BrokerWireMessage = serde_json::from_str(&line)?;
            hub.append_message_public(&hub.inbox_path(device_id), &msg)?;
            count += 1;
        }
        Ok(count)
    }
}

fn resolve_addr(host_port: &str) -> Result<SocketAddr, BrokerWireError> {
    let mut addrs = host_port
        .to_socket_addrs()
        .map_err(BrokerWireError::Io)?;
    addrs
        .next()
        .ok_or_else(|| BrokerWireError::Protocol(format!("unresolvable tcp address: {host_port}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker_wire::BrokerWireHub;
    use intentos_kernel::generate_broker_keys;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("intentos-broker-tcp-{nanos}"))
    }

    #[test]
    fn tcp_send_and_listen_round_trip() {
        let root = temp_root();
        let hub = BrokerWireHub::open(&root);
        let keys = generate_broker_keys().unwrap();
        let secret_hex: String = keys.secret_key_bytes().iter().map(|b| format!("{b:02x}")).collect();

        let device_id = "device-tcp";
        let server_hub = BrokerWireHub::open(&root);
        let handle = thread::spawn(move || {
            BrokerTcpTransport::serve(&server_hub, device_id, 0, true, 10).unwrap()
        });

        thread::sleep(Duration::from_millis(50));
        let listen_path = root.join("tcp_listen.json");
        for _ in 0..50 {
            if listen_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let m: TcpListenManifest =
            serde_json::from_slice(&std::fs::read(&listen_path).unwrap()).unwrap();
        let addr = BrokerTcpTransport::parse_endpoint(&m.endpoint).unwrap();

        let mut msg = BrokerWireHub::build_delegate(device_id, "peer-x", b"tcp-payload", 99);
        BrokerWireHub::sign_message(&mut msg, &secret_hex).unwrap();
        BrokerTcpTransport::send_message(addr, &msg).unwrap();

        let manifest = handle.join().unwrap();
        assert!(manifest.port > 0);
        let inbox = hub.recv_inbox(device_id, 5).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(
            crate::broker_wire::decode_payload_hex(&inbox[0].payload_b64).unwrap(),
            b"tcp-payload"
        );
    }
}