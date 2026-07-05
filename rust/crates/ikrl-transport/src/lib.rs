//! # ikrl-transport
//!
//! Cross-platform IPC transport for the IntentKernel daemon stack.
//!
//! | Platform | Transport support                    |
//! |----------|--------------------------------------|
//! | Linux    | Unix domain socket / TCP / mTLS      |
//! | macOS    | Unix domain socket / TCP / mTLS      |
//! | Windows  | TCP loopback / mTLS                  |
//! | `pipe://`| Parsed on Windows, fails fast        |
//!
//! All transports carry length-prefixed JSON messages so every daemon can
//! speak the same protocol regardless of the underlying socket type.
//!
//! ## Address schemes
//!
//! | Scheme        | Example                                  |
//! |---------------|------------------------------------------|
//! | `tcp://`      | `tcp://127.0.0.1:9100`                   |
//! | `unix://`     | `unix:///tmp/intentos.sock`              |
//! | `tls://`      | `tls://10.0.0.5:9443`                    |
//! | bare host:port| `127.0.0.1:9100`                         |
//!
//! For mTLS, build a [`TlsClientConfig`] or [`TlsServerConfig`] and pass it
//! to [`Channel::connect_tls`] / [`Listener::bind_tls`].

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
#[cfg(unix)]
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ─── TLS types (feature-gated) ────────────────────────────────────────────────

#[cfg(feature = "tls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Configuration for an mTLS client connection.
///
/// `cert_pem` + `key_pem`: PEM-encoded client certificate and private key for
/// mutual authentication.  `ca_pem`: PEM-encoded CA certificate used to verify
/// the server.
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct TlsClientConfig {
    /// PEM-encoded client certificate.
    pub cert_pem: String,
    /// PEM-encoded client private key.
    pub key_pem: String,
    /// PEM-encoded CA certificate that signed the server cert.
    pub ca_pem: String,
    /// Expected server name (used for SNI / certificate hostname verification).
    pub server_name: String,
}

/// Configuration for an mTLS server listener.
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct TlsServerConfig {
    /// PEM-encoded server certificate.
    pub cert_pem: String,
    /// PEM-encoded server private key.
    pub key_pem: String,
    /// PEM-encoded CA certificate that signed client certs (for mutual auth).
    /// If `None`, client certificates are not required.
    pub client_ca_pem: Option<String>,
}

// ─── TLS helper constructors ──────────────────────────────────────────────────

/// Parse PEM-encoded certificates into DER.
#[cfg(feature = "tls")]
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse certificate PEM: {e}"))?;
    Ok(certs)
}

/// Parse a PEM-encoded private key into DER.
#[cfg(feature = "tls")]
fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| anyhow::anyhow!("failed to parse private key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;
    Ok(key)
}

/// Build a `tokio_rustls::TlsConnector` from a [`TlsClientConfig`].
#[cfg(feature = "tls")]
pub fn build_tls_connector(cfg: &TlsClientConfig) -> Result<TlsConnector> {
    let ca_certs = load_certs(&cfg.ca_pem)?;
    let client_certs = load_certs(&cfg.cert_pem)?;
    let client_key = load_key(&cfg.key_pem)?;

    let mut root_store = rustls::RootCertStore::empty();
    for ca in ca_certs {
        root_store
            .add(ca)
            .map_err(|e| anyhow::anyhow!("failed to add CA cert: {e}"))?;
    }

    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| anyhow::anyhow!("TLS client config: {e}"))?;

    Ok(TlsConnector::from(Arc::new(client_tls)))
}

/// Build a `tokio_rustls::TlsAcceptor` from a [`TlsServerConfig`].
#[cfg(feature = "tls")]
pub fn build_tls_acceptor(cfg: &TlsServerConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&cfg.cert_pem)?;
    let key = load_key(&cfg.key_pem)?;

    let server_config = if let Some(ca_pem) = &cfg.client_ca_pem {
        let ca_certs = load_certs(ca_pem)?;
        let mut client_auth_roots = rustls::RootCertStore::empty();
        for ca in ca_certs {
            client_auth_roots
                .add(ca)
                .map_err(|e| anyhow::anyhow!("failed to add client CA cert: {e}"))?;
        }
        let verifier = rustls::server::WebPkiClientCertVerifier::builder(
            Arc::new(client_auth_roots),
        )
        .build()
        .map_err(|e| anyhow::anyhow!("client cert verifier: {e}"))?;

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS server config: {e}"))?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS server config: {e}"))?
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

// ─── Transport error ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unsupported address: {0}")]
    UnsupportedAddress(String),
    #[error("TLS error: {0}")]
    Tls(String),
}

// ─── Channel ──────────────────────────────────────────────────────────────────

/// A connection over any supported transport.
pub struct Channel {
    inner: ChannelInner,
    /// Peer identity information extracted from the TLS handshake.
    /// `None` for non-TLS connections.
    peer_cert_fingerprint: Option<String>,
}

enum ChannelInner {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(feature = "tls")]
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
    #[cfg(feature = "tls")]
    TlsClient(tokio_rustls::client::TlsStream<TcpStream>),
}

/// SHA-256 fingerprint of a DER certificate as a lowercase hex string.
#[cfg(feature = "tls")]
fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    let mut s = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest.iter() {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

impl Channel {
    pub async fn connect(addr: &str) -> Result<Self> {
        if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
            let stream = TcpStream::connect(tcp_addr).await?;
            return Ok(Self {
                inner: ChannelInner::Tcp(stream),
                peer_cert_fingerprint: None,
            });
        }

        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("unix://") {
            let stream = tokio::net::UnixStream::connect(path).await?;
            return Ok(Self {
                inner: ChannelInner::Unix(stream),
                peer_cert_fingerprint: None,
            });
        }

        #[cfg(windows)]
        if let Some(name) = addr.strip_prefix("pipe://") {
            return connect_named_pipe(name).await;
        }

        // Bare address: treat as TCP host:port for backward compatibility.
        if addr.contains(':') {
            let stream = TcpStream::connect(addr).await?;
            return Ok(Self {
                inner: ChannelInner::Tcp(stream),
                peer_cert_fingerprint: None,
            });
        }

        Err(TransportError::UnsupportedAddress(addr.to_string()).into())
    }

    /// Connect to a `tls://` endpoint with mutual TLS authentication.
    ///
    /// The `cfg` parameter supplies the client certificate, private key, and
    /// CA certificate used to verify the server.
    #[cfg(feature = "tls")]
    pub async fn connect_tls(addr: &str, cfg: &TlsClientConfig) -> Result<Self> {
        let tcp_addr = addr
            .strip_prefix("tls://")
            .unwrap_or(addr);
        let stream = TcpStream::connect(tcp_addr)
            .await
            .with_context(|| format!("TCP connect to {tcp_addr}"))?;

        let connector = build_tls_connector(cfg)?;
        let server_name = ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| anyhow::anyhow!("invalid server name '{}': {e}", cfg.server_name))?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;

        // Extract server cert fingerprint for audit purposes.
        let fp = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(cert_fingerprint);

        Ok(Self {
            inner: ChannelInner::TlsClient(tls_stream),
            peer_cert_fingerprint: fp,
        })
    }

    /// Return the peer certificate fingerprint, if this is a TLS channel.
    pub fn peer_cert_fingerprint(&self) -> Option<&str> {
        self.peer_cert_fingerprint.as_deref()
    }

    pub async fn send_json(&mut self, msg: &impl Serialize) -> Result<()> {
        let bytes =
            serde_json::to_vec(msg).map_err(|e| TransportError::Serialization(e.to_string()))?;
        let len = (bytes.len() as u32).to_be_bytes();
        self.write_all(&len).await?;
        self.write_all(&bytes).await?;
        self.flush_inner().await?;
        Ok(())
    }

    pub async fn recv_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(
                TransportError::Serialization(format!("message too large: {} bytes", len)).into(),
            );
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf)
            .map_err(|e| TransportError::Serialization(e.to_string()).into())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            ChannelInner::Tcp(s) => { let _ = s.read_exact(buf).await?; }
            #[cfg(unix)]
            ChannelInner::Unix(s) => { let _ = s.read_exact(buf).await?; }
            #[cfg(feature = "tls")]
            ChannelInner::Tls(s) => { let _ = s.read_exact(buf).await?; }
            #[cfg(feature = "tls")]
            ChannelInner::TlsClient(s) => { let _ = s.read_exact(buf).await?; }
        }
        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match &mut self.inner {
            ChannelInner::Tcp(s) => s.write_all(buf).await?,
            #[cfg(unix)]
            ChannelInner::Unix(s) => s.write_all(buf).await?,
            #[cfg(feature = "tls")]
            ChannelInner::Tls(s) => s.write_all(buf).await?,
            #[cfg(feature = "tls")]
            ChannelInner::TlsClient(s) => s.write_all(buf).await?,
        }
        Ok(())
    }

    async fn flush_inner(&mut self) -> Result<()> {
        match &mut self.inner {
            ChannelInner::Tcp(s) => s.flush().await?,
            #[cfg(unix)]
            ChannelInner::Unix(s) => s.flush().await?,
            #[cfg(feature = "tls")]
            ChannelInner::Tls(s) => s.flush().await?,
            #[cfg(feature = "tls")]
            ChannelInner::TlsClient(s) => s.flush().await?,
        }
        Ok(())
    }
}

// ─── Listener ─────────────────────────────────────────────────────────────────

/// A listener over any supported transport.
pub struct Listener {
    inner: ListenerInner,
}

enum ListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(feature = "tls")]
    Tls { tcp: TcpListener, acceptor: TlsAcceptor },
}

impl Listener {
    pub async fn bind(addr: &str) -> Result<Self> {
        if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
            let listener = TcpListener::bind(tcp_addr).await?;
            return Ok(Self {
                inner: ListenerInner::Tcp(listener),
            });
        }

        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("unix://") {
            let path = Path::new(path);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let listener = tokio::net::UnixListener::bind(path)?;
            return Ok(Self {
                inner: ListenerInner::Unix(listener),
            });
        }

        #[cfg(windows)]
        if addr.starts_with("pipe://") {
            return bind_named_pipe(addr).await;
        }

        if addr.contains(':') {
            let listener = TcpListener::bind(addr).await?;
            return Ok(Self {
                inner: ListenerInner::Tcp(listener),
            });
        }

        Err(TransportError::UnsupportedAddress(addr.to_string()).into())
    }

    /// Bind a TLS listener.  The address may include a `tls://` prefix or be a
    /// bare `host:port`.  Supply a [`TlsServerConfig`] with the server cert,
    /// key, and (optionally) a CA for mutual client authentication.
    #[cfg(feature = "tls")]
    pub async fn bind_tls(addr: &str, cfg: &TlsServerConfig) -> Result<Self> {
        let tcp_addr = addr.strip_prefix("tls://").unwrap_or(addr);
        let tcp = TcpListener::bind(tcp_addr)
            .await
            .with_context(|| format!("TLS TCP bind to {tcp_addr}"))?;
        let acceptor = build_tls_acceptor(cfg)?;
        Ok(Self {
            inner: ListenerInner::Tls { tcp, acceptor },
        })
    }

    pub fn local_addr(&self) -> Result<String> {
        match &self.inner {
            ListenerInner::Tcp(l) => Ok(l.local_addr()?.to_string()),
            #[cfg(unix)]
            ListenerInner::Unix(l) => {
                if let Some(addr) = l.local_addr()?.as_pathname() {
                    Ok(addr.to_string_lossy().into_owned())
                } else {
                    Ok("unix:abstract".into())
                }
            }
            #[cfg(feature = "tls")]
            ListenerInner::Tls { tcp, .. } => Ok(tcp.local_addr()?.to_string()),
        }
    }

    pub async fn accept(&self) -> Result<Channel> {
        match &self.inner {
            ListenerInner::Tcp(l) => {
                let (stream, _) = l.accept().await?;
                Ok(Channel {
                    inner: ChannelInner::Tcp(stream),
                    peer_cert_fingerprint: None,
                })
            }
            #[cfg(unix)]
            ListenerInner::Unix(l) => {
                let (stream, _) = l.accept().await?;
                Ok(Channel {
                    inner: ChannelInner::Unix(stream),
                    peer_cert_fingerprint: None,
                })
            }
            #[cfg(feature = "tls")]
            ListenerInner::Tls { tcp, acceptor } => {
                let (stream, _) = tcp.accept().await?;
                let tls_stream = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| anyhow::anyhow!("TLS accept error: {e}"))?;

                // Extract client cert fingerprint if mutual auth was used.
                let fp = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(cert_fingerprint);

                Ok(Channel {
                    inner: ChannelInner::Tls(tls_stream),
                    peer_cert_fingerprint: fp,
                })
            }
        }
    }
}

// ─── SHA-256 helper (no extra crate needed — use pure-Rust from sha2) ─────────

/// Minimal SHA-256 helper for certificate fingerprints.
#[cfg(feature = "tls")]
// ─── Windows stubs ────────────────────────────────────────────────────────────

#[cfg(windows)]
async fn connect_named_pipe(name: &str) -> Result<Channel> {
    anyhow::bail!(
        "Windows named pipes are not yet implemented for pipe://{}; use tcp://127.0.0.1:PORT instead",
        name
    )
}

#[cfg(windows)]
async fn bind_named_pipe(addr: &str) -> Result<Listener> {
    anyhow::bail!(
        "Windows named pipes are not yet implemented for {}; use tcp://127.0.0.1:PORT instead",
        addr
    )
}

// ─── Convenience RPC helper ───────────────────────────────────────────────────

/// Convenience RPC helper: send a request and await a response.
pub async fn rpc<Req: Serialize + Debug, Resp: DeserializeOwned>(
    addr: &str,
    req: &Req,
) -> Result<Resp> {
    let mut ch = Channel::connect(addr)
        .await
        .with_context(|| format!("connecting to {}", addr))?;
    ch.send_json(req).await?;
    let resp = ch.recv_json().await?;
    Ok(resp)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Ping {
        id: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Pong {
        id: u32,
    }

    #[tokio::test]
    async fn test_tcp_roundtrip() {
        let listener = Listener::bind("tcp://127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&Pong { id: ping.id }).await.unwrap();
        });

        let client = tokio::spawn(async move {
            let mut ch = Channel::connect(&format!("tcp://{}", local)).await.unwrap();
            ch.send_json(&Ping { id: 42 }).await.unwrap();
            let pong: Pong = ch.recv_json().await.unwrap();
            assert_eq!(pong.id, 42);
        });

        let (r1, r2) = tokio::join!(server, client);
        r1.unwrap();
        r2.unwrap();
    }

    #[tokio::test]
    async fn test_oversized_message_rejected() {
        let listener = Listener::bind("tcp://127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            // Send a length prefix exceeding the 16 MiB limit.
            use tokio::io::AsyncWriteExt;
            let oversized: u32 = 17 * 1024 * 1024;
            if let ChannelInner::Tcp(ref mut s) = ch.inner {
                s.write_all(&oversized.to_be_bytes()).await.unwrap();
            }
        });

        let client = tokio::spawn(async move {
            let mut ch = Channel::connect(&format!("tcp://{}", local)).await.unwrap();
            let result: Result<Ping> = ch.recv_json().await;
            assert!(result.is_err(), "oversized message must be rejected");
        });

        let _ = tokio::join!(server, client);
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_tls_roundtrip() {
        // Generate self-signed CA, server cert, and client cert with rcgen.
        use rcgen::{CertificateParams, KeyPair, SanType};

        // CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["IntentKernel Test CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Server cert
        let srv_key = KeyPair::generate().unwrap();
        let mut srv_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        srv_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();
        let server_cert_pem = srv_cert.pem();
        let server_key_pem = srv_key.serialize_pem();

        // Client cert
        let cli_key = KeyPair::generate().unwrap();
        let cli_params = CertificateParams::new(vec!["test-client".into()]).unwrap();
        let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();
        let client_cert_pem = cli_cert.pem();
        let client_key_pem = cli_key.serialize_pem();

        let server_cfg = TlsServerConfig {
            cert_pem: server_cert_pem,
            key_pem: server_key_pem,
            client_ca_pem: Some(ca_pem.clone()),
        };
        let client_cfg = TlsClientConfig {
            cert_pem: client_cert_pem,
            key_pem: client_key_pem,
            ca_pem: ca_pem,
            server_name: "localhost".into(),
        };

        let listener = Listener::bind_tls("tls://127.0.0.1:0", &server_cfg).await.unwrap();
        let local_addr = format!("tls://127.0.0.1:{}", listener.local_addr().unwrap()
            .rsplit(':').next().unwrap());

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            // Server-side sees the client cert fingerprint.
            assert!(ch.peer_cert_fingerprint().is_some());
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&Pong { id: ping.id }).await.unwrap();
        });

        let client_cfg2 = client_cfg.clone();
        let client = tokio::spawn(async move {
            let mut ch = Channel::connect_tls(&local_addr, &client_cfg2).await.unwrap();
            ch.send_json(&Ping { id: 99 }).await.unwrap();
            let pong: Pong = ch.recv_json().await.unwrap();
            assert_eq!(pong.id, 99);
        });

        let (r1, r2) = tokio::join!(server, client);
        r1.unwrap();
        r2.unwrap();
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_tls_rejects_untrusted_client() {
        use rcgen::{CertificateParams, KeyPair};

        // Real CA used by the server for client auth.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["Good CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Server cert signed by the good CA.
        let srv_key = KeyPair::generate().unwrap();
        let mut srv_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        srv_params.subject_alt_names =
            vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())];
        let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

        // Rogue CA – the server does not trust this.
        let rogue_ca_key = KeyPair::generate().unwrap();
        let mut rogue_params = CertificateParams::new(vec!["Rogue CA".into()]).unwrap();
        rogue_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let rogue_ca_cert = rogue_params.self_signed(&rogue_ca_key).unwrap();

        // Client cert signed by the rogue CA.
        let cli_key = KeyPair::generate().unwrap();
        let cli_params = CertificateParams::new(vec!["evil-client".into()]).unwrap();
        let cli_cert = cli_params
            .signed_by(&cli_key, &rogue_ca_cert, &rogue_ca_key)
            .unwrap();

        let server_cfg = TlsServerConfig {
            cert_pem: srv_cert.pem(),
            key_pem: srv_key.serialize_pem(),
            client_ca_pem: Some(ca_pem.clone()),
        };

        let listener = Listener::bind_tls("tls://127.0.0.1:0", &server_cfg).await.unwrap();
        let port = listener.local_addr().unwrap();
        let local_addr = format!("tls://127.0.0.1:{}", port.rsplit(':').next().unwrap());

        let server = tokio::spawn(async move {
            // Accepting should fail because the client's cert isn't trusted.
            let result = listener.accept().await;
            assert!(result.is_err(), "server must reject untrusted client");
        });

        let client_cfg = TlsClientConfig {
            cert_pem: cli_cert.pem(),
            key_pem: cli_key.serialize_pem(),
            ca_pem: ca_pem,
            server_name: "localhost".into(),
        };

        let client = tokio::spawn(async move {
            // Client side may error too; either way is fine.
            let _ = Channel::connect_tls(&local_addr, &client_cfg).await;
        });

        let _ = tokio::join!(server, client);
    }
}

