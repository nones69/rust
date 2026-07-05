//! mTLS-backed secure channels for the IKRL IPC stack.
//!
//! Implements "Mode A" (TLS-over-TCP/UDS) and "Mode C" (mutual TLS) from the
//! IntentKernel IPC security design.  Both TCP and Unix domain socket transports
//! share the same certificate model so local and remote IPC use identical
//! handshake logic, making it straightforward to promote local IPC to remote
//! IPC later without changes to the daemon code.
//!
//! # Quick start
//!
//! 1. Generate or obtain PEM-encoded cert/key pairs for the server and clients.
//! 2. Build a [`TlsConfig`] pointing at those files.
//! 3. Use [`SecureListener::bind`] on the server side and
//!    [`SecureChannel::connect`] on the client side.
//! 4. Inspect [`SecureChannel::peer`] for the authenticated peer identity.

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use serde::{de::DeserializeOwned, Serialize};
use sha3::{Digest, Sha3_256};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;

/// Maximum allowed size (in bytes) for a single framed IPC message.
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[cfg(unix)]
use super::peer_creds;

use super::TransportError;

// ───────────────────────────── Configuration ─────────────────────────────

/// Whether peers must present a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Server authenticates to client only (server presents cert, client does
    /// not).
    ServerOnly,
    /// Both endpoints authenticate with certificates (mutual TLS).
    Mutual,
}

/// TLS configuration for a [`SecureListener`] or [`SecureChannel`].
///
/// Fields are paths to PEM files that are read once at bind/connect time.
/// To rotate certificates, create a new listener/channel with updated paths.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain for **this** endpoint.
    pub cert_pem: PathBuf,
    /// Path to the PEM-encoded private key for **this** endpoint.
    pub key_pem: PathBuf,
    /// Path to the PEM-encoded CA certificate used to verify the **peer's**
    /// certificate chain.  Required for all modes when using a private CA.
    pub ca_cert_pem: Option<PathBuf>,
    /// Authentication mode.
    pub mode: TlsMode,
    /// Server Name Indication string (e.g. `"intentkernel.local"`) sent by
    /// the client during handshake and checked against the server certificate.
    /// Required for client connections.
    pub server_name: Option<String>,
}

// ───────────────────────────── Peer identity ──────────────────────────────

/// Authenticated peer identity extracted after a successful TLS handshake.
///
/// Populated on both sides of the channel:
/// - `mtls_verified`/`cert_fingerprint` come from the TLS layer.
/// - `pid`/`uid` come from OS-level Unix peer credentials (Unix only, server
///   side, Unix domain socket transport).
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity {
    /// `true` when the peer presented a valid certificate chain under the
    /// configured CA (only meaningful when [`TlsMode::Mutual`] is used).
    pub mtls_verified: bool,
    /// SHA3-256 fingerprint (lowercase hex) of the peer's leaf certificate,
    /// if one was presented.  Useful for certificate pinning.
    pub cert_fingerprint: Option<String>,
    /// OS-level peer process ID (Unix domain socket, server side only).
    pub pid: Option<u32>,
    /// OS-level peer user ID (Unix domain socket, server side only).
    pub uid: Option<u32>,
}

// ─────────────────────────────── Helpers ──────────────────────────────────

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open cert file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("parse certificates from {}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open key file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key from {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))
}

fn load_ca_store(path: &Path) -> Result<RootCertStore> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).context("add CA cert to root store")?;
    }
    Ok(store)
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let hash = Sha3_256::digest(cert.as_ref());
    hex::encode(hash)
}

fn build_server_config(config: &TlsConfig) -> Result<rustls::ServerConfig> {
    let certs = load_certs(&config.cert_pem)?;
    let key = load_key(&config.key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ServerConfig::builder_with_provider(provider);
    let builder = builder.with_safe_default_protocol_versions()?;

    let cfg = if config.mode == TlsMode::Mutual {
        let ca_path = config
            .ca_cert_pem
            .as_deref()
            .context("ca_cert_pem is required for TlsMode::Mutual")?;
        let root_store = load_ca_store(ca_path)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("build client cert verifier")?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };

    cfg.with_single_cert(certs, key)
        .context("configure server certificate")
}

fn build_client_config(config: &TlsConfig) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider);
    let builder = builder.with_safe_default_protocol_versions()?;

    let root_store = if let Some(ca_path) = &config.ca_cert_pem {
        load_ca_store(ca_path)?
    } else {
        bail!("ca_cert_pem is required for client TLS connections")
    };

    let cfg = builder.with_root_certificates(root_store);

    if config.mode == TlsMode::Mutual {
        let certs = load_certs(&config.cert_pem)?;
        let key = load_key(&config.key_pem)?;
        cfg.with_client_auth_cert(certs, key)
            .context("configure client certificate")
    } else {
        Ok(cfg.with_no_client_auth())
    }
}

fn extract_server_peer_identity<IO>(stream: &tokio_rustls::server::TlsStream<IO>) -> PeerIdentity {
    let (_, conn) = stream.get_ref();
    let certs = conn.peer_certificates();
    let mtls_verified = certs.map_or(false, |c| !c.is_empty());
    let cert_fingerprint = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(fingerprint);
    PeerIdentity {
        mtls_verified,
        cert_fingerprint,
        pid: None,
        uid: None,
    }
}

// ─────────────────────────────── Channels ─────────────────────────────────

/// A TLS-encrypted, optionally mutually-authenticated channel.
///
/// Implements the same length-prefixed JSON framing as the plain [`Channel`].
///
/// [`Channel`]: super::Channel
pub struct SecureChannel {
    inner: SecureChannelInner,
    /// Identity of the remote peer, populated after the TLS handshake.
    pub peer: PeerIdentity,
}

enum SecureChannelInner {
    TcpServer(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    TcpClient(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    #[cfg(unix)]
    UnixServer(tokio_rustls::server::TlsStream<tokio::net::UnixStream>),
    #[cfg(unix)]
    UnixClient(tokio_rustls::client::TlsStream<tokio::net::UnixStream>),
}

impl AsyncRead for SecureChannel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().inner {
            SecureChannelInner::TcpServer(s) => Pin::new(s).poll_read(cx, buf),
            SecureChannelInner::TcpClient(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            SecureChannelInner::UnixServer(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            SecureChannelInner::UnixClient(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SecureChannel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().inner {
            SecureChannelInner::TcpServer(s) => Pin::new(s).poll_write(cx, buf),
            SecureChannelInner::TcpClient(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            SecureChannelInner::UnixServer(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            SecureChannelInner::UnixClient(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().inner {
            SecureChannelInner::TcpServer(s) => Pin::new(s).poll_flush(cx),
            SecureChannelInner::TcpClient(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            SecureChannelInner::UnixServer(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            SecureChannelInner::UnixClient(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().inner {
            SecureChannelInner::TcpServer(s) => Pin::new(s).poll_shutdown(cx),
            SecureChannelInner::TcpClient(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            SecureChannelInner::UnixServer(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            SecureChannelInner::UnixClient(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl SecureChannel {
    /// Connect to a secure listener at `addr` using the provided TLS
    /// configuration.
    ///
    /// `addr` uses the same scheme syntax as the plain [`Channel`]:
    /// - `tcp://host:port`
    /// - `unix:///path/to/socket` (Unix only)
    pub async fn connect(addr: &str, config: &TlsConfig) -> Result<Self> {
        let sni = config
            .server_name
            .as_deref()
            .context("TlsConfig::server_name is required for client connections")?;
        let server_name: ServerName<'static> =
            ServerName::try_from(sni.to_string()).context("invalid server name")?;

        let client_config = build_client_config(config)?;
        let connector = TlsConnector::from(Arc::new(client_config));

        if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
            debug!("secure connect tcp://{}", tcp_addr);
            let stream = tokio::net::TcpStream::connect(tcp_addr)
                .await
                .with_context(|| format!("TCP connect to {}", tcp_addr))?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .context("TLS client handshake")?;
            return Ok(SecureChannel {
                inner: SecureChannelInner::TcpClient(tls_stream),
                peer: PeerIdentity::default(),
            });
        }

        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("unix://") {
            debug!("secure connect unix://{}", path);
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .with_context(|| format!("Unix connect to {}", path))?;
            let creds = peer_creds::get_unix_peer_creds(&stream);
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .context("TLS client handshake")?;
            let peer = PeerIdentity {
                pid: creds.pid,
                uid: creds.uid,
                ..Default::default()
            };
            return Ok(SecureChannel {
                inner: SecureChannelInner::UnixClient(tls_stream),
                peer,
            });
        }

        bail!(
            "{}",
            TransportError::UnsupportedAddress(addr.to_string())
        )
    }

    /// Send a JSON-serializable value over this secure channel.
    ///
    /// Uses the same 4-byte big-endian length prefix as the plain [`Channel`].
    pub async fn send_json(&mut self, msg: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        let len = (bytes.len() as u32).to_be_bytes();
        self.write_all(&len).await?;
        self.write_all(&bytes).await?;
        self.flush().await?;
        Ok(())
    }

    /// Receive and deserialize a JSON value from this secure channel.
    pub async fn recv_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_LEN {
            bail!(
                "{}",
                TransportError::Serialization(format!("message too large: {} bytes", len))
            );
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf)
            .map_err(|e| TransportError::Serialization(e.to_string()).into())
    }
}

// ─────────────────────────────── Listener ─────────────────────────────────

/// A TLS listener that accepts [`SecureChannel`] connections.
pub struct SecureListener {
    inner: SecureListenerInner,
    acceptor: TlsAcceptor,
    mode: TlsMode,
}

enum SecureListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl SecureListener {
    /// Bind a secure listener to `addr`.
    ///
    /// `addr` uses the same scheme syntax as the plain [`Listener`]:
    /// - `tcp://host:port`
    /// - `unix:///path/to/socket` (Unix only)
    ///
    /// The socket file is removed if it already exists.
    ///
    /// [`Listener`]: super::Listener
    pub async fn bind(addr: &str, config: &TlsConfig) -> Result<Self> {
        let server_config = build_server_config(config)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mode = config.mode;

        if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
            debug!("secure listen tcp://{}", tcp_addr);
            let listener = TcpListener::bind(tcp_addr)
                .await
                .with_context(|| format!("TCP bind to {}", tcp_addr))?;
            return Ok(SecureListener {
                inner: SecureListenerInner::Tcp(listener),
                acceptor,
                mode,
            });
        }

        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("unix://") {
            use std::path::Path;
            debug!("secure listen unix://{}", path);
            let path = Path::new(path);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            let listener = tokio::net::UnixListener::bind(path)?;
            return Ok(SecureListener {
                inner: SecureListenerInner::Unix(listener),
                acceptor,
                mode,
            });
        }

        bail!(
            "{}",
            TransportError::UnsupportedAddress(addr.to_string())
        )
    }

    /// Return the local address this listener is bound to.
    pub fn local_addr(&self) -> Result<String> {
        match &self.inner {
            SecureListenerInner::Tcp(l) => Ok(l.local_addr()?.to_string()),
            #[cfg(unix)]
            SecureListenerInner::Unix(l) => {
                if let Some(addr) = l.local_addr()?.as_pathname() {
                    Ok(addr.to_string_lossy().into_owned())
                } else {
                    Ok("unix:abstract".into())
                }
            }
        }
    }

    /// Accept the next inbound connection.
    ///
    /// Returns a [`SecureChannel`] whose `peer` field is populated with the
    /// authenticated identity of the connecting client.  The TLS handshake is
    /// completed before this method returns; a handshake error is surfaced as
    /// an `Err`.
    pub async fn accept(&self) -> Result<SecureChannel> {
        match &self.inner {
            SecureListenerInner::Tcp(listener) => {
                let (stream, peer_addr) = listener.accept().await?;
                debug!("TLS accept from {}", peer_addr);
                let tls_stream = self
                    .acceptor
                    .accept(stream)
                    .await
                    .context("TLS server handshake")?;
                let peer = extract_server_peer_identity(&tls_stream);
                Ok(SecureChannel {
                    inner: SecureChannelInner::TcpServer(tls_stream),
                    peer,
                })
            }
            #[cfg(unix)]
            SecureListenerInner::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                let creds = peer_creds::get_unix_peer_creds(&stream);
                let tls_stream = self
                    .acceptor
                    .accept(stream)
                    .await
                    .context("TLS server handshake")?;
                let mut peer = extract_server_peer_identity(&tls_stream);
                peer.pid = creds.pid;
                peer.uid = creds.uid;
                Ok(SecureChannel {
                    inner: SecureChannelInner::UnixServer(tls_stream),
                    peer,
                })
            }
        }
    }

    /// Return the configured [`TlsMode`] for this listener.
    pub fn mode(&self) -> TlsMode {
        self.mode
    }
}

// ───────────────────────── Tests ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, BasicConstraints, KeyPair, SanType};
    use serde::{Deserialize, Serialize};
    use tempfile::NamedTempFile;
    use std::io::Write;

    // ── cert generation helpers ──────────────────────────────────────────

    struct TestPki {
        ca_cert_pem: NamedTempFile,
        server_cert_pem: NamedTempFile,
        server_key_pem: NamedTempFile,
        client_cert_pem: NamedTempFile,
        client_key_pem: NamedTempFile,
    }

    fn gen_pki() -> TestPki {
        // CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Server cert
        let server_key = KeyPair::generate().unwrap();
        let mut s_params = CertificateParams::default();
        s_params.distinguished_name.push(DnType::CommonName, "test-server");
        s_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().unwrap()),
        ];
        let server_cert = s_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // Client cert
        let client_key = KeyPair::generate().unwrap();
        let mut c_params = CertificateParams::default();
        c_params.distinguished_name.push(DnType::CommonName, "test-client");
        c_params.subject_alt_names = vec![
            SanType::DnsName("client.local".try_into().unwrap()),
        ];
        let client_cert = c_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        let write_tmp = |pem: &str| -> NamedTempFile {
            let mut f = NamedTempFile::new().unwrap();
            f.write_all(pem.as_bytes()).unwrap();
            f
        };

        TestPki {
            ca_cert_pem: write_tmp(&ca_cert.pem()),
            server_cert_pem: write_tmp(&server_cert.pem()),
            server_key_pem: write_tmp(&server_key.serialize_pem()),
            client_cert_pem: write_tmp(&client_cert.pem()),
            client_key_pem: write_tmp(&client_key.serialize_pem()),
        }
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Ping { id: u32 }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Pong { id: u32 }

    // ── mTLS TCP round-trip ───────────────────────────────────────────────

    #[tokio::test]
    async fn mtls_tcp_roundtrip() {
        let pki = gen_pki();

        let server_config = TlsConfig {
            cert_pem: pki.server_cert_pem.path().to_owned(),
            key_pem: pki.server_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::Mutual,
            server_name: None,
        };

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &server_config)
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{}", local);

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            assert!(ch.peer.mtls_verified);
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&Pong { id: ping.id }).await.unwrap();
        });

        let client_config = TlsConfig {
            cert_pem: pki.client_cert_pem.path().to_owned(),
            key_pem: pki.client_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::Mutual,
            server_name: Some("localhost".to_string()),
        };

        let client = tokio::spawn(async move {
            let mut ch = SecureChannel::connect(&addr, &client_config).await.unwrap();
            ch.send_json(&Ping { id: 99 }).await.unwrap();
            let pong: Pong = ch.recv_json().await.unwrap();
            assert_eq!(pong.id, 99);
        });

        let (r1, r2) = tokio::join!(server, client);
        r1.unwrap();
        r2.unwrap();
    }

    // ── Unauthenticated client rejected in mTLS mode ──────────────────────

    #[tokio::test]
    async fn mtls_rejects_client_without_cert() {
        let pki = gen_pki();

        let server_config = TlsConfig {
            cert_pem: pki.server_cert_pem.path().to_owned(),
            key_pem: pki.server_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::Mutual,
            server_name: None,
        };

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &server_config)
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{}", local);

        // Server: attempt accept (will fail because client sends no cert).
        let server = tokio::spawn(async move {
            let result = listener.accept().await;
            // Handshake should fail.
            assert!(result.is_err(), "expected TLS handshake error");
        });

        // Client: server-only config (no client cert) against an mTLS server.
        let client_config = TlsConfig {
            // cert/key are irrelevant here; we never send them.
            cert_pem: pki.client_cert_pem.path().to_owned(),
            key_pem: pki.client_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::ServerOnly, // <-- no client cert presented
            server_name: Some("localhost".to_string()),
        };
        let client = tokio::spawn(async move {
            // Connection may succeed at TCP level but TLS should fail.
            let _ = SecureChannel::connect(&addr, &client_config).await;
        });

        let (r1, r2) = tokio::join!(server, client);
        r1.unwrap();
        r2.unwrap();
    }

    // ── Server-only TLS (no client cert required) ─────────────────────────

    #[tokio::test]
    async fn server_only_tls_roundtrip() {
        let pki = gen_pki();

        let server_config = TlsConfig {
            cert_pem: pki.server_cert_pem.path().to_owned(),
            key_pem: pki.server_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::ServerOnly,
            server_name: None,
        };

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &server_config)
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{}", local);

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            // No client cert — mtls_verified should be false.
            assert!(!ch.peer.mtls_verified);
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&Pong { id: ping.id }).await.unwrap();
        });

        let client_config = TlsConfig {
            cert_pem: pki.client_cert_pem.path().to_owned(),
            key_pem: pki.client_key_pem.path().to_owned(),
            ca_cert_pem: Some(pki.ca_cert_pem.path().to_owned()),
            mode: TlsMode::ServerOnly,
            server_name: Some("localhost".to_string()),
        };

        let client = tokio::spawn(async move {
            let mut ch = SecureChannel::connect(&addr, &client_config).await.unwrap();
            ch.send_json(&Ping { id: 7 }).await.unwrap();
            let pong: Pong = ch.recv_json().await.unwrap();
            assert_eq!(pong.id, 7);
        });

        let (r1, r2) = tokio::join!(server, client);
        r1.unwrap();
        r2.unwrap();
    }
}
