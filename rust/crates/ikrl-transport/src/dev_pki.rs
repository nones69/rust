//! Development / test certificate provisioning for IntentKernel mTLS.
//!
//! **Prototype only** — this generates ephemeral self-signed CA material with
//! `rcgen` for local labs and CI. It is not a production PKI, does not rotate
//! keys, and must not be treated as a security boundary claim.
//!
//! # Layout written by [`DevPki::materialize`]
//!
//! ```text
//! <dir>/
//!   ca.crt
//!   server.crt  server.key
//!   client.crt  client.key
//! ```

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::fs;
use std::path::{Path, PathBuf};

use crate::tls::{TlsConfig, TlsMode};

/// Ephemeral development PKI (CA + server + client).
pub struct DevPki {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub server_name: String,
}

impl DevPki {
    /// Generate a fresh in-memory development CA and leaf certificates.
    pub fn generate() -> Result<Self> {
        let server_name = "localhost".to_string();

        let ca_key = KeyPair::generate().context("generate CA key")?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "IntentKernel Dev CA");
        let ca_cert = ca_params.self_signed(&ca_key).context("self-sign CA")?;

        let server_key = KeyPair::generate().context("generate server key")?;
        let mut s_params = CertificateParams::default();
        s_params
            .distinguished_name
            .push(DnType::CommonName, "intentkernel-dev-server");
        s_params.subject_alt_names =
            vec![SanType::DnsName(server_name.as_str().try_into().unwrap())];
        let server_cert = s_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .context("sign server cert")?;

        let client_key = KeyPair::generate().context("generate client key")?;
        let mut c_params = CertificateParams::default();
        c_params
            .distinguished_name
            .push(DnType::CommonName, "intentkernel-dev-client");
        c_params.subject_alt_names = vec![SanType::DnsName("client.local".try_into().unwrap())];
        let client_cert = c_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .context("sign client cert")?;

        Ok(Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            server_name,
        })
    }

    /// Write PEM files under `dir` and return paths usable with [`TlsConfig`].
    pub fn materialize(&self, dir: &Path) -> Result<DevPkiPaths> {
        fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let write = |name: &str, data: &str| -> Result<PathBuf> {
            let p = dir.join(name);
            fs::write(&p, data).with_context(|| format!("write {}", p.display()))?;
            Ok(p)
        };
        Ok(DevPkiPaths {
            ca_cert: write("ca.crt", &self.ca_cert_pem)?,
            server_cert: write("server.crt", &self.server_cert_pem)?,
            server_key: write("server.key", &self.server_key_pem)?,
            client_cert: write("client.crt", &self.client_cert_pem)?,
            client_key: write("client.key", &self.client_key_pem)?,
            server_name: self.server_name.clone(),
        })
    }
}

/// On-disk paths produced by [`DevPki::materialize`].
#[derive(Debug, Clone)]
pub struct DevPkiPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub server_name: String,
}

impl DevPkiPaths {
    pub fn server_mtls_config(&self) -> TlsConfig {
        TlsConfig {
            cert_pem: self.server_cert.clone(),
            key_pem: self.server_key.clone(),
            ca_cert_pem: Some(self.ca_cert.clone()),
            mode: TlsMode::Mutual,
            server_name: None,
        }
    }

    pub fn client_mtls_config(&self) -> TlsConfig {
        TlsConfig {
            cert_pem: self.client_cert.clone(),
            key_pem: self.client_key.clone(),
            ca_cert_pem: Some(self.ca_cert.clone()),
            mode: TlsMode::Mutual,
            server_name: Some(self.server_name.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecureChannel, SecureListener};
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Ping {
        n: u32,
    }

    #[tokio::test]
    async fn materialize_and_mtls_roundtrip() {
        let dir = tempdir().unwrap();
        let paths = DevPki::generate().unwrap().materialize(dir.path()).unwrap();
        assert!(paths.ca_cert.exists());
        assert!(paths.server_key.exists());

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config())
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            assert!(ch.peer.mtls_verified);
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&ping).await.unwrap();
        });

        let client_cfg = paths.client_mtls_config();
        let client = tokio::spawn(async move {
            let mut ch = SecureChannel::connect(&addr, &client_cfg).await.unwrap();
            ch.send_json(&Ping { n: 7 }).await.unwrap();
            let pong: Ping = ch.recv_json().await.unwrap();
            assert_eq!(pong.n, 7);
        });

        let (a, b) = tokio::join!(server, client);
        a.unwrap();
        b.unwrap();
    }
}
