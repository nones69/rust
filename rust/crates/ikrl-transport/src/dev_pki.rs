//! Development / test certificate provisioning for IntentKernel mTLS.
//!
//! **Prototype / lab-grade only** — generates ephemeral self-signed CA material
//! with `rcgen` for local labs and CI. This is **not** a production PKI:
//! there is no CRL/OCSP, no HSM, and rotation here only rewrites leaf PEMs
//! under a throwaway CA.
//!
//! # Layout written by [`DevPki::materialize`]
//!
//! ```text
//! <dir>/
//!   ca.crt
//!   server.crt  server.key
//!   client.crt  client.key
//!   GENERATION   # monotonic counter after rotate_leaves
//! ```

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tls::{TlsConfig, TlsMode};

/// Ephemeral development PKI (CA + server + client).
///
/// Keeps the CA signing key/cert in memory so [`DevPki::rotate_leaves`] can
/// re-issue leaves that still chain to the same `ca.crt`.
pub struct DevPki {
    pub ca_cert_pem: String,
    ca_cert: Certificate,
    ca_key: KeyPair,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub server_name: String,
    /// How many leaf rotations have been applied (0 = initial generate).
    pub generation: u64,
}

impl DevPki {
    /// Generate a fresh in-memory development CA and leaf certificates.
    pub fn generate() -> Result<Self> {
        let server_name = "localhost".to_string();
        let (ca_cert_pem, ca_cert, ca_key) = make_ca()?;
        let (server_cert_pem, server_key_pem) =
            make_leaf(&ca_cert, &ca_key, "intentkernel-dev-server", &server_name)?;
        let (client_cert_pem, client_key_pem) =
            make_leaf(&ca_cert, &ca_key, "intentkernel-dev-client", "client.local")?;

        Ok(Self {
            ca_cert_pem,
            ca_cert,
            ca_key,
            server_cert_pem,
            server_key_pem,
            client_cert_pem,
            client_key_pem,
            server_name,
            generation: 0,
        })
    }

    /// Re-issue server/client leaves under the **same** in-memory CA.
    ///
    /// Callers should re-`materialize` and rebuild listeners/clients. Old leaf
    /// keys are discarded from this struct; files on disk are only updated when
    /// you call [`materialize`](Self::materialize) again. The CA PEM is unchanged.
    pub fn rotate_leaves(&mut self) -> Result<()> {
        let (server_cert_pem, server_key_pem) = make_leaf(
            &self.ca_cert,
            &self.ca_key,
            "intentkernel-dev-server",
            &self.server_name,
        )?;
        let (client_cert_pem, client_key_pem) = make_leaf(
            &self.ca_cert,
            &self.ca_key,
            "intentkernel-dev-client",
            "client.local",
        )?;

        self.server_cert_pem = server_cert_pem;
        self.server_key_pem = server_key_pem;
        self.client_cert_pem = client_cert_pem;
        self.client_key_pem = client_key_pem;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    /// SHA3-256 hex fingerprint of the current server leaf certificate DER.
    pub fn server_fingerprint(&self) -> Result<String> {
        fingerprint_pem(&self.server_cert_pem)
    }

    /// SHA3-256 hex fingerprint of the current client leaf certificate DER.
    pub fn client_fingerprint(&self) -> Result<String> {
        fingerprint_pem(&self.client_cert_pem)
    }

    /// Write PEM files under `dir` and return paths usable with [`TlsConfig`].
    pub fn materialize(&self, dir: &Path) -> Result<DevPkiPaths> {
        fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let write = |name: &str, data: &str| -> Result<PathBuf> {
            let p = dir.join(name);
            fs::write(&p, data).with_context(|| format!("write {}", p.display()))?;
            Ok(p)
        };
        write("GENERATION", &format!("{}\n", self.generation))?;
        Ok(DevPkiPaths {
            ca_cert: write("ca.crt", &self.ca_cert_pem)?,
            server_cert: write("server.crt", &self.server_cert_pem)?,
            server_key: write("server.key", &self.server_key_pem)?,
            client_cert: write("client.crt", &self.client_cert_pem)?,
            client_key: write("client.key", &self.client_key_pem)?,
            server_name: self.server_name.clone(),
            generation: self.generation,
            server_fingerprint: self.server_fingerprint()?,
            client_fingerprint: self.client_fingerprint()?,
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
    pub generation: u64,
    pub server_fingerprint: String,
    pub client_fingerprint: String,
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

    /// Load generation counter previously written by [`DevPki::materialize`].
    pub fn read_generation(dir: &Path) -> Result<u64> {
        let raw = fs::read_to_string(dir.join("GENERATION"))
            .with_context(|| format!("read GENERATION in {}", dir.display()))?;
        raw.trim().parse().context("parse GENERATION")
    }
}

fn make_ca() -> Result<(String, Certificate, KeyPair)> {
    let ca_key = KeyPair::generate().context("generate CA key")?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "IntentKernel Dev CA");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, format!("dev-{stamp}"));
    let ca_cert = ca_params.self_signed(&ca_key).context("self-sign CA")?;
    Ok((ca_cert.pem(), ca_cert, ca_key))
}

fn make_leaf(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    cn: &str,
    dns: &str,
) -> Result<(String, String)> {
    let key = KeyPair::generate().with_context(|| format!("generate key for {cn}"))?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = vec![SanType::DnsName(dns.try_into().unwrap())];
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .with_context(|| format!("sign leaf {cn}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn fingerprint_pem(pem: &str) -> Result<String> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse cert PEM for fingerprint")?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no certificates in PEM"))?;
    Ok(hex::encode(Sha3_256::digest(leaf.as_ref())))
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
        assert_eq!(paths.generation, 0);

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config())
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");
        let expected_server_fp = paths.server_fingerprint.clone();
        let expected_client_fp = paths.client_fingerprint.clone();

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            assert!(ch.peer.mtls_verified);
            ch.require_peer_fingerprint(&expected_client_fp).unwrap();
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&ping).await.unwrap();
        });

        let client_cfg = paths.client_mtls_config();
        let client = tokio::spawn(async move {
            let mut ch = SecureChannel::connect(&addr, &client_cfg).await.unwrap();
            assert!(ch.peer_cert_fingerprint().is_some());
            ch.require_peer_fingerprint(&expected_server_fp).unwrap();
            ch.send_json(&Ping { n: 7 }).await.unwrap();
            let pong: Ping = ch.recv_json().await.unwrap();
            assert_eq!(pong.n, 7);
        });

        let (a, b) = tokio::join!(server, client);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn fingerprint_pin_rejects_mismatch() {
        let dir = tempdir().unwrap();
        let paths = DevPki::generate().unwrap().materialize(dir.path()).unwrap();
        let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config())
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");

        let server = tokio::spawn(async move {
            let ch = listener.accept().await.unwrap();
            let err = ch
                .require_peer_fingerprint("deadbeef")
                .expect_err("pin must fail");
            let msg = err.to_string();
            assert!(msg.contains("mismatch") || msg.contains("fingerprint"));
        });

        let client_cfg = paths.client_mtls_config();
        let client = tokio::spawn(async move {
            let _ch = SecureChannel::connect(&addr, &client_cfg).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (a, b) = tokio::join!(server, client);
        a.unwrap();
        b.unwrap();
    }

    #[tokio::test]
    async fn rotate_leaves_still_chains_to_same_ca() {
        let dir = tempdir().unwrap();
        let mut pki = DevPki::generate().unwrap();
        let ca_before = pki.ca_cert_pem.clone();
        pki.rotate_leaves().unwrap();
        assert_eq!(pki.generation, 1);
        assert_eq!(pki.ca_cert_pem, ca_before);
        let paths = pki.materialize(dir.path()).unwrap();
        assert_eq!(DevPkiPaths::read_generation(dir.path()).unwrap(), 1);

        let listener = SecureListener::bind("tcp://127.0.0.1:0", &paths.server_mtls_config())
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        let addr = format!("tcp://{local}");
        let expected_server_fp = paths.server_fingerprint.clone();

        let server = tokio::spawn(async move {
            let mut ch = listener.accept().await.unwrap();
            assert!(ch.peer.mtls_verified);
            let ping: Ping = ch.recv_json().await.unwrap();
            ch.send_json(&ping).await.unwrap();
        });

        let client_cfg = paths.client_mtls_config();
        let client = tokio::spawn(async move {
            let mut ch = SecureChannel::connect(&addr, &client_cfg).await.unwrap();
            ch.require_peer_fingerprint(&expected_server_fp).unwrap();
            ch.send_json(&Ping { n: 9 }).await.unwrap();
            let pong: Ping = ch.recv_json().await.unwrap();
            assert_eq!(pong.n, 9);
        });

        let (a, b) = tokio::join!(server, client);
        a.unwrap();
        b.unwrap();
    }

    #[test]
    fn rotate_leaves_bumps_generation_and_fingerprints() {
        let mut pki = DevPki::generate().unwrap();
        let fp0 = pki.server_fingerprint().unwrap();
        pki.rotate_leaves().unwrap();
        assert_eq!(pki.generation, 1);
        let fp1 = pki.server_fingerprint().unwrap();
        assert_ne!(fp0, fp1);
        let dir = tempdir().unwrap();
        let paths = pki.materialize(dir.path()).unwrap();
        assert_eq!(DevPkiPaths::read_generation(dir.path()).unwrap(), 1);
        assert_eq!(paths.server_fingerprint, fp1);
    }
}
