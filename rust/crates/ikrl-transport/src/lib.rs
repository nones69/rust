//! # ikrl-transport
//!
//! Cross-platform IPC transport for the IntentKernel daemon stack.
//!
//! | Platform | Current transport support |
//! |----------|---------------------------|
//! | Linux    | Unix domain socket / TCP  |
//! | macOS    | Unix domain socket / TCP  |
//! | Windows  | TCP loopback today        |
//! | `pipe://`| Parsed on Windows, but fails fast as unimplemented |
//!
//! All transports carry length-prefixed JSON messages so every daemon can
//! speak the same protocol regardless of the underlying socket type.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unsupported address: {0}")]
    UnsupportedAddress(String),
}

/// A connection over any supported transport.
pub struct Channel {
    inner: ChannelInner,
}

enum ChannelInner {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl Channel {
    pub async fn connect(addr: &str) -> Result<Self> {
        if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
            let stream = TcpStream::connect(tcp_addr).await?;
            return Ok(Self {
                inner: ChannelInner::Tcp(stream),
            });
        }

        #[cfg(unix)]
        if let Some(path) = addr.strip_prefix("unix://") {
            let stream = tokio::net::UnixStream::connect(path).await?;
            return Ok(Self {
                inner: ChannelInner::Unix(stream),
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
            });
        }

        Err(TransportError::UnsupportedAddress(addr.to_string()).into())
    }

    pub async fn send_json(&mut self, msg: &impl Serialize) -> Result<()> {
        let bytes =
            serde_json::to_vec(msg).map_err(|e| TransportError::Serialization(e.to_string()))?;
        let len = (bytes.len() as u32).to_be_bytes();
        match &mut self.inner {
            ChannelInner::Tcp(s) => {
                s.write_all(&len).await?;
                s.write_all(&bytes).await?;
                s.flush().await?;
            }
            #[cfg(unix)]
            ChannelInner::Unix(s) => {
                s.write_all(&len).await?;
                s.write_all(&bytes).await?;
                s.flush().await?;
            }
        }
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
            ChannelInner::Tcp(s) => {
                let _ = s.read_exact(buf).await?;
            }
            #[cfg(unix)]
            ChannelInner::Unix(s) => {
                let _ = s.read_exact(buf).await?;
            }
        }
        Ok(())
    }
}

/// A listener over any supported transport.
pub struct Listener {
    inner: ListenerInner,
}

enum ListenerInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
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
        }
    }

    pub async fn accept(&self) -> Result<Channel> {
        match &self.inner {
            ListenerInner::Tcp(l) => {
                let (stream, _) = l.accept().await?;
                Ok(Channel {
                    inner: ChannelInner::Tcp(stream),
                })
            }
            #[cfg(unix)]
            ListenerInner::Unix(l) => {
                let (stream, _) = l.accept().await?;
                Ok(Channel {
                    inner: ChannelInner::Unix(stream),
                })
            }
        }
    }
}

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
}
