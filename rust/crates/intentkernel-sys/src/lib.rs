//! Minimal JSON-over-IPC client for IntentKernel (Unix domain socket on Unix).
//! This is a small, test-friendly client. Production clients should add retries, timeouts, and stronger error handling.

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

pub mod syscall_types_impl {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum IkSyscall {
        IkOpen {
            path: String,
            mode: OpenMode,
        },
        IkRead {
            handle: Uuid,
            len: u64,
        },
        IkWrite {
            handle: Uuid,
            data: Vec<u8>,
        },
        IkClose {
            handle: Uuid,
        },
        IkPolicyExplain {
            syscall: Box<IkSyscall>,
        },
        IkAiInfer {
            prompt: String,
            max_tokens: Option<u64>,
        },
        IkNetRequest {
            method: HttpMethod,
            url: String,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum OpenMode {
        Read,
        Write,
        ReadWrite,
        Create,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum HttpMethod {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH,
    }
}

pub mod types {
    use super::syscall_types_impl;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    pub type CapabilityTokenId = Uuid;
    pub type HandleId = Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IkCallEnvelope {
        pub token_id: CapabilityTokenId,
        pub call: syscall_types_impl::IkSyscall,
        pub call_id: Uuid,
        pub timestamp_ms: u128,
    }
}

#[derive(thiserror::Error, Debug)]
pub enum IkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unexpected response")]
    UnexpectedResponse,
}

pub struct IkClient {
    #[cfg(unix)]
    socket_path: String,
    #[cfg(unix)]
    stream: Option<UnixStream>,
}

impl IkClient {
    pub fn new_unix(socket_path: impl Into<String>) -> Self {
        #[cfg(unix)]
        {
            Self {
                socket_path: socket_path.into(),
                stream: None,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            Self {}
        }
    }

    fn ensure_connected(&mut self) -> Result<(), IkError> {
        #[cfg(unix)]
        {
            if self.stream.is_none() {
                let s = UnixStream::connect(&self.socket_path)?;
                self.stream = Some(s);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(IkError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unsupported platform",
            )))
        }
    }

    pub fn send_envelope(
        &mut self,
        envelope: &types::IkCallEnvelope,
    ) -> Result<serde_json::Value, IkError> {
        self.ensure_connected()?;
        #[cfg(unix)]
        {
            let stream = self.stream.as_mut().unwrap();
            let req = serde_json::to_vec(envelope)?;
            let len = (req.len() as u32).to_le_bytes();
            stream.write_all(&len)?;
            stream.write_all(&req)?;
            stream.flush()?;

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf)?;
            let resp_len = u32::from_le_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf)?;
            let v: serde_json::Value = serde_json::from_slice(&resp_buf)?;
            Ok(v)
        }
        #[cfg(not(unix))]
        {
            Err(IkError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unsupported platform",
            )))
        }
    }

    pub fn open(
        &mut self,
        token_id: Uuid,
        path: &str,
        mode: syscall_types_impl::OpenMode,
    ) -> Result<serde_json::Value, IkError> {
        let envelope = types::IkCallEnvelope {
            token_id,
            call: syscall_types_impl::IkSyscall::IkOpen {
                path: path.to_string(),
                mode,
            },
            call_id: Uuid::new_v4(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };
        self.send_envelope(&envelope)
    }

    pub fn policy_explain(
        &mut self,
        token_id: Uuid,
        syscall: syscall_types_impl::IkSyscall,
    ) -> Result<serde_json::Value, IkError> {
        let envelope = types::IkCallEnvelope {
            token_id,
            call: syscall_types_impl::IkSyscall::IkPolicyExplain {
                syscall: Box::new(syscall),
            },
            call_id: Uuid::new_v4(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };
        self.send_envelope(&envelope)
    }
}
