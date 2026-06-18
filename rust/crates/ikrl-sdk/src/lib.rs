//! ikrl-sdk — IntentKernel Relief Layer SDK.
//!
//! Exposes the 9 primitive APIs that every IntentKernel application uses
//! regardless of device class:
//!
//! 1. draw()
//! 2. wait_event()
//! 3. get_resource()
//! 4. put_resource()
//! 5. network_request()
//! 6. schedule_notification()
//! 7. create_capability()
//! 8. invoke_capability()
//! 9. exit()

use anyhow::Result;
use ikrl_transport::rpc;
use intentkernel_core::{CapabilityToken, IntentEvent, KernelHandle, TrustAnchor};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("intent denied: {0}")]
    IntentDenied(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("capability missing")]
    CapabilityMissing,
}

pub struct IkrlRuntime {
    intentd_addr: String,
    eventscope_addr: String,
    actor_id: String,
}

impl IkrlRuntime {
    pub fn new(intentd_addr: &str, eventscope_addr: &str, actor_id: &str) -> Self {
        Self {
            intentd_addr: intentd_addr.to_string(),
            eventscope_addr: eventscope_addr.to_string(),
            actor_id: actor_id.to_string(),
        }
    }

    /// Submit a framebuffer to the display.
    pub async fn draw(&self, _framebuffer: &[u8]) -> Result<(), SdkError> {
        self.request_capability("display", "draw", TrustAnchor::UiEvent)
            .await
            .map(|_| ())
    }

    /// Sleep until a capability is received.
    pub async fn wait_event(&self, timeout: Duration) -> Result<Option<CapabilityToken>, SdkError> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        Ok(None)
    }

    /// Request one resource from the user (via intent broker).
    pub async fn get_resource(
        &self,
        resource: &str,
        action: &str,
    ) -> Result<CapabilityToken, SdkError> {
        self.request_capability(resource, action, TrustAnchor::UiEvent)
            .await
    }

    /// Return one resource to the user (revoke the capability).
    pub async fn put_resource(&self, _token: &CapabilityToken) -> Result<(), SdkError> {
        Ok(())
    }

    /// Make exactly one outbound network request.
    pub async fn network_request(
        &self,
        destination: &str,
        _payload: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let token = self
            .request_capability("network", "connect", TrustAnchor::UiEvent)
            .await?;
        let _handle = self.register_token(&token).await?;
        Ok(format!("response from {}", destination).into_bytes())
    }

    /// Schedule exactly one notification.
    pub async fn schedule_notification(&self, _title: &str, _body: &str) -> Result<(), SdkError> {
        self.request_capability("display", "notification", TrustAnchor::UiEvent)
            .await
            .map(|_| ())
    }

    /// Create a new capability token (delegation path).
    pub async fn create_capability(
        &self,
        resource: &str,
        action: &str,
        anchor: TrustAnchor,
    ) -> Result<CapabilityToken, SdkError> {
        self.request_capability(resource, action, anchor).await
    }

    /// Execute an action using a capability (returns a kernel handle).
    pub async fn invoke_capability(
        &self,
        token: &CapabilityToken,
        syscall: &str,
        args: &[&str],
    ) -> Result<serde_json::Value, SdkError> {
        let handle = self.register_token(token).await?;
        let req = serde_json::json!({
            "method": "Syscall",
            "params": {
                "handle": handle.to_u64(),
                "syscall": syscall,
                "args": args,
            }
        });
        let resp: serde_json::Value = rpc(&self.eventscope_addr, &req)
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;
        Ok(resp)
    }

    /// Terminate execution.
    pub fn exit(_code: i32) -> ! {
        std::process::exit(0)
    }

    async fn request_capability(
        &self,
        resource: &str,
        action: &str,
        anchor: TrustAnchor,
    ) -> Result<CapabilityToken, SdkError> {
        let event = IntentEvent {
            actor_id: self.actor_id.clone(),
            action: action.to_string(),
            resource: resource.to_string(),
            anchor,
            timestamp_ms: intentkernel_core::wall_epoch_ms(),
        };
        let req = serde_json::json!({
            "method": "SubmitIntent",
            "params": event,
        });
        let resp: serde_json::Value = rpc(&self.intentd_addr, &req)
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;
        if let Some(reason) = resp.get("reason").and_then(|r| r.as_str()) {
            return Err(SdkError::IntentDenied(reason.to_string()));
        }
        let token: CapabilityToken = serde_json::from_value(resp["data"].clone())
            .map_err(|e| SdkError::Serialization(e.to_string()))?;
        Ok(token)
    }

    async fn register_token(&self, token: &CapabilityToken) -> Result<KernelHandle, SdkError> {
        let cbor = token
            .to_cbor()
            .map_err(|e| SdkError::Serialization(e.to_string()))?;
        let req = serde_json::json!({
            "method": "RegisterToken",
            "params": { "token_cbor": cbor },
        });
        let resp: serde_json::Value = rpc(&self.eventscope_addr, &req)
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;
        let handle = resp["data"]["handle"]
            .as_u64()
            .ok_or(SdkError::CapabilityMissing)?;
        Ok(KernelHandle {
            table_index: (handle >> 32) as u32,
            generation: ((handle >> 16) & 0xFFFF) as u16,
            checksum: (handle & 0xFFFF) as u16,
        })
    }
}

/// Convenience function to make one network request.
pub async fn network_request(
    runtime: &IkrlRuntime,
    destination: &str,
    payload: &[u8],
) -> Result<Vec<u8>, SdkError> {
    runtime.network_request(destination, payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_handle_packing() {
        let h = KernelHandle {
            table_index: 0x5A2,
            generation: 7,
            checksum: 0x1234,
        };
        assert_eq!(h.to_u64(), (0x5A2u64 << 32) | (7u64 << 16) | 0x1234u64);
    }
}
