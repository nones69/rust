use intentos_kernel::{Handle, Kernel, SyscallOp, SyscallRequest, SyscallResult};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiError {
    #[error("denied: {0}")]
    Denied(String),
}

/// Native AI inference utility — capability-gated, no external daemon.
pub struct AiGateway;

impl AiGateway {
    /// Run inference after the kernel authorizes an `ai/infer` capability.
    pub fn infer(
        kernel: &Kernel,
        handle: Handle,
        model: &str,
        prompt: &str,
    ) -> Result<String, AiError> {
        match kernel.syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::Infer,
                target: model.into(),
                payload: prompt.as_bytes().to_vec(),
            },
        ) {
            SyscallResult::Allowed { .. } => {}
            SyscallResult::Denied(r) => return Err(AiError::Denied(r)),
        }

        // Native stub backend — replace with Ollama/vLLM adapter in production.
        Ok(format!(
            "[intentos-ai:{model}] echo: {}",
            prompt.chars().take(240).collect::<String>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_kernel::{Intent, TrustAnchor, wall_ms};

    fn intent(resource: &str, action: &str) -> Intent {
        Intent {
            actor: "test".into(),
            resource: resource.into(),
            action: action.into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        }
    }

    #[test]
    fn authorized_infer_returns_response() {
        let kernel = Kernel::boot().unwrap();
        let handle = kernel
            .intent_to_handle_confirmed(intent("ai", "infer"), true)
            .unwrap();
        let out = AiGateway::infer(&kernel, handle, "intentos", "say hi").unwrap();
        assert!(out.contains("say hi"), "got {out}");
        assert!(out.contains("intentos"), "got {out}");
    }

    #[test]
    fn infer_without_ai_capability_is_denied() {
        let kernel = Kernel::boot().unwrap();
        // A `file/read` capability must not authorize AI inference.
        let handle = kernel.intent_to_handle(intent("file", "read")).unwrap();
        let err = AiGateway::infer(&kernel, handle, "intentos", "say hi").unwrap_err();
        assert!(matches!(err, AiError::Denied(_)), "got {err:?}");
    }
}