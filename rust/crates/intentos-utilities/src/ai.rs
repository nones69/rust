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