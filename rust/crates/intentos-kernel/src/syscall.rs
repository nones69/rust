use serde_json::json;

use crate::capability_schema::{AiScope, TokenScope};
use crate::syscall_envelope::{IkCallEnvelope, IkSyscall};
use crate::token_verifier::{verify_token_scope, VerifiedToken};
use crate::utilities;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

pub fn dispatch_call(
    env: IkCallEnvelope,
    token: &VerifiedToken,
) -> Result<serde_json::Value, String> {
    verify_token_scope(token, &env.call)?;

    match env.call {
        IkSyscall::IkOpen { path, mode } => {
            match utilities::host_vfs::vfs_open(&token.id, &path, mode) {
                Ok(handle) => Ok(json!({"handle": handle.to_string()})),
                Err(e) => Err(format!("vfs_open error: {}", e)),
            }
        }
        IkSyscall::IkRead { handle, len } => {
            match utilities::host_vfs::vfs_read(&token.id, handle, len) {
                Ok(bytes) => Ok(json!({"data": BASE64.encode(&bytes)})),
                Err(e) => Err(format!("vfs_read error: {}", e)),
            }
        }
        IkSyscall::IkWrite { handle, data } => {
            match utilities::host_vfs::vfs_write(&token.id, handle, &data) {
                Ok(()) => Ok(json!({"written": data.len()})),
                Err(e) => Err(format!("vfs_write error: {}", e)),
            }
        }
        IkSyscall::IkAiInfer {
            model,
            prompt,
            max_tokens,
        } => {
            let scope = ai_scope_for_model(&token.scope, &model)
                .ok_or_else(|| "ai scope not found for model".to_string())?;
            match utilities::ai_backend::infer_scoped(&token.id, scope, &prompt, max_tokens) {
                Ok(output) => Ok(json!({ "output": output })),
                Err(e) => Err(format!("ai_infer error: {}", e)),
            }
        }
        _ => Err("syscall not implemented in demo".to_string()),
    }
}

fn ai_scope_for_model<'a>(scope: &'a TokenScope, model: &str) -> Option<&'a AiScope> {
    match scope {
        TokenScope::Ai(ai) => {
            if ai.model == "*" || ai.model.eq_ignore_ascii_case(model) {
                Some(ai)
            } else {
                None
            }
        }
        TokenScope::Composite(scopes) => scopes.iter().find_map(|s| ai_scope_for_model(s, model)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_model_in_composite_scope() {
        let scope = TokenScope::Composite(vec![
            TokenScope::Fs(crate::capability_schema::FsScope {
                path_prefix: "/tmp/intentos_root".to_string(),
                ops: vec![crate::capability_schema::FsOp::Read],
            }),
            TokenScope::Ai(crate::capability_schema::AiScope {
                model: "gpt-4o-mini".to_string(),
                max_tokens: Some(64),
            }),
        ]);

        let found = ai_scope_for_model(&scope, "GPT-4O-mini");
        assert!(found.is_some());
    }
}
