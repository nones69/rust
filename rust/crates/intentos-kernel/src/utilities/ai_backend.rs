use std::env;
use uuid::Uuid;

use crate::capability_schema::AiScope;

pub trait AiBackend: Send + Sync {
    fn infer(
        &self,
        token_id: &Uuid,
        scope: &AiScope,
        prompt: &str,
        max_tokens: Option<u64>,
    ) -> Result<String, String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalAiBackend;

impl AiBackend for LocalAiBackend {
    fn infer(
        &self,
        token_id: &Uuid,
        scope: &AiScope,
        prompt: &str,
        max_tokens: Option<u64>,
    ) -> Result<String, String> {
        let limit = resolved_limit(scope, max_tokens)?;
        let preview: String = prompt.chars().take(240).collect();
        Ok(format!(
            "[local:{} token={} max_tokens={}] {}",
            scope.model, token_id, limit, preview
        ))
    }
}

#[derive(Debug, Clone)]
pub struct RemoteAiBackend {
    provider: String,
}

impl RemoteAiBackend {
    pub fn from_env() -> Self {
        Self {
            provider: env::var("INTENTOS_AI_REMOTE_PROVIDER")
                .unwrap_or_else(|_| "openai".to_string()),
        }
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
}

impl AiBackend for RemoteAiBackend {
    fn infer(
        &self,
        token_id: &Uuid,
        scope: &AiScope,
        prompt: &str,
        max_tokens: Option<u64>,
    ) -> Result<String, String> {
        let limit = resolved_limit(scope, max_tokens)?;
        let preview: String = prompt.chars().take(240).collect();
        Ok(format!(
            "[remote:{} model={} token={} max_tokens={}] {}",
            self.provider(),
            scope.model,
            token_id,
            limit,
            preview
        ))
    }
}

pub fn infer_scoped(
    token_id: &Uuid,
    scope: &AiScope,
    prompt: &str,
    max_tokens: Option<u64>,
) -> Result<String, String> {
    match env::var("INTENTOS_AI_BACKEND")
        .unwrap_or_else(|_| "local".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "remote" => RemoteAiBackend::from_env().infer(token_id, scope, prompt, max_tokens),
        _ => LocalAiBackend.infer(token_id, scope, prompt, max_tokens),
    }
}

fn resolved_limit(scope: &AiScope, requested: Option<u64>) -> Result<u64, String> {
    match (scope.max_tokens, requested) {
        (Some(limit), Some(req)) if req > limit => Err(format!(
            "requested tokens exceed scope limit ({req} > {limit})"
        )),
        (Some(limit), Some(req)) => Ok(req.min(limit)),
        (Some(limit), None) => Ok(limit),
        (None, Some(req)) => Ok(req),
        (None, None) => Ok(256),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_backend_respects_scope_limit() {
        let scope = AiScope {
            model: "stub".into(),
            max_tokens: Some(32),
        };
        let out = LocalAiBackend
            .infer(&Uuid::nil(), &scope, "hello world", Some(16))
            .unwrap();
        assert!(out.contains("max_tokens=16"));
        let err = LocalAiBackend
            .infer(&Uuid::nil(), &scope, "hello", Some(64))
            .unwrap_err();
        assert!(err.contains("exceed scope limit"));
    }
}
