//! Optional Ollama HTTP backend for intent recognition (Phase 2).

use intentos_kernel::RecognizedIntent;
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_MODEL: &str = "llama3.2";
const TIMEOUT_MS: u64 = 3_000;

#[derive(Debug)]
pub struct OllamaClient {
    base_url: String,
    model: String,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct GenerateResponse {
    response: String,
}

#[derive(Debug, Deserialize)]
struct OllamaIntentJson {
    resource: String,
    action: String,
    confidence: Option<f32>,
}

impl OllamaClient {
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("INTENTOS_OLLAMA_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let url_set = std::env::var("INTENTOS_OLLAMA_URL").is_ok();
        if !enabled && !url_set {
            return None;
        }

        let base_url = std::env::var("INTENTOS_OLLAMA_URL")
            .unwrap_or_else(|_| DEFAULT_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        let model = std::env::var("INTENTOS_OLLAMA_MODEL")
            .unwrap_or_else(|_| DEFAULT_MODEL.to_string());

        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(TIMEOUT_MS))
            .build()
            .ok()?;

        Some(Self {
            base_url,
            model,
            http,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn recognize(&self, text: &str) -> Option<RecognizedIntent> {
        let prompt = format!(
            "You map user requests to OS capability intents. \
             Reply with ONLY valid JSON, no markdown: \
             {{\"resource\":\"file|dir|network|ai|process|unknown\",\
             \"action\":\"read|write|list|send|infer|noop|list\",\
             \"confidence\":0.0-1.0}}\n\
             User request: {text}"
        );

        let url = format!("{}/api/generate", self.base_url);
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "format": "json",
        });

        let resp = self.http.post(&url).json(&body).send().ok()?;
        if !resp.status().is_success() {
            return None;
        }

        let gen: GenerateResponse = resp.json().ok()?;
        let parsed: OllamaIntentJson = serde_json::from_str(gen.response.trim()).ok()?;
        if parsed.resource == "unknown" || parsed.action == "noop" {
            return None;
        }

        Some(RecognizedIntent {
            resource: parsed.resource,
            action: parsed.action,
            confidence: parsed.confidence.unwrap_or(0.55).clamp(0.0, 1.0),
            raw_text: text.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ollama_enabled() -> bool {
        std::env::var("INTENTOS_OLLAMA_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    #[test]
    fn from_env_disabled_by_default() {
        std::env::remove_var("INTENTOS_OLLAMA_ENABLE");
        std::env::remove_var("INTENTOS_OLLAMA_URL");
        assert!(OllamaClient::from_env().is_none());
    }

    /// Gated integration test — set `INTENTOS_OLLAMA_ENABLE=1` and run a local Ollama server.
    #[test]
    fn ollama_live_recognize_when_enabled() {
        if !ollama_enabled() {
            eprintln!("skip: INTENTOS_OLLAMA_ENABLE not set");
            return;
        }

        let client = OllamaClient::from_env().expect("Ollama should be configured when enabled");
        let out = client
            .recognize("please list all files in the documents folder")
            .expect("Ollama should return a mapped intent");

        assert_eq!(out.resource, "dir");
        assert_eq!(out.action, "list");
        assert!(out.confidence >= 0.40);
    }
}