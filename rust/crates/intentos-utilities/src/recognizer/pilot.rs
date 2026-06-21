//! Phase 2 pilot recognizer: enterprise commands → Ollama NL → keyword stub.

use super::ollama::OllamaClient;
use crate::sectors::enterprise::EnterpriseMapper;
use intentos_kernel::{IntentRecognizer, RecognizedIntent, StubRecognizer};

/// Production pilot recognizer wired at `OsRuntime::boot`.
pub struct PilotRecognizer {
    ollama: Option<OllamaClient>,
    stub: StubRecognizer,
}

impl PilotRecognizer {
    pub fn boot() -> Self {
        Self {
            ollama: OllamaClient::from_env(),
            stub: StubRecognizer,
        }
    }

    pub fn new() -> Self {
        Self::boot()
    }

    pub fn ollama_enabled(&self) -> bool {
        self.ollama.is_some()
    }
}

impl IntentRecognizer for PilotRecognizer {
    fn recognize(&self, text: &str) -> RecognizedIntent {
        if let Some(mapped) = EnterpriseMapper::map(text) {
            return RecognizedIntent {
                resource: mapped.resource,
                action: mapped.action,
                confidence: 0.92,
                raw_text: text.into(),
            };
        }

        if let Some(client) = &self.ollama {
            if let Some(out) = client.recognize(text) {
                if out.confidence >= 0.40 {
                    return out;
                }
            }
        }

        self.stub.recognize(text)
    }

    fn name(&self) -> &'static str {
        if self.ollama.is_some() {
            "enterprise+ollama+stub"
        } else {
            "enterprise+stub"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_still_wins_over_stub() {
        let r = PilotRecognizer::boot();
        let out = r.recognize("cat /etc/hosts");
        assert_eq!(out.resource, "file");
        assert_eq!(out.action, "read");
    }
}