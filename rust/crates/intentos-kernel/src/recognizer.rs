//! Pluggable intent recognition — stub today, Ollama/cloud backends later.

use crate::types::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// Output of an intent recognizer before policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct RecognizedIntent {
    pub resource: String,
    pub action: String,
    pub confidence: f32,
    pub raw_text: String,
}

impl RecognizedIntent {
    pub fn into_intent(self, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: self.resource,
            action: self.action,
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("confidence".into(), format!("{:.2}", self.confidence)),
                ("raw".into(), self.raw_text),
            ]),
        }
    }
}

/// Recognizer contract — swap implementations without changing the kernel API.
pub trait IntentRecognizer: Send + Sync {
    fn recognize(&self, text: &str) -> RecognizedIntent;
    fn name(&self) -> &'static str;
}

/// Keyword-based stub recognizer for Phase 1 pilots.
pub struct StubRecognizer;

impl IntentRecognizer for StubRecognizer {
    fn recognize(&self, text: &str) -> RecognizedIntent {
        let lower = text.to_lowercase();
        let (resource, action, confidence) = if lower.contains("read")
            || lower.contains("cat")
            || lower.contains("get-content")
            || lower.contains("open")
        {
            ("file", "read", 0.75)
        } else if lower.contains("write")
            || lower.contains("save")
            || lower.contains("set-content")
        {
            ("file", "write", 0.75)
        } else if lower.contains("list") || lower.contains("ls") || lower.contains("dir") {
            ("dir", "list", 0.70)
        } else if lower.contains("infer") || lower.contains("ask") || lower.contains("ai") {
            ("ai", "infer", 0.65)
        } else if lower.contains("send") || lower.contains("network") {
            ("network", "send", 0.60)
        } else {
            ("unknown", "noop", 0.10)
        };

        RecognizedIntent {
            resource: resource.into(),
            action: action.into(),
            confidence,
            raw_text: text.into(),
        }
    }

    fn name(&self) -> &'static str {
        "stub-keyword"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_maps_read_verbs() {
        let r = StubRecognizer;
        let out = r.recognize("please read the config file");
        assert_eq!(out.resource, "file");
        assert_eq!(out.action, "read");
        assert!(out.confidence > 0.5);
    }
}