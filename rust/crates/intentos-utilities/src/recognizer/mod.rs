//! Intent recognizer backends for IntentOS utilities tier.

mod ollama;
mod pilot;

pub use ollama::OllamaClient;
pub use pilot::PilotRecognizer;