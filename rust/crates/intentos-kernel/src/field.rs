//! Field — isolated workspace context for intent cards.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Field is a named context where intent cards execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}

impl Field {
    pub fn new(name: &str, created_at: u64) -> Self {
        Self {
            id: format!("fld-{}", Uuid::new_v4()),
            name: name.to_string(),
            created_at,
        }
    }
}