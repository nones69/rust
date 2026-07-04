//! OpenMode type shared between host_vfs and callers within intentos-utilities.

use serde::{Deserialize, Serialize};

/// File-open mode flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Create,
}
