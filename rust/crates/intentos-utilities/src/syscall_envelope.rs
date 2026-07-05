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

/// HTTP methods for network syscalls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
}
