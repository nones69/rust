use serde::{Deserialize, Serialize};

use crate::syscall_envelope::HttpMethod;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetScope {
    pub hosts: Vec<String>,
    pub methods: Vec<HttpMethod>,
}
