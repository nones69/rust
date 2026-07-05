use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::syscall_envelope::{HttpMethod, IkSyscall, OpenMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOp {
    Read,
    Write,
    Create,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsScope {
    pub path_prefix: String,
    pub ops: Vec<FsOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetScope {
    pub hosts: Vec<String>,
    pub methods: Vec<HttpMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScope {
    pub model: String,
    pub max_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenScope {
    Fs(FsScope),
    Net(NetScope),
    Ai(AiScope),
    Composite(Vec<TokenScope>),
}

impl TokenScope {
    pub fn permits(&self, syscall: &IkSyscall) -> bool {
        match self {
            TokenScope::Fs(fs) => permits_fs(fs, syscall),
            TokenScope::Net(net) => permits_net(net, syscall),
            TokenScope::Ai(ai) => permits_ai(ai, syscall),
            TokenScope::Composite(scopes) => scopes.iter().any(|s| s.permits(syscall)),
        }
    }
}

fn permits_fs(scope: &FsScope, syscall: &IkSyscall) -> bool {
    match syscall {
        IkSyscall::IkOpen { path, mode } => {
            let op = match mode {
                OpenMode::Read => FsOp::Read,
                OpenMode::Write => FsOp::Write,
                OpenMode::ReadWrite => FsOp::Read,
                OpenMode::Create => FsOp::Create,
            };
            scope.ops.contains(&op) && path_under_prefix(path, &scope.path_prefix)
        }
        IkSyscall::IkRead { .. } => scope.ops.contains(&FsOp::Read),
        IkSyscall::IkWrite { .. } => scope.ops.contains(&FsOp::Write),
        IkSyscall::IkClose { .. } => true,
        _ => false,
    }
}

fn permits_net(scope: &NetScope, syscall: &IkSyscall) -> bool {
    match syscall {
        IkSyscall::IkNetRequest { method, url, .. } => {
            let host_ok = scope.hosts.iter().any(|h| url.contains(h));
            let method_ok = scope.methods.contains(method);
            host_ok && method_ok
        }
        _ => false,
    }
}

fn permits_ai(scope: &AiScope, syscall: &IkSyscall) -> bool {
    match syscall {
        IkSyscall::IkAiInfer { max_tokens, .. } => {
            if let Some(limit) = scope.max_tokens && let Some(req) = max_tokens {
                return req <= &limit;
            }
            true
        }
        _ => false,
    }
}

fn path_under_prefix(path: &str, prefix: &str) -> bool {
    let p = match Path::new(path).canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pref = match Path::new(prefix).canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    p.starts_with(pref)
}
