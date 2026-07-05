use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

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
            let op_ok = match mode {
                OpenMode::Read => FsOp::Read,
                OpenMode::Write => FsOp::Write,
                OpenMode::ReadWrite => {
                    return scope.ops.contains(&FsOp::Read)
                        && scope.ops.contains(&FsOp::Write)
                        && path_under_prefix(path, &scope.path_prefix);
                }
                OpenMode::Create => FsOp::Create,
            };
            scope.ops.contains(&op_ok) && path_under_prefix(path, &scope.path_prefix)
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
            let host_ok = extract_host(url)
                .map(|host| scope.hosts.iter().any(|h| host_matches(&host, h)))
                .unwrap_or(false);
            let method_ok = scope.methods.contains(method);
            host_ok && method_ok
        }
        _ => false,
    }
}

fn permits_ai(scope: &AiScope, syscall: &IkSyscall) -> bool {
    match syscall {
        IkSyscall::IkAiInfer { max_tokens, .. } => {
            if let Some(limit) = scope.max_tokens {
                if let Some(req) = max_tokens {
                    return *req <= limit;
                }
            }
            true
        }
        _ => false,
    }
}

fn path_under_prefix(path: &str, prefix: &str) -> bool {
    let pref = match normalize_absolute(prefix) {
        Some(pref) => pref,
        None => return false,
    };
    let p = match normalize_for_scope(path, &pref) {
        Some(path) => path,
        None => return false,
    };
    p.starts_with(pref)
}

fn normalize_for_scope(path: &str, scope_prefix: &Path) -> Option<PathBuf> {
    let input = Path::new(path);
    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        scope_prefix.join(input)
    };
    normalize_path(joined)
}

fn normalize_absolute(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return None;
    }
    normalize_path(path.to_path_buf())
}

fn normalize_path(base: PathBuf) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in base.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            _ => out.push(component),
        }
    }
    Some(out)
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split('/').next()?;
    let authority = authority.rsplit('@').next()?;

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[1..end].to_ascii_lowercase());
    };

    let host = authority.split(':').next().unwrap();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn host_matches(host: &str, allowed: &str) -> bool {
    let allowed = allowed.trim().to_ascii_lowercase();
    if allowed.is_empty() {
        return false;
    }
    host == allowed || host.ends_with(&format!(".{allowed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readwrite_mode_requires_both_ops() {
        let scope = FsScope {
            path_prefix: "/tmp/intentos_root".to_string(),
            ops: vec![FsOp::Read],
        };
        let syscall = IkSyscall::IkOpen {
            path: "a.txt".to_string(),
            mode: OpenMode::ReadWrite,
        };
        assert!(!permits_fs(&scope, &syscall));
    }

    #[test]
    fn relative_path_is_scoped_to_prefix() {
        assert!(path_under_prefix("notes/file.txt", "/tmp/intentos_root"));
    }

    #[test]
    fn host_match_accepts_exact_and_subdomain_only() {
        assert!(host_matches("api.example.com", "example.com"));
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("malicious-example.com", "example.com"));
    }
}
