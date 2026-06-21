//! Enterprise command → intent mapping (PowerShell, Bash, CMD).

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Intent, TrustAnchor, wall_ms};
use std::collections::BTreeMap;

/// Maps enterprise shell commands to structured intents.
pub struct EnterpriseMapper;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedIntent {
    pub resource: String,
    pub action: String,
    pub shell_family: ShellFamily,
    pub original: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellFamily {
    PowerShell,
    Bash,
    Cmd,
    Unknown,
}

impl EnterpriseMapper {
    pub const SUPPORTED: &'static [&'static str] = &[
        "Get-ChildItem",
        "Get-Content",
        "Set-Content",
        "Invoke-WebRequest",
        "Get-Process",
        "dir",
        "type",
        "copy",
        "ls",
        "cat",
        "cp",
        "curl",
        "wget",
        "ps",
        "docker ps",
        "kubectl get pods",
    ];

    pub fn detect_family(cmd: &str) -> ShellFamily {
        let trimmed = cmd.trim();
        if trimmed.starts_with("Get-")
            || trimmed.starts_with("Set-")
            || trimmed.starts_with("New-")
            || trimmed.starts_with("Invoke-")
            || trimmed.contains("-Item")
        {
            ShellFamily::PowerShell
        } else if trimmed.starts_with("dir ")
            || trimmed == "dir"
            || trimmed.starts_with("type ")
            || trimmed.starts_with("copy ")
        {
            ShellFamily::Cmd
        } else if trimmed.contains('|')
            || trimmed.starts_with("ls ")
            || trimmed == "ls"
            || trimmed.starts_with("cat ")
            || trimmed.starts_with("cp ")
            || trimmed.starts_with("curl ")
            || trimmed.starts_with("wget ")
            || trimmed.starts_with("ps")
            || trimmed.starts_with("docker ")
            || trimmed.starts_with("kubectl ")
        {
            ShellFamily::Bash
        } else {
            ShellFamily::Unknown
        }
    }

    pub fn map(cmd: &str) -> Option<MappedIntent> {
        let family = Self::detect_family(cmd);
        let lower = cmd.trim().to_lowercase();

        let (resource, action) = match lower.as_str() {
            "dir" | "ls" => ("dir", "list"),
            s if s.starts_with("get-childitem") || s.starts_with("dir ") => ("dir", "list"),
            s if s.starts_with("ls ") => ("dir", "list"),
            s if s.starts_with("docker ps") || s.starts_with("kubectl get") => ("dir", "list"),
            s if s.starts_with("cat ")
                || s.starts_with("type ")
                || s.starts_with("get-content") =>
            {
                ("file", "read")
            }
            s if s.starts_with("copy ")
                || s.starts_with("cp ")
                || s.starts_with("set-content")
                || s.starts_with("out-file") =>
            {
                ("file", "write")
            }
            s if s.starts_with("invoke-webrequest")
                || s.starts_with("curl ")
                || s.starts_with("wget ") =>
            {
                ("network", "send")
            }
            s if s.starts_with("get-process") || s == "ps" || s.starts_with("ps ") => {
                ("process", "list")
            }
            s if s.contains("infer") || s.contains("openai") => ("ai", "infer"),
            _ => return None,
        };

        Some(MappedIntent {
            resource: resource.into(),
            action: action.into(),
            shell_family: family,
            original: cmd.trim().to_string(),
        })
    }

    pub fn to_intent(mapped: &MappedIntent, actor: &str) -> Intent {
        Intent {
            actor: actor.into(),
            resource: mapped.resource.clone(),
            action: mapped.action.clone(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: BTreeMap::from([
                ("sector".into(), "enterprise".into()),
                ("shell".into(), format!("{:?}", mapped.shell_family)),
                ("command".into(), mapped.original.clone()),
            ]),
        }
    }

    pub fn map_and_audit(cmd: &str, actor: &str, audit: &AuditLog) -> Option<Intent> {
        let mapped = Self::map(cmd)?;
        let _ = audit.record(
            AuditEventKind::SectorMap,
            actor,
            format!(
                "{:?} `{}` -> {}/{}",
                mapped.shell_family, mapped.original, mapped.resource, mapped.action
            ),
        );
        Some(Self::to_intent(&mapped, actor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_powershell_list() {
        let m = EnterpriseMapper::map("Get-ChildItem C:\\Users").unwrap();
        assert_eq!(m.resource, "dir");
        assert_eq!(m.shell_family, ShellFamily::PowerShell);
    }

    #[test]
    fn maps_bash_cat() {
        let m = EnterpriseMapper::map("cat /etc/hosts").unwrap();
        assert_eq!(m.resource, "file");
        assert_eq!(m.action, "read");
    }

    #[test]
    fn maps_docker_ps() {
        let m = EnterpriseMapper::map("docker ps").unwrap();
        assert_eq!(m.resource, "dir");
        assert_eq!(m.action, "list");
    }

    #[test]
    fn maps_get_process() {
        let m = EnterpriseMapper::map("Get-Process").unwrap();
        assert_eq!(m.resource, "process");
        assert_eq!(m.action, "list");
    }
}