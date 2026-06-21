use crate::{AuditLog, PlatformInfo};
use intentos_kernel::Kernel;

/// System utility helpers native to IntentOS.
pub struct SysTools;

impl SysTools {
    pub fn kernel_report(kernel: &Kernel, platform: &PlatformInfo) -> String {
        let stats = kernel.stats();
        format!(
            "host={} arch={:?} os={:?} uptime_ms={} caps={} leases={} recognizer={}",
            platform.hostname,
            platform.arch,
            platform.os,
            stats.uptime_ms,
            stats.active_capabilities,
            stats.active_leases,
            stats.recognizer
        )
    }

    pub fn audit_summary(audit: &AuditLog, tail: usize) -> String {
        match audit.tail(tail) {
            Ok(entries) => {
                let mut lines = Vec::new();
                for e in entries {
                    lines.push(format!(
                        "[{}] {:?} {} — {}",
                        e.seq, e.kind, e.actor, e.detail
                    ));
                }
                lines.join("\n")
            }
            Err(e) => format!("audit error: {e}"),
        }
    }
}