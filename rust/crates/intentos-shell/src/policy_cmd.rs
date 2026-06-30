//! Policy pack selection — personal vs enterprise profiles.

use crate::builtins::BuiltinContext;
use crate::parser::ParsedLine;
use anyhow::{Context, Result};
use intentos_audit::AuditEventKind;
use intentos_kernel::PolicyPack;

impl BuiltinContext<'_> {
    pub fn policy_cmd(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("list");
        match sub {
            "list" => {
                for pack in [PolicyPack::Personal, PolicyPack::Enterprise] {
                    println!(
                        "{} threshold={:?} — {}",
                        pack.as_str(),
                        pack.default_threshold(),
                        pack.description()
                    );
                }
                let session = self.runtime.loom.session();
                println!("active={:?}", session.policy_pack);
            }
            "use" => {
                let name = parsed.arg(1).context("usage: policy use <personal|enterprise>")?;
                let pack = PolicyPack::parse(name)
                    .with_context(|| format!("unknown policy pack: {name}"))?;
                self.runtime.loom.set_policy_pack(pack)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::Policy,
                    &self.state.actor,
                    format!(
                        "policy_pack={} threshold={:?}",
                        pack.as_str(),
                        pack.default_threshold()
                    ),
                );
                println!(
                    "policy pack set to {} (threshold={:?})",
                    pack.as_str(),
                    pack.default_threshold()
                );
            }
            other => anyhow::bail!("usage: policy list | use <personal|enterprise> (got: {other})"),
        }
        Ok(())
    }
}