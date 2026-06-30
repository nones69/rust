//! Kernel Bar, Field, and OOBE-lite command handlers (MVP AI OS surface).

use crate::builtins::BuiltinContext;
use crate::parser::ParsedLine;
use anyhow::{Context, Result};
use intentos_audit::AuditEventKind;
use intentos_kernel::ThresholdLevel;

impl BuiltinContext<'_> {
    pub fn field_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("list");
        match sub {
            "create" => {
                let name = parsed
                    .arg(1)
                    .context("usage: field create <name>")?;
                let field = self.runtime.loom.create_field(name)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::FieldSwitched,
                    &self.state.actor,
                    format!("created field={} id={}", field.name, field.id),
                );
                println!("field created id={} name={}", field.id, field.name);
            }
            "use" => {
                let id = parsed.arg(1).context("usage: field use <id>")?;
                self.runtime.loom.use_field(id)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::FieldSwitched,
                    &self.state.actor,
                    format!("active field={id}"),
                );
                println!("active field={id}");
            }
            "list" => {
                let session = self.runtime.loom.session();
                for f in &session.fields {
                    let active = session
                        .active_field_id
                        .as_deref()
                        .map(|id| id == f.id)
                        .unwrap_or(false);
                    println!(
                        "{} id={} created={}{}",
                        f.name,
                        f.id,
                        f.created_at,
                        if active { " (active)" } else { "" }
                    );
                }
                if session.fields.is_empty() {
                    println!("(no fields — run `field create <name>` or complete OOBE)");
                }
            }
            other => anyhow::bail!("usage: field create|use|list (got: {other})"),
        }
        Ok(())
    }

    pub fn kb_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("open");
        match sub {
            "open" => {
                let session = self.runtime.loom.session();
                let field = session
                    .active_field()
                    .map(|f| format!("{} ({})", f.name, f.id))
                    .unwrap_or_else(|| "(none)".into());
                println!("Kernel Bar — active field: {field}");
                println!("cards ({}):", session.cards.len());
                for c in &session.cards {
                    println!(
                        "  {} title={} caps={} risk={:?}",
                        c.id,
                        c.title,
                        c.cap_summary(),
                        c.risk_level
                    );
                }
                if session.cards.is_empty() {
                    println!("  (empty — `kb create <title> <resource> <action>`)");
                }
            }
            "suggest" => {
                let n: usize = parsed.arg(1).and_then(|s| s.parse().ok()).unwrap_or(3);
                let cards = self.runtime.loom.suggest_cards(n);
                println!("suggested cards ({n}):");
                for c in cards {
                    println!(
                        "  {} — {} ({}) risk={:?}",
                        c.id,
                        c.title,
                        c.cap_summary(),
                        c.risk_level
                    );
                }
            }
            "create" => {
                let title = parsed.arg(1).context("usage: kb create <title> <resource> <action>")?;
                let resource = parsed.arg(2).context("usage: kb create <title> <resource> <action>")?;
                let action = parsed.arg(3).context("usage: kb create <title> <resource> <action>")?;
                let card = self.runtime.loom.create_card(title, resource, action)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::CardCreated,
                    &self.state.actor,
                    format!(
                        "card={} field={} caps={} risk={:?}",
                        card.id,
                        card.field_id,
                        card.cap_summary(),
                        card.risk_level
                    ),
                );
                println!(
                    "card created id={} caps={} risk={:?}",
                    card.id,
                    card.cap_summary(),
                    card.risk_level
                );
            }
            "run" => {
                let card_id = parsed.arg(1).context("usage: kb run <card_id> [--confirm]")?;
                let confirmed = parsed.args.iter().any(|a| *a == "--confirm");
                let (handle, decision) = self
                    .runtime
                    .loom
                    .run_card(
                        &self.runtime.kernel(),
                        &self.runtime.audit,
                        card_id,
                        &self.state.actor,
                        confirmed,
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                self.state.last_handle = Some(handle);
                println!(
                    "executed card={card_id} outcome={} handle=0x{:X} — {}",
                    decision.outcome.as_str(),
                    handle.as_u64(),
                    decision.reason
                );
            }
            "status" => {
                let session = self.runtime.loom.session();
                let stats = self.runtime.kernel().stats();
                println!(
                    "kb status field={:?} cards={} threshold={:?} telemetry={} ai={} caps={} revoked={}",
                    session.active_field_id,
                    session.cards.len(),
                    session.default_threshold,
                    session.telemetry_enabled,
                    session.ai_enabled,
                    stats.active_capabilities,
                    stats.revoked_tokens
                );
            }
            other => anyhow::bail!(
                "usage: kb open|suggest|create|run|status (got: {other})"
            ),
        }
        Ok(())
    }

    pub fn oobe_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");
        match sub {
            "status" => {
                let session = self.runtime.loom.session();
                println!(
                    "oobe_complete={} profile={} threshold={:?} telemetry={} ai={}",
                    session.oobe_complete,
                    session.profile_id,
                    session.default_threshold,
                    session.telemetry_enabled,
                    session.ai_enabled
                );
            }
            "run" => {
                if self.runtime.loom.is_oobe_complete() {
                    println!("OOBE already complete (use `oobe reset` to re-run)");
                    return Ok(());
                }
                let level = parsed
                    .arg(1)
                    .and_then(ThresholdLevel::parse)
                    .unwrap_or(ThresholdLevel::Medium);
                self.runtime.loom.complete_oobe(level)?;
                let session = self.runtime.loom.session();
                let _ = self.runtime.audit.record(
                    AuditEventKind::OobeComplete,
                    &self.state.actor,
                    format!(
                        "profile={} threshold={:?} telemetry=off ai=off",
                        session.profile_id, session.default_threshold
                    ),
                );
                println!(
                    "OOBE complete profile={} threshold={:?} privacy defaults: telemetry=off ai=off",
                    session.profile_id, session.default_threshold
                );
            }
            "reset" => {
                self.runtime.loom.reset_oobe()?;
                println!("OOBE reset — run `oobe run` on next session");
            }
            other => anyhow::bail!("usage: oobe status|run [low|medium|high]|reset (got: {other})"),
        }
        Ok(())
    }

    pub fn loom_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");
        match sub {
            "export" => {
                let path = parsed
                    .arg(1)
                    .context("usage: loom export <path>")?;
                let bundle = self.runtime.loom.export_signed(path)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::LoomExported,
                    &self.state.actor,
                    format!(
                        "export_version={} cards={} fields={} profile={}",
                        bundle.export_version,
                        bundle.payload.cards.len(),
                        bundle.payload.fields.len(),
                        bundle.payload.profile_id
                    ),
                );
                println!(
                    "loom exported cards={} fields={} profile={}",
                    bundle.payload.cards.len(),
                    bundle.payload.fields.len(),
                    bundle.payload.profile_id
                );
            }
            "import" => {
                let path = parsed
                    .arg(1)
                    .context("usage: loom import <path>")?;
                let payload = self.runtime.loom.import_signed(path)?;
                let _ = self.runtime.audit.record(
                    AuditEventKind::LoomImported,
                    &self.state.actor,
                    format!(
                        "imported cards={} fields={} from profile={}",
                        payload.cards.len(),
                        payload.fields.len(),
                        payload.profile_id
                    ),
                );
                println!(
                    "loom imported cards={} fields={} from profile={}",
                    payload.cards.len(),
                    payload.fields.len(),
                    payload.profile_id
                );
            }
            "status" => {
                let session = self.runtime.loom.session();
                println!(
                    "loom profile={} fields={} cards={} signing_key={}",
                    session.profile_id,
                    session.fields.len(),
                    session.cards.len(),
                    if session.signing_public_key_hex.is_empty() {
                        "none"
                    } else {
                        "present"
                    }
                );
            }
            other => anyhow::bail!("usage: loom status|export <path>|import <path> (got: {other})"),
        }
        Ok(())
    }
}