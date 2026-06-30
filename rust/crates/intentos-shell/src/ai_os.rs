//! Kernel Bar, Field, and OOBE-lite command handlers (MVP AI OS surface).

use crate::builtins::BuiltinContext;
use crate::parser::ParsedLine;
use anyhow::{Context, Result};
use intentos_audit::AuditEventKind;
use intentos_kernel::{ThresholdLevel, ThresholdSignals};

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
            "preview" => {
                let card_id = parsed.arg(1).context("usage: kb preview <card_id>")?;
                let platform = &self.runtime.platform;
                let signals = ThresholdSignals::from_platform(
                    &format!("{:?}", platform.arch),
                    &format!("{:?}", platform.os),
                    platform.logical_cpus,
                    platform.backend,
                );
                let preview = self
                    .runtime
                    .loom
                    .preview_card(card_id, Some(&signals))?;
                println!("{}", serde_json::to_string_pretty(&preview)?);
                if preview.requires_confirmation {
                    println!("confirmation required — run: kb run {card_id} --confirm");
                }
            }
            "run" => {
                let card_id = parsed.arg(1).context("usage: kb run <card_id> [--confirm]")?;
                let confirmed = parsed.args.iter().any(|a| *a == "--confirm");
                let signals = intentos_utilities::LoomStore::threshold_signals(
                    &self.runtime.platform,
                );
                let (handle, decision) = self
                    .runtime
                    .loom
                    .run_card(
                        &self.runtime.kernel(),
                        &self.runtime.audit,
                        card_id,
                        &self.state.actor,
                        confirmed,
                        Some(&signals),
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
            "tui" | "bar" => {
                crate::kb_tui::run_kb_tui(self)?;
            }
            other => anyhow::bail!(
                "usage: kb open|suggest|create|preview|run|status|tui (got: {other})"
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
            "hook" => {
                let sub = parsed.arg(1).unwrap_or("status");
                match sub {
                    "status" => {
                        let session = self.runtime.loom.session();
                        let manifest =
                            intentos_utilities::emit_oobe_hook(&self.runtime.platform, &session.profile_id);
                        println!(
                            "oobe_hook platform={} path={} profile={}",
                            manifest.platform, manifest.hook_path, manifest.profile_id
                        );
                    }
                    "emit" => {
                        let session = self.runtime.loom.session();
                        let path = parsed
                            .arg(2)
                            .context("usage: oobe hook emit <path>")?;
                        let manifest =
                            intentos_utilities::emit_oobe_hook(&self.runtime.platform, &session.profile_id);
                        std::fs::create_dir_all(
                            std::path::Path::new(path)
                                .parent()
                                .unwrap_or(std::path::Path::new(".")),
                        )?;
                        std::fs::write(path, &manifest.script)?;
                        let _ = self.runtime.audit.record(
                            AuditEventKind::OobeHookEmitted,
                            &self.state.actor,
                            format!(
                                "platform={} path={} profile={}",
                                manifest.platform, path, manifest.profile_id
                            ),
                        );
                        println!("oobe hook written to {path}");
                    }
                    other => anyhow::bail!("usage: oobe hook status|emit <path> (got: {other})"),
                }
            }
            other => anyhow::bail!(
                "usage: oobe status|run [low|medium|high]|reset|hook (got: {other})"
            ),
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