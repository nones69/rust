//! Kernel Bar TUI — numbered card picker with live refresh.

use crate::builtins::BuiltinContext;
use anyhow::{Context, Result};
use intentos_utilities::LoomStore;
use std::io::{self, Write};

pub fn run_kb_tui(ctx: &mut BuiltinContext<'_>) -> Result<()> {
    let mut selected: Option<usize> = None;
    clear_screen();
    render_bar(ctx, selected)?;
    println!("Kernel Bar TUI — `help` for commands, `q` to exit");
    let stdin = io::stdin();
    loop {
        print!("kb> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            clear_screen();
            render_bar(ctx, selected)?;
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied().unwrap_or("") {
            "q" | "quit" | "exit" => break,
            "help" | "?" => print_tui_help(),
            "refresh" | "list" | "open" | "bar" => {
                clear_screen();
                render_bar(ctx, selected)?;
            }
            "status" => print_status(ctx)?,
            "suggest" => {
                let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
                let cards = ctx.runtime.loom.suggest_cards(n);
                println!("suggested ({n}):");
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
            "create" | "c" => {
                let title = parts.get(1).context("usage: create <title> <resource> <action>")?;
                let resource = parts.get(2).context("usage: create <title> <resource> <action>")?;
                let action = parts.get(3).context("usage: create <title> <resource> <action>")?;
                let card = ctx.runtime.loom.create_card(title, resource, action)?;
                println!(
                    "created {} caps={} risk={:?}",
                    card.id,
                    card.cap_summary(),
                    card.risk_level
                );
                clear_screen();
                render_bar(ctx, selected)?;
            }
            "sel" | "select" => {
                let idx = card_index(&parts, 1)?;
                selected = Some(idx);
                clear_screen();
                render_bar(ctx, selected)?;
            }
            "preview" | "p" => {
                let idx = card_index(&parts, 1)?;
                selected = Some(idx);
                let card_id = card_id_at(ctx, idx)?;
                preview_card(ctx, &card_id)?;
            }
            "run" | "r" => {
                let confirmed = parts.iter().any(|a| *a == "--confirm");
                let idx_pos = if parts.get(1) == Some(&"--confirm") {
                    2
                } else {
                    1
                };
                let idx = card_index(&parts, idx_pos)?;
                selected = Some(idx);
                let card_id = card_id_at(ctx, idx)?;
                run_card(ctx, &card_id, confirmed)?;
                clear_screen();
                render_bar(ctx, selected)?;
            }
            n if n.parse::<usize>().is_ok() => {
                let idx = n.parse::<usize>().context("invalid card index")?;
                selected = Some(idx);
                let card_id = card_id_at(ctx, idx)?;
                preview_card(ctx, &card_id)?;
            }
            other => println!("unknown: {other} (type `help`)"),
        }
    }
    Ok(())
}

fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

fn print_tui_help() {
    println!(
        r#"Kernel Bar commands:
  refresh|bar       Redraw card table (clears screen)
  status            Kernel + posture summary
  create <t> <r> <a>  New intent card
  sel <n>           Highlight card n
  <n>               Preview card n
  p <n>             Preview card n
  r <n> [--confirm] Run card n
  suggest [n]       Suggest cards (default 3)
  q                 Exit TUI"#
    );
}

fn print_status(ctx: &BuiltinContext<'_>) -> Result<()> {
    let session = ctx.runtime.loom.session();
    let stats = ctx.runtime.kernel().stats();
    let signals = LoomStore::threshold_signals(&ctx.runtime.platform);
    println!(
        "field={:?} cards={} caps={} revoked={} pqc={} peers={}",
        session.active_field_id,
        session.cards.len(),
        stats.active_capabilities,
        stats.revoked_tokens,
        session.pqc_tokens_enabled,
        session.broker_peers.len()
    );
    println!(
        "trust_score={} sig_version={} telemetry={} ai={}",
        signals.trust_score,
        ctx.runtime.kernel().token_sig_version(),
        session.telemetry_enabled,
        session.ai_enabled
    );
    Ok(())
}

fn render_bar(ctx: &BuiltinContext<'_>, selected: Option<usize>) -> Result<()> {
    let session = ctx.runtime.loom.session();
    let field = session
        .active_field()
        .map(|f| format!("{} ({})", f.name, f.id))
        .unwrap_or_else(|| "(none)".into());
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║ Kernel Bar — field: {field:<40} ║");
    println!("╠════╤══════════════════════════╤══════════════╤══════════════╣");
    println!("║ #  │ Title                    │ Caps         │ Risk         ║");
    println!("╠════╪══════════════════════════╪══════════════╪══════════════╣");
    if session.cards.is_empty() {
        println!("║ (no cards — `create <title> <res> <act>`)                    ║");
    } else {
        for (i, c) in session.cards.iter().enumerate() {
            let n = i + 1;
            let marker = if selected == Some(n) { ">" } else { " " };
            println!(
                "║{marker}{:>2} │ {:<24} │ {:<12} │ {:<12?} ║",
                n,
                truncate(&c.title, 24),
                truncate(&c.cap_summary(), 12),
                c.risk_level
            );
        }
    }
    println!("╚════╧══════════════════════════╧══════════════╧══════════════╝");
    println!(
        "threshold={:?} pqc={} telemetry={} ai={} peers={}",
        session.default_threshold,
        session.pqc_tokens_enabled,
        session.telemetry_enabled,
        session.ai_enabled,
        session.broker_peers.len()
    );
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn card_index(parts: &[&str], pos: usize) -> Result<usize> {
    let raw = parts
        .get(pos)
        .context("usage: <n> | p <n> | r <n> [--confirm]")?;
    let idx: usize = raw.parse().context("card index must be a positive integer")?;
    if idx == 0 {
        anyhow::bail!("card index starts at 1");
    }
    Ok(idx)
}

fn card_id_at(ctx: &BuiltinContext<'_>, idx: usize) -> Result<String> {
    let session = ctx.runtime.loom.session();
    let card = session
        .cards
        .get(idx - 1)
        .with_context(|| format!("no card at index {idx}"))?;
    Ok(card.id.clone())
}

fn preview_card(ctx: &BuiltinContext<'_>, card_id: &str) -> Result<()> {
    let signals = LoomStore::threshold_signals(&ctx.runtime.platform);
    let preview = ctx
        .runtime
        .loom
        .preview_card(card_id, Some(&signals))?;
    println!(
        "preview {} title={} caps={} outcome={} confirm={} reason={}",
        preview.card_id,
        preview.title,
        preview.cap_summary,
        preview.outcome.as_str(),
        preview.requires_confirmation,
        preview.reason
    );
    if preview.requires_confirmation {
        println!("run with: r {} --confirm", preview.card_id);
    }
    Ok(())
}

fn run_card(ctx: &mut BuiltinContext<'_>, card_id: &str, confirmed: bool) -> Result<()> {
    let signals = LoomStore::threshold_signals(&ctx.runtime.platform);
    let (handle, decision) = ctx
        .runtime
        .loom
        .run_card(
            &ctx.runtime.kernel(),
            &ctx.runtime.audit,
            card_id,
            &ctx.state.actor,
            confirmed,
            Some(&signals),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    ctx.state.last_handle = Some(handle);
    println!(
        "executed card={card_id} outcome={} handle=0x{:X} — {}",
        decision.outcome.as_str(),
        handle.as_u64(),
        decision.reason
    );
    Ok(())
}