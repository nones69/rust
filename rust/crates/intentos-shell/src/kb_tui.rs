//! Minimal Kernel Bar TUI — numbered card picker without raw terminal mode.

use crate::builtins::BuiltinContext;
use anyhow::{Context, Result};
use intentos_kernel::ThresholdSignals;
use std::io::{self, Write};

pub fn run_kb_tui(ctx: &mut BuiltinContext<'_>) -> Result<()> {
    println!("Kernel Bar TUI — type `help` for commands, `q` to exit");
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
            render_bar(ctx)?;
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied().unwrap_or("") {
            "q" | "quit" | "exit" => break,
            "help" | "?" => print_tui_help(),
            "list" | "open" | "bar" => render_bar(ctx)?,
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
            "preview" | "p" => {
                let idx = card_index(&parts, 1)?;
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
                let card_id = card_id_at(ctx, idx)?;
                run_card(ctx, &card_id, confirmed)?;
            }
            n if n.parse::<usize>().is_ok() => {
                let idx = n.parse::<usize>().context("invalid card index")?;
                let card_id = card_id_at(ctx, idx)?;
                preview_card(ctx, &card_id)?;
            }
            other => println!("unknown: {other} (type `help`)"),
        }
    }
    Ok(())
}

fn print_tui_help() {
    println!(
        r#"Kernel Bar commands:
  list|bar          Render card table
  <n>               Preview card n
  p <n>             Preview card n
  r <n> [--confirm] Run card n
  suggest [n]       Suggest cards (default 3)
  q                 Exit TUI"#
    );
}

fn render_bar(ctx: &BuiltinContext<'_>) -> Result<()> {
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
        println!("║ (no cards — create with `kb create <title> <res> <act>`)     ║");
    } else {
        for (i, c) in session.cards.iter().enumerate() {
            let n = i + 1;
            println!(
                "║ {:>2} │ {:<24} │ {:<12} │ {:<12?} ║",
                n,
                truncate(&c.title, 24),
                truncate(&c.cap_summary(), 12),
                c.risk_level
            );
        }
    }
    println!("╚════╧══════════════════════════╧══════════════╧══════════════╝");
    println!(
        "threshold={:?} telemetry={} ai={}",
        session.default_threshold, session.telemetry_enabled, session.ai_enabled
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
    let platform = &ctx.runtime.platform;
    let signals = ThresholdSignals::from_platform(
        &format!("{:?}", platform.arch),
        &format!("{:?}", platform.os),
        platform.logical_cpus,
        platform.backend,
    );
    let preview = ctx
        .runtime
        .loom
        .preview_card(card_id, Some(&signals))?;
    println!(
        "preview {} title={} caps={} outcome={} confirm={}",
        preview.card_id,
        preview.title,
        preview.cap_summary,
        preview.outcome.as_str(),
        preview.requires_confirmation
    );
    if preview.requires_confirmation {
        println!("run with: r {card_id} --confirm  (or index with --confirm in TUI)");
    }
    Ok(())
}

fn run_card(ctx: &mut BuiltinContext<'_>, card_id: &str, confirmed: bool) -> Result<()> {
    let signals =
        intentos_utilities::LoomStore::threshold_signals(&ctx.runtime.platform);
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