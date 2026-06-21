use crate::builtins::{help_text, BuiltinContext, BuiltinState};
use crate::parser::ParsedLine;
use crate::tier::PROMPT;
use anyhow::{Context, Result};
use intentos_utilities::OsRuntime;
use std::io::{self, Write};
use std::sync::Arc;

pub struct ShellSession {
    runtime: Arc<OsRuntime>,
    state: BuiltinState,
}

impl ShellSession {
    pub fn new(runtime: Arc<OsRuntime>) -> Self {
        let actor = runtime.boot_actor();
        Self {
            runtime,
            state: BuiltinState {
                actor,
                last_handle: None,
            },
        }
    }

    pub fn actor(&self) -> &str {
        &self.state.actor
    }

    pub fn run_repl(&mut self) -> Result<()> {
        let stdin = io::stdin();
        loop {
            print!("{PROMPT}");
            io::stdout().flush()?;
            let mut line = String::new();
            if stdin.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match self.eval(line) {
                Ok(false) => {
                    println!("logout");
                    break;
                }
                Ok(true) => {}
                Err(e) => eprintln!("error: {:#}", e),
            }
        }
        Ok(())
    }

    pub fn eval(&mut self, line: &str) -> Result<bool> {
        let parsed = ParsedLine::parse(line).context("empty line")?;
        let mut ctx = BuiltinContext {
            runtime: &self.runtime,
            state: &mut self.state,
        };

        match parsed.command {
            "help" | "?" => {
                println!("{}", help_text());
                Ok(true)
            }
            "exit" | "quit" => Ok(false),
            "status" => {
                ctx.status()?;
                Ok(true)
            }
            "tier" | "tiers" => {
                ctx.tier()?;
                Ok(true)
            }
            "intent" => {
                ctx.intent(&parsed)?;
                Ok(true)
            }
            "flow" => {
                ctx.flow(&parsed)?;
                Ok(true)
            }
            "syscall" => {
                ctx.syscall(&parsed)?;
                Ok(true)
            }
            "ls" => {
                ctx.ls(&parsed)?;
                Ok(true)
            }
            "cat" => {
                ctx.cat(&parsed)?;
                Ok(true)
            }
            "write" => {
                ctx.write(&parsed)?;
                Ok(true)
            }
            "ai" => {
                if parsed.arg(0) != Some("infer") {
                    anyhow::bail!("usage: ai infer <prompt>");
                }
                ctx.ai_infer(&parsed)?;
                Ok(true)
            }
            "hal" => {
                ctx.hal()?;
                Ok(true)
            }
            "audit" => {
                ctx.audit(&parsed)?;
                Ok(true)
            }
            "recognize" => {
                ctx.recognize(&parsed)?;
                Ok(true)
            }
            "enterprise" | "ent" => {
                ctx.enterprise(&parsed)?;
                Ok(true)
            }
            "migrate" => {
                if parsed.arg(0) != Some("assess") {
                    anyhow::bail!("usage: migrate assess");
                }
                ctx.migrate_assess()?;
                Ok(true)
            }
            "identity" | "id" => {
                ctx.identity(&parsed)?;
                Ok(true)
            }
            "healthcare" | "hc" => {
                ctx.healthcare(&parsed)?;
                Ok(true)
            }
            "safety" | "psafe" => {
                ctx.public_safety(&parsed)?;
                Ok(true)
            }
            "banking" | "bank" | "atm" => {
                ctx.banking(&parsed)?;
                Ok(true)
            }
            "iot" | "embedded" => {
                ctx.iot(&parsed)?;
                Ok(true)
            }
            "markets" | "trading" | "exchange" | "fm" => {
                ctx.markets(&parsed)?;
                Ok(true)
            }
            "bench" => {
                ctx.bench()?;
                Ok(true)
            }
            "ipdis" | "ip" => {
                ctx.ipdis(&parsed)?;
                Ok(true)
            }
            "lease" => {
                ctx.lease(&parsed)?;
                Ok(true)
            }
            "actor" => {
                if !parsed.args.is_empty() {
                    ctx.state.actor = parsed.args.join(" ");
                }
                println!("actor={}", ctx.state.actor);
                Ok(true)
            }
            other => {
                eprintln!("unknown command: {other}. type `help`.");
                Ok(true)
            }
        }
    }
}