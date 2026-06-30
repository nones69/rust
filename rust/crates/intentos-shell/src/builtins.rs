//! Native shell builtins — tier-2 command implementations.

use crate::parser::ParsedLine;
use crate::tier::OsTier;
use anyhow::{Context, Result};
use intentos_bench::{run_bench, run_markets_latency_bench};
use intentos_kernel::{Handle, Intent, SyscallOp, SyscallRequest, TrustAnchor, wall_ms};
use intentos_utilities::{
    AiGateway, BankingAssessor, BankingMapper, CompatibilityMatrix, EnterpriseHardeningAssessor,
    EnterpriseMapper, HealthcareAssessor, HealthcareMapper, IotAssessor, IotMapper, MarketsAssessor,
    MarketsMapper, MarketDeploymentReporter, MigrationAssessor, OsRuntime, PublicSafetyAssessor,
    PublicSafetyMapper, RollbackCheckpoint, SysTools,
};
use std::sync::Arc;

pub struct BuiltinState {
    pub actor: String,
    pub last_handle: Option<Handle>,
}

pub struct BuiltinContext<'a> {
    pub runtime: &'a Arc<OsRuntime>,
    pub state: &'a mut BuiltinState,
}

impl BuiltinContext<'_> {
    pub fn status(&self) -> Result<()> {
        println!(
            "{}",
            SysTools::kernel_report(&self.runtime.kernel(), &self.runtime.platform)
        );
        Ok(())
    }

    pub fn hal(&self) -> Result<()> {
        let p = &self.runtime.platform;
        println!(
            "hal backend={} arch={:?} os={:?} cpus={} host={}",
            p.backend, p.arch, p.os, p.logical_cpus, p.hostname
        );
        Ok(())
    }

    pub fn audit(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("tail");
        match sub {
            "tail" => {
                let redact = parsed.args.iter().any(|a| *a == "--redact");
                let n: usize = parsed
                    .args
                    .iter()
                    .skip(1)
                    .find(|a| **a != "--redact")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);
                for entry in self.runtime.audit.tail(n)? {
                    println!(
                        "{}",
                        intentos_audit::AuditLog::format_entry(&entry, redact)
                    );
                }
                let ok = self.runtime.audit.verify_chain()?;
                let total = self.runtime.audit.len()?;
                println!(
                    "chain_ok={ok} tail={n} total={total} redact={redact} head={}",
                    self.runtime.audit.head_hash()?
                );
            }
            "verify" => {
                let ok = self.runtime.audit.verify_chain()?;
                println!("chain_ok={ok} head={}", self.runtime.audit.head_hash()?);
            }
            other => anyhow::bail!("usage: audit tail [n] [--redact] | verify (got: {other})"),
        }
        Ok(())
    }

    pub fn telemetry_status(&self) -> Result<()> {
        let enabled = self.runtime.loom.is_telemetry_enabled();
        println!(
            "telemetry_enabled={enabled} (opt-in only — run `telemetry enable` to allow outbound analytics)"
        );
        Ok(())
    }

    pub fn telemetry_enable(&self) -> Result<()> {
        self.runtime.loom.set_telemetry_enabled(true)?;
        let _ = self.runtime.audit.record(
            intentos_audit::AuditEventKind::TelemetryEnabled,
            &self.state.actor,
            "telemetry opt-in accepted for active profile".to_string(),
        );
        println!("telemetry enabled (opt-in recorded in audit)");
        Ok(())
    }

    pub fn posture_status(&self) -> Result<()> {
        use intentos_utilities::{DevicePosture, LoomStore};
        let posture = DevicePosture::probe();
        let signals = LoomStore::threshold_signals(&self.runtime.platform);
        println!(
            "posture dev={} secure_boot={} biometric={} screen_lock={} trust_score={}",
            posture.developer_mode,
            posture.secure_boot_attested,
            posture.biometric_available,
            posture.screen_lock_enabled,
            posture.trust_score()
        );
        println!("{}", serde_json::to_string_pretty(&signals)?);
        Ok(())
    }

    pub fn telemetry_disable(&self) -> Result<()> {
        self.runtime.loom.set_telemetry_enabled(false)?;
        let _ = self.runtime.audit.record(
            intentos_audit::AuditEventKind::TelemetryDisabled,
            &self.state.actor,
            "telemetry disabled for active profile".to_string(),
        );
        println!("telemetry disabled");
        Ok(())
    }

    pub fn recognize(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let text = parsed.rest_from(0);
        if text.is_empty() {
            anyhow::bail!("usage: recognize <natural language or command>");
        }
        let out = self.runtime.kernel().recognize(&text);
        let intent = out.clone().into_intent(&self.state.actor);
        let decision = self.runtime.kernel().submit_intent(intent);
        println!(
            "recognizer={} resource={} action={} conf={:.2}",
            self.runtime.kernel().recognizer_name(),
            out.resource,
            out.action,
            out.confidence
        );
        println!(
            "policy: allowed={} ttl={}ms uses={} — {}",
            decision.allowed, decision.ttl_ms, decision.max_uses, decision.reason
        );
        Ok(())
    }

    pub fn migrate_assess(&self) -> Result<()> {
        let report = MigrationAssessor::assess(&self.runtime.platform);
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    pub fn market(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");
        match sub {
            "status" => {
                let report = MarketDeploymentReporter::status(
                    &self.runtime.platform,
                    &self.runtime.audit,
                    &self.runtime.identity,
                );
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            other => anyhow::bail!("usage: market status (got: {other})"),
        }
        Ok(())
    }

    pub fn identity(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("whoami");
        let bridge = &self.runtime.identity;
        match sub {
            "whoami" => {
                let p = bridge.whoami();
                println!(
                    "backend={:?} actor={} upn={} groups={} trust={}",
                    p.backend,
                    bridge.actor_id(&p),
                    p.upn,
                    p.groups.join(","),
                    bridge.trust_hint(&p)
                );
                self.state.actor = bridge.actor_id(&p);
                println!("shell actor set to {}", self.state.actor);
            }
            "lookup" => {
                let user = parsed
                    .arg(1)
                    .context("usage: identity lookup <username>")?;
                let p = bridge
                    .lookup(user)
                    .with_context(|| format!("principal not found in stub directory: {user}"))?;
                println!(
                    "backend={:?} actor={} upn={} groups={} trust={}",
                    p.backend,
                    bridge.actor_id(&p),
                    p.upn,
                    p.groups.join(","),
                    bridge.trust_hint(&p)
                );
            }
            "domain" => {
                println!(
                    "domain={} backend={:?}",
                    bridge.domain(),
                    bridge.backend()
                );
            }
            other => anyhow::bail!("usage: identity whoami | lookup <user> | domain (got: {other})"),
        }
        Ok(())
    }

    pub fn banking(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("banking supported operations:");
            for op in BankingMapper::SUPPORTED {
                println!("  {op}");
            }
            return Ok(());
        }
        if sub == "assess" {
            let report = BankingAssessor::assess(&self.runtime.platform);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!("usage: banking list | assess | <payment-operation>");
        }
        let intent = BankingMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
            .context("unknown banking operation")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "payment {}/{} allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn iot(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("iot supported operations:");
            for op in IotMapper::SUPPORTED {
                println!("  {op}");
            }
            return Ok(());
        }
        if sub == "assess" {
            let report = IotAssessor::assess(&self.runtime.platform);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!("usage: iot list | assess | <device-operation>");
        }
        let intent = IotMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
            .context("unknown iot operation")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "device {}/{} allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn markets(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("financial markets supported operations:");
            for op in MarketsMapper::SUPPORTED {
                println!("  {op}");
            }
            return Ok(());
        }
        if sub == "assess" {
            let report = MarketsAssessor::assess(&self.runtime.platform);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        if sub == "bench" {
            let iterations: usize = parsed.arg(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);
            let report = run_markets_latency_bench(iterations);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!("usage: markets list | assess | bench [iterations] | <trading-operation>");
        }
        let intent = MarketsMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
            .context("unknown financial markets operation")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "trading {}/{} allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn public_safety(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("public safety supported operations:");
            for op in PublicSafetyMapper::SUPPORTED {
                println!("  {op}");
            }
            return Ok(());
        }
        if sub == "assess" {
            let report = PublicSafetyAssessor::assess(&self.runtime.platform);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!("usage: safety list | assess | <mission-operation>");
        }
        let intent =
            PublicSafetyMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
                .context("unknown public safety operation")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "mission {}/{} allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn healthcare(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("healthcare supported operations:");
            for op in HealthcareMapper::SUPPORTED {
                println!("  {op}");
            }
            return Ok(());
        }
        if sub == "assess" {
            let report = HealthcareAssessor::assess_with_audit(
                &self.runtime.platform,
                Some(&self.runtime.audit),
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!("usage: healthcare list | assess | <fhir-operation>");
        }
        let intent =
            HealthcareMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
                .context("unknown healthcare operation")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "clinical {}/{} allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn enterprise(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "list" {
            println!("enterprise supported commands:");
            for c in EnterpriseMapper::SUPPORTED {
                println!("  {c}");
            }
            return Ok(());
        }
        if sub == "compat" {
            let report = CompatibilityMatrix::run_default();
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        if sub == "harden" {
            let report = EnterpriseHardeningAssessor::assess(
                &self.runtime.platform,
                &self.runtime.audit,
                &self.runtime.identity,
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        if sub == "rollback" {
            let label = parsed
                .arg(1)
                .context("usage: enterprise rollback <label> [snapshot]")?;
            let snapshot = parsed.arg(2).unwrap_or("manual-checkpoint");
            let hash = RollbackCheckpoint::record(
                &self.runtime.audit,
                &self.state.actor,
                label,
                snapshot,
            )?;
            println!("rollback checkpoint recorded label={label} hash={hash}");
            return Ok(());
        }

        let cmd = parsed.rest_from(0);
        if cmd.is_empty() {
            anyhow::bail!(
                "usage: enterprise list | compat | harden | rollback <label> | <powershell|bash|cmd command>"
            );
        }
        let intent = EnterpriseMapper::map_and_audit(&cmd, &self.state.actor, &self.runtime.audit)
            .context("no enterprise mapping for command")?;
        let decision = self.runtime.kernel().submit_intent(intent.clone());
        println!(
            "mapped {}/{} policy allowed={} — {}",
            intent.resource, intent.action, decision.allowed, decision.reason
        );
        if decision.allowed {
            let handle = self
                .runtime
                .kernel()
                .intent_to_handle_confirmed(intent, true)?;
            self.state.last_handle = Some(handle);
            println!("handle=0x{:X}", handle.as_u64());
        }
        Ok(())
    }

    pub fn kernel_cmd(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("stats");
        match sub {
            "stats" => {
                let stats = self.runtime.kernel().stats();
                println!("{}", serde_json::to_string_pretty(&stats)?);
            }
            "revoke" => {
                let arg = parsed
                    .arg(1)
                    .context("usage: kernel revoke <jti|0xHANDLE>")?;
                let jti = if arg.starts_with("0x") || arg.starts_with("0X") {
                    let raw = u64::from_str_radix(&arg[2..], 16)
                        .context("invalid handle hex")?;
                    let handle = Handle::from_u64(raw);
                    self.runtime
                        .kernel()
                        .jti_for_handle(handle)
                        .context("no active capability for handle")?
                } else {
                    arg.to_string()
                };
                let fresh = self
                    .runtime
                    .kernel()
                    .revoke_jti(&jti, &self.state.actor);
                println!(
                    "revoked={} jti={jti}",
                    if fresh { "new" } else { "already" }
                );
            }
            other => anyhow::bail!("usage: kernel stats | revoke <jti|0xHANDLE> (got: {other})"),
        }
        Ok(())
    }

    pub fn bench(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("");
        if sub == "markets" {
            let iterations: usize = parsed.arg(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);
            let report = run_markets_latency_bench(iterations);
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        let report = run_bench();
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    pub fn ipdis(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let sub = parsed.arg(0).unwrap_or("status");

        if sub == "status" {
            match &self.runtime.ip_discrambler {
                Some(bridge) => println!(
                    "ip-discrambler=online root={}",
                    bridge.root().display()
                ),
                None => println!(
                    "ip-discrambler=offline (set INTENTOS_IP_DISCRAMBLER_ROOT or run from repo root)"
                ),
            }
            return Ok(());
        }

        let bridge = self
            .runtime
            .ip_discrambler
            .as_ref()
            .context("IP-Discrambler not available — install tools/ip-discrambler and set INTENTOS_IP_DISCRAMBLER_ROOT")?;

        match sub {
            "lookup" => {
                let ip = parsed
                    .arg(1)
                    .context("usage: ipdis lookup <ip>")?;
                let result = bridge.audit_lookup(ip, &self.state.actor, &self.runtime.audit)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            "subnet" => {
                let cidr = parsed
                    .arg(1)
                    .context("usage: ipdis subnet <cidr>")?;
                let summary = bridge.subnet_json(cidr)?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
            "policy" => {
                let ip = parsed
                    .arg(1)
                    .context("usage: ipdis policy <ip>")?;
                let verdict = bridge.policy_check(ip, &self.state.actor)?;
                println!(
                    "ip={} allowed={} threat={} — {}",
                    verdict.ip, verdict.allowed, verdict.threat_score, verdict.reason
                );
                if let Some(ref e) = verdict.enrichment {
                    println!(
                        "geo country={:?} org={:?} asn={:?}",
                        e.country, e.org, e.asn
                    );
                }
                if verdict.allowed {
                    let mut meta = std::collections::BTreeMap::new();
                    meta.insert("dest_ip".into(), ip.into());
                    meta.insert("threat_score".into(), verdict.threat_score.to_string());
                    let intent = Intent {
                        actor: self.state.actor.clone(),
                        resource: "network".into(),
                        action: "descramble".into(),
                        anchor: TrustAnchor::UiEvent,
                        timestamp_ms: wall_ms(),
                        metadata: meta,
                    };
                    let handle = self
                        .runtime
                        .kernel()
                        .intent_to_handle_confirmed(intent, true)?;
                    self.state.last_handle = Some(handle);
                    println!("network/descramble handle=0x{:X}", handle.as_u64());
                }
            }
            "serve" => {
                let host = parsed.arg(1).unwrap_or("127.0.0.1");
                let port: u16 = parsed
                    .arg(2)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8765);
                let child = bridge.serve(host, port)?;
                println!(
                    "IP-Discrambler REST API spawned pid={} http://{}:{}/lookup?ip=8.8.8.8",
                    child.id(),
                    host,
                    port
                );
            }
            other => anyhow::bail!(
                "usage: ipdis status | lookup <ip> | subnet <cidr> | policy <ip> | serve [host] [port] (got: {other})"
            ),
        }
        Ok(())
    }

    pub fn tier(&self) -> Result<()> {
        println!(
            "1 utilities  2 shell (active)  3 kernel\nactive tier: {} ({})",
            OsTier::Shell.number(),
            OsTier::Shell.name()
        );
        Ok(())
    }

    pub fn intent(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let (resource, action) = parse_pair(&parsed.args)?;
        let decision = self
            .runtime
            .kernel()
            .submit_intent(self.make_intent(resource, action));
        println!(
            "policy: allowed={} ttl={}ms uses={} — {}",
            decision.allowed, decision.ttl_ms, decision.max_uses, decision.reason
        );
        Ok(())
    }

    pub fn flow(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let (resource, action) = parse_pair(&parsed.args)?;
        let handle = self
            .runtime
            .kernel()
            .intent_to_handle_confirmed(self.make_intent(resource, action), true)?;
        self.state.last_handle = Some(handle);
        println!("flow ok  handle=0x{:X}", handle.as_u64());
        Ok(())
    }

    pub fn syscall(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let op = parsed
            .arg(0)
            .context("usage: syscall <read|write|list|infer> [target]")?;
        let handle = self
            .state
            .last_handle
            .context("no handle — run `flow` first")?;
        let target = parsed.arg(1).unwrap_or("").to_string();
        let result = self.runtime.kernel().syscall(
            handle,
            SyscallRequest {
                op: SyscallOp::parse(op),
                target,
                payload: vec![],
            },
        );
        println!("{result:?}");
        Ok(())
    }

    pub fn ls(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let path = parsed.arg(0).unwrap_or("/");
        let handle = self.ensure_dir_handle()?;
        let k = self.runtime.kernel();
        let names = {
            let rt = self.runtime.utilities.lock().unwrap();
            rt.vfs.list(&k, handle, path)?
        };
        for n in names {
            println!("{n}");
        }
        Ok(())
    }

    pub fn cat(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let path = parsed.arg(0).context("usage: cat <path>")?;
        let handle = self.ensure_file_read_handle()?;
        let k = self.runtime.kernel();
        let data = {
            let rt = self.runtime.utilities.lock().unwrap();
            rt.vfs.read(&k, handle, path)?
        };
        print!("{}", String::from_utf8_lossy(&data));
        if !data.ends_with(b"\n") {
            println!();
        }
        Ok(())
    }

    pub fn write(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        let path = parsed.arg(0).context("usage: write <path> <text...>")?;
        let text = parsed.rest_from(1);
        let handle = self.ensure_file_write_handle()?;
        let k = self.runtime.kernel();
        let n = {
            let mut rt = self.runtime.utilities.lock().unwrap();
            rt.vfs.write(&k, handle, path, text.as_bytes())?
        };
        println!("wrote {n} bytes");
        Ok(())
    }

    pub fn ai_status(&self) -> Result<()> {
        let enabled = self.runtime.loom.is_ai_enabled();
        println!(
            "ai_enabled={enabled} (run `ai enable` for this session profile)"
        );
        Ok(())
    }

    pub fn ai_enable(&self) -> Result<()> {
        self.runtime.loom.set_ai_enabled(true)?;
        let _ = self.runtime.audit.record(
            intentos_audit::AuditEventKind::AiEnabled,
            &self.state.actor,
            "ai gateway enabled for active profile".to_string(),
        );
        println!("ai enabled for this profile");
        Ok(())
    }

    pub fn ai_disable(&self) -> Result<()> {
        self.runtime.loom.set_ai_enabled(false)?;
        let _ = self.runtime.audit.record(
            intentos_audit::AuditEventKind::AiDisabled,
            &self.state.actor,
            "ai gateway disabled for active profile".to_string(),
        );
        println!("ai disabled for this profile");
        Ok(())
    }

    pub fn ai_infer(&mut self, parsed: &ParsedLine<'_>) -> Result<()> {
        if !self.runtime.loom.is_ai_enabled() {
            anyhow::bail!("ai gateway disabled — run `ai enable` first (privacy-by-default)");
        }
        let prompt = parsed.rest_from(1);
        if prompt.is_empty() {
            anyhow::bail!("usage: ai infer <prompt>");
        }
        let handle = self.ensure_ai_handle()?;
        let out = AiGateway::infer(&self.runtime.kernel(), handle, "intentos", &prompt)?;
        println!("{out}");
        Ok(())
    }

    pub fn lease(&self, parsed: &ParsedLine<'_>) -> Result<()> {
        let pid: u32 = parsed
            .arg(0)
            .and_then(|p| p.parse().ok())
            .unwrap_or(std::process::id());
        let lease = self.runtime.kernel().grant_lease(pid, 30_000);
        println!(
            "lease {} pid={} expires={}",
            lease.lease_id, lease.pid, lease.expires_at
        );
        Ok(())
    }

    fn make_intent(&self, resource: &str, action: &str) -> Intent {
        Intent {
            actor: self.state.actor.clone(),
            resource: resource.into(),
            action: action.into(),
            anchor: TrustAnchor::UiEvent,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        }
    }

    fn ensure_file_read_handle(&mut self) -> Result<Handle> {
        // Always mint a fresh single-use `file/read` capability. Reusing
        // `last_handle` is incorrect: after a `write`, the cached handle is an
        // exhausted `file/write` capability, so a `cat` would be denied
        // ("syscall Read not allowed for FileWrite" / "capability exhausted").
        let h = self
            .runtime
            .kernel()
            .intent_to_handle_confirmed(self.make_intent("file", "read"), true)?;
        self.state.last_handle = Some(h);
        Ok(h)
    }

    fn ensure_file_write_handle(&mut self) -> Result<Handle> {
        let h = self
            .runtime
            .kernel()
            .intent_to_handle_confirmed(self.make_intent("file", "write"), true)?;
        self.state.last_handle = Some(h);
        Ok(h)
    }

    fn ensure_dir_handle(&mut self) -> Result<Handle> {
        let h = self
            .runtime
            .kernel()
            .intent_to_handle_confirmed(self.make_intent("dir", "list"), true)?;
        self.state.last_handle = Some(h);
        Ok(h)
    }

    fn ensure_ai_handle(&mut self) -> Result<Handle> {
        let h = self
            .runtime
            .kernel()
            .intent_to_handle_confirmed(self.make_intent("ai", "infer"), true)?;
        self.state.last_handle = Some(h);
        Ok(h)
    }
}

fn parse_pair<'a>(parts: &'a [&'a str]) -> Result<(&'a str, &'a str)> {
    if parts.len() < 2 {
        anyhow::bail!("expected <resource> <action>");
    }
    Ok((parts[0], parts[1]))
}

pub fn help_text() -> &'static str {
    r#"
IntentOS shell — tier 2 (native, no RPC):

  tier                   Show tier numbering (1=utilities 2=shell 3=kernel)
  status                 Kernel stats + HAL probe
  field create|use|list  Field context management
  kb open|suggest|run|tui Kernel Bar — intent cards (tui = numbered picker)
  telemetry status|enable|disable  Outbound analytics opt-in (off by default)
  oobe status|run|reset|hook  First-run onboarding + platform bootstrap hooks
  posture                Device posture + Threshold signals (HAL probe)
  broker status|register|delegate  Intent Broker federation peers
  kernel stats           Kernel uptime, caps, leases, revocations (JSON)
  kernel revoke <jti>    Revoke capability token (or 0xHANDLE)
  intent <res> <act>     Evaluate policy
  flow <res> <act>       Mint token + register handle
  syscall <op> [target]  Direct kernel syscall
  ls [path]              List VFS (needs dir capability)
  cat <path>             Read VFS file
  write <path> <text>    Write VFS file
  ai status|enable|disable|infer  AI gateway (disabled until `ai enable`)
  loom export|import     Signed Loom session transfer between machines
  hal                    Show hardware abstraction probe
  audit tail [n] [--redact]|verify  Append-only audit trail (persisted locally)
  policy list|use        Personal vs enterprise policy packs
  kb preview <card_id>   Preview caps/ttl/risk before execution
  recognize <text>       Intent recognition (enterprise map / Ollama / stub)
  enterprise list        Show mapped enterprise commands
  enterprise compat      Run app compatibility matrix (pass/fail)
  enterprise <cmd>       Map Win32/Bash/PowerShell cmd to intent
  migrate assess         Enterprise migration readiness report
  market status          All-sector deployment status + Wave 1 hardening gates
  identity whoami        Resolve AD/LDAP principal + set actor
  identity lookup <user> Lookup principal (live LDAP or stub)
  identity domain        Show identity domain/backend config
  healthcare list        Show FHIR-shaped pilot operations
  healthcare assess      Healthcare pilot readiness (HIPAA blockers)
  healthcare <op>        Map clinical operation to intent
  safety list            Show CAD/CJIS-shaped pilot operations
  safety assess          Public safety pilot readiness (CJIS blockers)
  safety <op>            Map mission operation to intent
  banking list           Show PCI/EMV-shaped pilot operations
  banking assess         Banking/ATM pilot readiness (PCI-DSS blockers)
  banking <op>           Map payment operation to intent
  iot list               Show OTA/secure-boot pilot operations
  iot assess             IoT/embedded pilot readiness (IEC 62443 blockers)
  iot <op>               Map device operation to intent
  markets list           Show FIX/ITCH/OMS-shaped pilot operations
  markets assess         Financial markets pilot readiness (SEC/MiFID blockers)
  markets bench [n]      Pre-trade risk latency harness (default 10000 iterations)
  markets <op>           Map trading operation to intent
  bench                  Run Phase 1 boot/intent/syscall benchmarks
  bench markets [n]      Financial markets latency harness (risk P99 vs 250µs)
  enterprise harden      Phase 3 Wave 1 pilot exit gate assessment
  enterprise rollback    Record rollback checkpoint in audit chain
  ipdis status           Show IP-Discrambler bridge availability
  ipdis lookup <ip>      Enrich IP (geo, WHOIS, threat) via Python bridge
  ipdis subnet <cidr>    Analyze CIDR block
  ipdis policy <ip>      Kernel policy + enrichment; mint network/descramble handle
  ipdis serve [host] [port]  Spawn REST API (background process)
  lease [pid]            Grant background lease
  actor [name]           Show/set actor id
  exit                   End session
"#
}