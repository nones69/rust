//! # intentos-bench — Latency benchmarks
//!
//! Measures boot, syscall, and intent-to-handle paths against Market
//! Deployment Framework targets (documented in `docs/market_deployment_framework.md`).

mod markets;

pub use markets::{
    run_markets_latency_bench, MarketsLatencyPass, MarketsLatencyReport, MarketsLatencyTargets,
    LatencyStats, TARGET_CLOCK_DRIFT_NS, TARGET_RISK_PRECHECK_P99_US,
};

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_hal::native_hal;
use intentos_kernel::{
    Intent, Kernel, KernelConfig, SyscallOp, SyscallRequest, TrustAnchor, wall_ms,
};
use intentos_utilities::OsRuntime;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Documented Phase 1 latency targets (milliseconds).
pub const TARGET_BOOT_MS: u64 = 250;
pub const TARGET_INTENT_TO_HANDLE_MS: u64 = 5;
pub const TARGET_SYSCALL_MS: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub boot_ms: u64,
    pub intent_to_handle_ms: u64,
    pub syscall_ms: u64,
    pub hal_backend: String,
    pub audit_entries: usize,
    pub targets: BenchTargets,
    pub pass: BenchPass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchTargets {
    pub boot_ms: u64,
    pub intent_to_handle_ms: u64,
    pub syscall_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchPass {
    pub boot: bool,
    pub intent_to_handle: bool,
    pub syscall: bool,
}

pub fn run_bench() -> BenchReport {
    let hal = native_hal();
    let platform = hal.probe();

    let t0 = Instant::now();
    let audit = Arc::new(AuditLog::new());
    let runtime = OsRuntime::boot_with_audit(Arc::clone(&audit)).expect("boot");
    let boot_ms = t0.elapsed().as_millis() as u64;

    let kernel = runtime.kernel();
    let intent = Intent {
        actor: "bench".into(),
        resource: "file".into(),
        action: "read".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };

    let t1 = Instant::now();
    let handle = kernel.intent_to_handle(intent).expect("handle");
    let intent_to_handle_ms = t1.elapsed().as_millis() as u64;

    let t2 = Instant::now();
    let _ = kernel.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Read,
            target: "bench.txt".into(),
            payload: vec![],
        },
    );
    let syscall_ms = t2.elapsed().as_millis() as u64;

    let _ = audit.record(
        AuditEventKind::Bench,
        "bench",
        format!(
            "boot={boot_ms}ms intent={intent_to_handle_ms}ms syscall={syscall_ms}ms"
        ),
    );

    let pass = BenchPass {
        boot: boot_ms <= TARGET_BOOT_MS,
        intent_to_handle: intent_to_handle_ms <= TARGET_INTENT_TO_HANDLE_MS,
        syscall: syscall_ms <= TARGET_SYSCALL_MS,
    };

    BenchReport {
        boot_ms,
        intent_to_handle_ms,
        syscall_ms,
        hal_backend: platform.backend.to_string(),
        audit_entries: audit.len().unwrap_or(0),
        targets: BenchTargets {
            boot_ms: TARGET_BOOT_MS,
            intent_to_handle_ms: TARGET_INTENT_TO_HANDLE_MS,
            syscall_ms: TARGET_SYSCALL_MS,
        },
        pass,
    }
}

/// Kernel-only micro-bench (no full OsRuntime) for unit tests.
pub fn kernel_micro_bench() -> (u64, u64) {
    let k = Kernel::boot_with(KernelConfig::default()).unwrap();
    let intent = Intent {
        actor: "bench".into(),
        resource: "file".into(),
        action: "read".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    };
    let t0 = Instant::now();
    let handle = k.intent_to_handle(intent).unwrap();
    let intent_ms = t0.elapsed().as_millis() as u64;

    let t1 = Instant::now();
    let _ = k.syscall(
        handle,
        SyscallRequest {
            op: SyscallOp::Read,
            target: "x".into(),
            payload: vec![],
        },
    );
    let syscall_ms = t1.elapsed().as_millis() as u64;
    (intent_ms, syscall_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_runs_without_panic() {
        let report = run_bench();
        assert!(report.boot_ms < 10_000);
    }
}