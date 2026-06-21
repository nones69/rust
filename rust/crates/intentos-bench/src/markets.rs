//! Financial markets latency harness — measures pre-trade risk and order paths.
//!
//! Targets from `docs/market_deployment_framework.md` (Wave 4):
//! - Pre-trade risk check: ≤250µs P99
//! - Clock sync drift: ≤1µs (stub probe until PTP module ships)

use intentos_audit::{AuditEventKind, AuditLog};
use intentos_kernel::{Kernel, KernelConfig};
use intentos_utilities::MarketsMapper;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Documented pre-trade risk latency target (microseconds, P99).
pub const TARGET_RISK_PRECHECK_P99_US: u64 = 250;

/// Documented clock drift target (nanoseconds) — stub until PTP ships.
pub const TARGET_CLOCK_DRIFT_NS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub samples: usize,
    pub mean_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_us: f64,
    pub p99_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketsLatencyTargets {
    pub risk_precheck_p99_us: u64,
    pub clock_drift_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketsLatencyPass {
    pub risk_precheck: bool,
    pub clock_drift_stub: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketsLatencyReport {
    pub sector: String,
    pub iterations: usize,
    pub risk_precheck: LatencyStats,
    pub fix_order_submit: LatencyStats,
    pub clock_drift_stub_ns: u64,
    pub targets: MarketsLatencyTargets,
    pub pass: MarketsLatencyPass,
    pub notes: Vec<String>,
}

pub fn run_markets_latency_bench(iterations: usize) -> MarketsLatencyReport {
    let iterations = iterations.max(100);
    let kernel = Kernel::boot_with(KernelConfig::default()).expect("kernel boot");
    let audit = Arc::new(AuditLog::new());

    let risk_precheck = bench_risk_precheck(&kernel, iterations);
    let fix_order_submit = bench_fix_order_submit(&kernel, iterations);
    let clock_drift_stub_ns = measure_clock_drift_stub();

    let pass = MarketsLatencyPass {
        risk_precheck: risk_precheck.p99_us <= TARGET_RISK_PRECHECK_P99_US as f64,
        clock_drift_stub: clock_drift_stub_ns <= TARGET_CLOCK_DRIFT_NS,
    };

    let _ = audit.record(
        AuditEventKind::Bench,
        "markets",
        format!(
            "risk_p99_us={:.3} fix_p99_ns={} clock_stub_ns={}",
            risk_precheck.p99_us, fix_order_submit.p99_ns, clock_drift_stub_ns
        ),
    );

    let mut notes = vec![
        "Prototype harness measures in-process map + policy submit only (not live FIX/OMS).".into(),
        "Clock drift uses back-to-back Instant delta stub until PTP/NTP module ships.".into(),
    ];
    if !pass.risk_precheck {
        notes.push(format!(
            "risk P99 {:.3}µs exceeds target {}µs — expected until kernel-bypass path ships",
            risk_precheck.p99_us, TARGET_RISK_PRECHECK_P99_US
        ));
    }

    MarketsLatencyReport {
        sector: "financial_markets".into(),
        iterations,
        risk_precheck,
        fix_order_submit,
        clock_drift_stub_ns,
        targets: MarketsLatencyTargets {
            risk_precheck_p99_us: TARGET_RISK_PRECHECK_P99_US,
            clock_drift_ns: TARGET_CLOCK_DRIFT_NS,
        },
        pass,
        notes,
    }
}

fn bench_risk_precheck(kernel: &Kernel, iterations: usize) -> LatencyStats {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let mapped = MarketsMapper::map("Risk.precheck").expect("map");
        let intent = MarketsMapper::to_intent(&mapped, "bench-trader");
        let _ = kernel.submit_intent(intent);
        samples.push(t0.elapsed().as_nanos() as u64);
    }
    summarize(&samples)
}

fn bench_fix_order_submit(kernel: &Kernel, iterations: usize) -> LatencyStats {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let mapped = MarketsMapper::map("FIX.order").expect("map");
        let intent = MarketsMapper::to_intent(&mapped, "bench-trader");
        let _ = kernel.submit_intent(intent);
        samples.push(t0.elapsed().as_nanos() as u64);
    }
    summarize(&samples)
}

fn measure_clock_drift_stub() -> u64 {
    let t0 = Instant::now();
    let t1 = Instant::now();
    t1.duration_since(t0).as_nanos() as u64
}

fn summarize(samples: &[u64]) -> LatencyStats {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let sum: u64 = sorted.iter().sum();
    let mean_ns = sum / n as u64;
    LatencyStats {
        samples: n,
        mean_ns,
        p50_ns: percentile(&sorted, 50.0),
        p95_ns: percentile(&sorted, 95.0),
        p99_ns: percentile(&sorted, 99.0),
        min_ns: sorted[0],
        max_ns: sorted[n - 1],
        mean_us: mean_ns as f64 / 1_000.0,
        p99_us: percentile(&sorted, 99.0) as f64 / 1_000.0,
    }
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markets_latency_bench_runs() {
        let report = run_markets_latency_bench(200);
        assert_eq!(report.sector, "financial_markets");
        assert_eq!(report.risk_precheck.samples, 200);
        assert!(report.risk_precheck.max_ns > 0);
    }
}