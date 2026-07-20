# Intent Kernel AI OS — What's Left to Finish

**Status date:** 2026-06-20  
**Repo:** `projects/intentkernel`  
**Source of truth:** This checklist + `docs/market_deployment_framework.md` + `docs/intent_kernel_ux_blueprint.md` + `roadmap/implementation_plan.md`

Legend: `[x]` done · `[~]` partial · `[ ]` not started

---

## Snapshot: Where We Are

| Area | Status | Notes |
|------|--------|-------|
| Architecture specs (thesis, UCCS, IKRL, IBPS, token RFC) | [x] | Published in `docs/` |
| Rust reference stack (capd, intentd, leasebroker, eventscope, SDK, sim) | [x] | Builds release on Windows |
| Ransomware immunity demo | [x] | `ransomware-demo` crate |
| Capability unit tests (core + crypto) | [x] | Full-flow + replay + policy tests |
| CI that runs `cargo test` on Rust stack | [~] | Workflows exist; need Rust job |
| Production PQC (liboqs / FIPS 204/203) | [ ] | Mocks only unless `--features oqs` |
| Linux seccomp / LSM enforcement | [~] | ptrace POC + seccomp scaffold |
| Windows VBS / named-pipe production path | [~] | Service wrapper; pipe is stub (use TCP) |
| Market vertical integrations (6 sectors) | [ ] | Framework documented; 0 adapters |
| Compliance certifications | [ ] | Mapping docs only |
| Native microkernel bare metal | [~] | C reference only |

**Bottom line:** Phase 1 foundation (capability runtime + demos) is largely done. Remaining work is (1) harden Phase 1, (2) ship Enterprise pilot, (3) sector adapters after that.

---

## Tier 0 — Strategic Alignment

| # | Task | Status |
|---|------|--------|
| 0.1 | Reconcile narrative: IKRL-first compatibility layer, native OS Year 2+ | [x] Documented in architecture + this file |
| 0.2 | Persist market deployment framework in repo | [x] `docs/market_deployment_framework.md` |
| 0.3 | Remaining-work checklist (this file) | [x] |
| 0.4 | Choose MVP vertical: **Enterprise Windows/Linux** | [x] Decision recorded |
| 0.5 | Stakeholder answers (pricing, open-core, edge vs cloud) | [~] Recommendations in framework doc; need founder sign-off |

---

## Tier 1 — Phase 1 Foundation Finish (Months 1–3)

### Must finish before any market pilot

| # | Task | Status | Owner path |
|---|------|--------|------------|
| 1.1 | Integration tests: full capability flow | [x] | `intentkernel-core` tests |
| 1.2 | Tests: replay, tamper, policy deny, revoke | [x] | `intentkernel-core` tests |
| 1.3 | Crypto wire-size + AES/ML-DSA/ML-KEM unit tests | [x] | `intentkernel-crypto` tests |
| 1.4 | CI: `cargo test -p intentkernel-core -p intentkernel-crypto` + release build | [x] | `.github/workflows/rust.yml` |
| 1.5 | Replace PQC mocks with certified liboqs path validated in CI (optional job) | [ ] | `intentkernel-crypto` feature `oqs` |
| 1.6 | Linux seccomp user-notification supervisor (not just ptrace) | [ ] | `ikrl-linux` |
| 1.7 | Windows named-pipe transport (today: TCP only) | [ ] | `ikrl-transport` |
| 1.8 | Rule-based intent translator (PowerShell/Bash → capability request) | [ ] | new crate or `intentd` |
| 1.9 | Benchmarks vs targets (token validation &lt;1ms; document boot/memory) | [ ] | `ikrl-bench` + CI artifact |
| 1.10 | TPM/TEE design note for `capd` key storage | [ ] | `docs/` |
| 1.11 | Immutable audit log export API | [ ] | `intentd` / platform |
| 1.12 | Daemon integration test (start stack, `ikrl-cli full-flow`, tear down) | [ ] | new `tests/integration` or script |

---

## Tier 2 — Enterprise Pilot (Months 4–8) — **next revenue path**

| # | Task | Status |
|---|------|--------|
| 2.1 | Win32/Win64 syscall mapping table (critical compatibility layer) | [ ] |
| 2.2 | AD/LDAP identity federation bridge | [ ] |
| 2.3 | PowerShell intent translator | [ ] |
| 2.4 | Bash intent translator | [ ] |
| 2.5 | GPO → capability policy translator | [ ] |
| 2.6 | Docker/Podman OCI hooks via eventscope | [ ] |
| 2.7 | Legacy OS inventory scanner (migration matrix automation) | [ ] |
| 2.8 | Migration rollback toolkit | [ ] |
| 2.9 | Fleet management console (extend `platform/ui`) | [ ] |
| 2.10 | Isolated-network pilot installer package | [ ] |

---

## Tier 3 — Sector Pilots (sequence after enterprise)

### Healthcare
| Component | Status |
|-----------|--------|
| Patient data encryption module | [ ] |
| DICOM/PACS integration | [ ] |
| Medical device driver framework | [ ] |
| Clinical decision support API | [ ] |
| Telemedicine optimization layer | [ ] |
| Pharmacy management bridge | [ ] |
| Lab results automation | [ ] |
| Emergency alert system | [ ] |
| HIPAA audit trail | [ ] |
| Offline surgical-suite mode | [ ] |

### Banking / ATM
| Component | Status |
|-----------|--------|
| EMV/PCI transaction processing | [ ] |
| ATM driver abstraction (Diebold/NCR) | [ ] |
| Fraud detection ML engine | [ ] |
| SWIFT/ACH integration | [ ] |
| AML module | [ ] |
| Biometric auth bridge | [ ] |
| Remote monitoring/diagnostics | [ ] |
| Compliance reporting automation | [ ] |
| Backup/DR geographic redundancy | [ ] |
| PCI-DSS v4.0 control mapping | [ ] |

### Public safety
| Component | Status |
|-----------|--------|
| 911/Dispatch (NG911) API | [ ] |
| NCIC/NLETS bridge | [ ] |
| Body camera / evidence CoC | [ ] |
| Vehicle telemetry | [ ] |
| GIS automation | [ ] |
| Radio interoperability (P25/DMR) | [ ] |
| Facial recognition gateway | [ ] |
| Real-time crime analytics | [ ] |
| Mutual aid coordination | [ ] |
| CJIS compliance pack | [ ] |
| 99.999% HA + air-gap profile | [ ] |

### Financial markets
| Component | Status |
|-----------|--------|
| FIX/ITCH feed handler | [ ] |
| OMS bridge | [ ] |
| FPGA acceleration framework | [ ] |
| Risk / kill-switch engine | [ ] |
| Latency monitoring (PTP) | [ ] |
| Smart order routing | [ ] |
| Regulatory reporting (CAT/MiFID II) | [ ] |
| Market surveillance | [ ] |
| Backtesting engine | [ ] |
| Crypto exchange bridge | [ ] |

### Electronics / IoT
| Component | Status |
|-----------|--------|
| FreeRTOS/Zephyr bridge | [ ] |
| Embedded ML inference | [ ] |
| Secure boot chain | [ ] |
| OTA update + rollback | [ ] |
| HAL vendor SDK matrix | [ ] |
| Device identity (X.509) | [ ] |
| Power management | [ ] |
| Sensor fusion | [ ] |
| Mesh networking | [ ] |
| Edge-cloud sync (MQTT/CoAP) | [ ] |
| &lt;1MB footprint profile | [ ] |

---

## Tier 4 — Compliance & Production Hardening

| # | Task | Status |
|---|------|--------|
| 4.1 | ISO 27001 control mapping | [ ] |
| 4.2 | SOC 2 Type II readiness | [ ] |
| 4.3 | FedRAMP boundary (if federal) | [ ] |
| 4.4 | GDPR/CCPA data handling review | [ ] |
| 4.5 | Zero-trust continuous verification runtime | [ ] |
| 4.6 | Post-quantum production libraries only (no mock path in release) | [ ] |
| 4.7 | HA / multi-broker federation for 99.999% | [ ] |
| 4.8 | Observability: metrics, traces, structured logs | [ ] |

---

## Tier 5 — Ecosystem (Year 2+)

| # | Task | Status |
|---|------|--------|
| 5.1 | Third-party SDK marketplace | [ ] |
| 5.2 | Industry plugin framework | [ ] |
| 5.3 | Native microkernel bare-metal boot (&lt;3s) | [ ] |
| 5.4 | SoC reference design | [ ] |
| 5.5 | Global LTS channel | [ ] |
| 5.6 | Federated learning for intent models | [ ] |
| 5.7 | Explainable AI (XAI) for regulated decisions | [ ] |

---

## Performance Benchmark Gate (not yet green)

| Metric | Target | Status |
|--------|--------|--------|
| Boot to intent-ready | &lt; 3s | [ ] not measured |
| Intent recognition latency | &lt; 50ms | [ ] NLP path not built |
| Syscall overhead | &lt; 100ns | [ ] not measured |
| Token validation | &lt; 1ms (internal) | [ ] `ikrl-bench` exists; no CI gate |
| Uptime SLA | 99.999% | [ ] no HA design shipped |
| Base memory | &lt; 256MB | [ ] not profiled |

---

## Recommended Finish Order (next 90 days)

### Sprint A (now → 2 weeks)
1. CI Rust job (build + test)
2. Daemon integration test script
3. `ikrl-bench` baseline numbers checked into `docs/benchmarks.md`
4. TPM/TEE design note

### Sprint B (weeks 3–6)
5. Linux seccomp supervisor
6. Windows named-pipe transport
7. Rule-based PowerShell/Bash intent translator v0
8. Audit log export

### Sprint C (weeks 7–12)
9. Enterprise pilot kit (installer + fleet UI)
10. AD/LDAP bridge prototype
11. First customer isolated-network pilot

**Do not start** healthcare / CJIS / trading / ATM drivers until Sprint C pilot path is real.

---

## How to Verify Current Foundation

```powershell
cd C:\Users\Dizzle\projects\intentkernel\rust
cargo test -p intentkernel-core -p intentkernel-crypto
cargo build --release
cargo run -p ikrl-sim --release
cargo run -p ransomware-demo --release
```

Expected: all tests pass; sim completes full flow; ransomware demo reports **0 bytes encrypted** unauthorized.
