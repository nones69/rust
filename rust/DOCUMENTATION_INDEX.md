# Rust Workspace Documentation Index

Welcome! This directory contains comprehensive analysis and mapping of all Rust crates in the IntentOS + IKRL project.

---

## 📚 Documentation Files

### 1. **CRATE_MAP.md** (Main Reference)
   - **Purpose:** Complete inventory of all 28 Rust crates
   - **Contents:**
     - Architecture overview
     - Layer-by-layer crate descriptions
     - IntentOS tier-based architecture (T1/T2/T3)
     - IKRL distributed daemon system
     - Full dependency descriptions
     - Crate matrix with metadata
   - **Best For:** Understanding what each crate does and how they relate
   - **Size:** ~20 KB

### 2. **DEPENDENCY_GRAPH.md** (Visual Reference)
   - **Purpose:** Dependency relationships visualized with Mermaid diagrams
   - **Contents:**
     - Foundation layer (no dependencies)
     - Core types & protocol layer
     - IntentOS system flows
     - IKRL platform, daemons, services
     - Full integrated dependency graph
     - Critical dependency paths
     - Dependency statistics & color legend
   - **Best For:** Visual understanding of how systems connect
   - **Size:** ~13 KB
   - **Note:** Render in VS Code with Markdown Preview Mermaid extension

### 3. **ARCHITECTURE_GUIDE.md** (Quick Reference)
   - **Purpose:** Quick lookup guide and design principles
   - **Contents:**
     - Executive summary
     - Two-system architecture overview
     - Crate tables by layer/function
     - Critical dependency paths (text format)
     - Security architecture
     - Integration points
     - Build commands
     - Design principles
   - **Best For:** Getting oriented quickly, understanding guidelines
   - **Size:** ~11 KB

### 4. **README.md** (Project Overview)
   - **Purpose:** High-level project goals and structure
   - **Contents:** Project vision and top-level organization
   - **Best For:** Understanding project mission

---

## 🎯 Quick Navigation

### I want to understand...

| Question | Document | Section |
|----------|----------|---------|
| **What is IntentOS?** | ARCHITECTURE_GUIDE.md | Two-System Architecture → IntentOS |
| **What is IKRL?** | ARCHITECTURE_GUIDE.md | Two-System Architecture → IKRL |
| **All crates & purposes** | CRATE_MAP.md | Crate Hierarchy Layers + Crate Matrix |
| **How crates depend on each other** | DEPENDENCY_GRAPH.md | Full Dependency Graph |
| **What are the layers?** | CRATE_MAP.md | Crate Hierarchy Layers |
| **How IntentOS boots** | ARCHITECTURE_GUIDE.md | IntentOS: Monolithic Single Binary |
| **How IKRL initializes** | ARCHITECTURE_GUIDE.md | IKRL: Distributed Daemon System |
| **Cryptography strategy** | CRATE_MAP.md | Cross-Cutting Concerns → Cryptography |
| **Audit & logging** | CRATE_MAP.md | Cross-Cutting Concerns → Audit & Logging |
| **Platform abstraction** | CRATE_MAP.md | Cross-Cutting Concerns → Platform Abstraction |
| **Critical code paths** | ARCHITECTURE_GUIDE.md | Critical Dependency Paths |
| **Build commands** | ARCHITECTURE_GUIDE.md | Build & Test |
| **Adding a new crate** | ARCHITECTURE_GUIDE.md | When Adding a New Crate |

---

## 🗂️ Crate Inventory at a Glance

### Foundation Layer (3 crates)
```
intentkernel-crypto    — Post-quantum + classical crypto
intentos-audit         — Immutable hash-chained audit log
intentos-hal           — Hardware abstraction layer
```

### Core Layer (3 crates)
```
intentkernel-core      — Protocol types & session state
intentkernel-os        — OS architecture descriptor
ikrl-transport         — Async IPC/RPC layer
```

### IntentOS System (4 crates)
```
intentos               — Single-binary OS (main app)
intentos-kernel        — Tier-3: policy, tokens, capabilities
intentos-utilities     — Tier-1: VFS, AI, platform tools
intentos-shell         — Tier-2: interactive REPL
intentos-bench         — Benchmark harness
```

### IKRL Platform (3 crates)
```
ikrl-init              — Boot supervisor
ikrl-windows           — Windows service adapter
ikrl-linux             — Linux platform adapter
```

### IKRL Daemons (4 crates)
```
intentd                — Intent dispatch daemon
capd                   — Capability daemon
leasebroker            — Lease management daemon
eventscope             — Event auditing daemon
```

### IKRL Services (6 crates)
```
ikrl-cli               — Command-line interface
ikrl-shell             — Interactive REPL
ikrl-bridge            — Protocol bridge
ikrl-ai                — AI/LLM gateway
ikrl-fs                — File system verification
ikrl-sdk               — Public SDK (FFI)
```

### IKRL Testing (3 crates)
```
ikrl-bench             — Protocol benchmarks
ikrl-sim               — Protocol simulation
ikrl-federation        — Peer discovery (mDNS)
```

### Utilities & Demo (1 crate)
```
ransomware-demo        — Security demonstration
```

---

## 🔍 Key Statistics

| Metric | Value |
|--------|-------|
| **Total Crates** | 28 |
| **Binaries** | 18 |
| **Libraries** | 15 |
| **Hybrid (bin+lib)** | 5 |
| **Max Dependency Depth** | 4 layers |
| **Foundation Crates** | 3 (no internal deps) |
| **Platform-Specific** | 3 (Windows/Linux adapters) |
| **Cross-Platform** | 25 |

---

## 🏛️ Architecture Principles

1. **Layered Design:** Foundation → Core → Systems → Application
2. **Clean Dependencies:** Each layer only depends on layers below
3. **Single Point of Truth:** Shared crypto, audit, HAL (zero duplication)
4. **Post-Quantum Ready:** Cryptography abstractions for algorithm agility
5. **Audit Trail Guarantees:** Hash-chained immutable events
6. **Cross-Platform:** Windows/Linux, x86_64/ARM64
7. **Dual Mode:** Monolithic (IntentOS) + Distributed (IKRL)
8. **Configuration-Driven:** Boot-time setup without recompilation

---

## 📖 How to Read These Documents

### For Architecture Overview
1. Start with **ARCHITECTURE_GUIDE.md** (5-minute read)
2. Refer to **DEPENDENCY_GRAPH.md** for visual connections
3. Go deeper with **CRATE_MAP.md** for details

### For Implementation Details
1. Open **CRATE_MAP.md** and find your crate
2. Check dependencies in **DEPENDENCY_GRAPH.md**
3. Read Cargo.toml in `rust/crates/{crate-name}/`
4. Read lib.rs/main.rs entry points

### For Adding Features
1. Identify target tier in **ARCHITECTURE_GUIDE.md**
2. Find dependencies in **CRATE_MAP.md** → Crate Matrix
3. Check critical paths in **ARCHITECTURE_GUIDE.md**
4. Verify layer constraints in **DEPENDENCY_GRAPH.md**

---

## 🛠️ Maintenance

These documents are **automatically generated** from Cargo.toml analysis. To update:

1. Modify any crate (Cargo.toml, dependencies)
2. Run analysis to regenerate maps
3. Update this index if new crates added

**Last Generated:** 2024 (static analysis date)  
**Maintenance:** Update when adding/removing crates or changing major dependencies

---

## 📞 Questions Answered

**Q: Where do I find code for feature X?**  
A: Use CRATE_MAP.md to identify the tier/crate, then DEPENDENCY_GRAPH.md to understand dependencies.

**Q: How do I add a new crate?**  
A: See ARCHITECTURE_GUIDE.md → "When Adding a New Crate"

**Q: What's the difference between IntentOS and IKRL?**  
A: See ARCHITECTURE_GUIDE.md → "Two-System Architecture"

**Q: How are cryptographic operations organized?**  
A: All crypto is in `intentkernel-crypto`. See CRATE_MAP.md → Cross-Cutting Concerns.

**Q: Can I break/skip a layer?**  
A: No. See ARCHITECTURE_GUIDE.md → Dependency Rules for guidelines.

**Q: Which crates should I test before shipping?**  
A: Foundation layer (crypto, audit, hal) always. Then critical path for your feature.

---

## 📊 Document Statistics

| File | Size | Sections | Content |
|------|------|----------|---------|
| CRATE_MAP.md | 20 KB | 8 main | Full inventory + analysis |
| DEPENDENCY_GRAPH.md | 13 KB | 10 main | Mermaid diagrams + paths |
| ARCHITECTURE_GUIDE.md | 11 KB | 13 main | Quick reference + principles |
| **Total** | **44 KB** | **31** | Complete documentation |

---

## 🎓 Learning Path

**Beginner (30 min):**
1. ARCHITECTURE_GUIDE.md (Executive Summary + Two-System Architecture)
2. DEPENDENCY_GRAPH.md (Full Dependency Graph diagram)

**Intermediate (1 hour):**
1. CRATE_MAP.md (Architecture Overview + Layer descriptions)
2. ARCHITECTURE_GUIDE.md (Security Architecture + Integration Points)

**Advanced (2+ hours):**
1. All three documents in detail
2. Examine actual Cargo.toml files in `rust/crates/*/`
3. Read lib.rs/main.rs entry points for your crate of interest

---

## ✅ Checklist for New Team Members

- [ ] Read ARCHITECTURE_GUIDE.md (5 min)
- [ ] Review DEPENDENCY_GRAPH.md visuals (5 min)
- [ ] Skim CRATE_MAP.md for your assigned crate (10 min)
- [ ] Understand your crate's dependencies (10 min)
- [ ] Clone repo and build locally (depends on setup time)
- [ ] Run `cargo test --workspace` to verify setup (5-15 min)
- [ ] Find your team's crate in code, explore entry point (15 min)

**Total onboarding time:** ~1 hour

---

## 🚀 Getting Started

```bash
# Navigate to workspace
cd rust/

# View full inventory
cat CRATE_MAP.md

# View dependency graphs
cat DEPENDENCY_GRAPH.md

# Get quick reference
cat ARCHITECTURE_GUIDE.md

# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Check specific crate
cargo build --bin intentos
```

---

## 📝 Notes

- These docs assume familiarity with Rust/Cargo concepts
- Mermaid diagrams render in VS Code with appropriate extensions
- Internal dependencies use relative paths; workspace dependencies use `workspace = true`
- All crates follow workspace inheritance for version consistency
- Post-quantum crypto is opt-in (default: classical only, `--features oqs` for PQC)

---

**This documentation is your single source of truth for Rust workspace architecture.**

For questions or updates, refer to the maintainers.
