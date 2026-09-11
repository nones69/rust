# Repository layout (keep / quarantine / drop)

Living map of what belongs in this tree after the cleanup pass.
Primary product path: **`rust/`** IntentOS prototype. Everything else is
spec, reference, or clearly marked experimental research.

## Keep (active)

| Path | Role |
|------|------|
| `docs/` | Specs, vision, token RFC, claim posture |
| `governance/` | Project principles |
| `roadmap/` | Implementation plans (goals, not guarantees) |
| `rust/` | Active Rust workspace — **the** runnable prototype |
| `src/reference/` | C capability-table harness (`make test_harness`) |
| `thesis/00_master` … `05_*`, `chapters/`, `reflections/`, `research/` | Curated thesis corpus |
| `LICENSE`, `AUTHORS.md`, `README.md`, `BUILD.md`, `rust-toolchain.toml` | Project entrypoints |
| `.github/workflows/rust.yml`, `build.yml`, `iso-build.yml` | CI |

## Quarantine / experimental (keep, not primary path)

| Path | Role |
|------|------|
| `iso-build/` | Live-ISO / bare-metal pipeline — see its README |
| `install/`, `platform/` | Packaging / UI experiments — see `EXPERIMENTAL.md` |
| `experimental/baremetal-root-stubs/` | Quarantined incomplete root stubs |
| `src/kernel/`, `src/arch/` | Incomplete C bare-metal stubs (optional `make kernel`) |
| `tools/vm/` | Host VM helper scripts (Windows-oriented) |
| `scripts/` | Host build helpers (non-prototype) |
| Legacy IKRL daemons in `rust/crates/{capd,intentd,...}` | Multi-process experiments; not the happy path |

## Removed in cleanup (do not reintroduce casually)

- Accidental root ISO dumps duplicated by `iso-build/` (`assemble.sh`, `grub.cfg`, …)
- Unrelated `tools/ip-discrambler` Python product + its CI workflow
- Thesis paste dumps (`thesis/06_*` … `09_archive`, XML/Word scratch)
- Duplicate root `principles.md` (canonical: `governance/principles.md`)
- Orphan Windows test/setup bats tied to removed ISO scratch

Optional IP enrichment remains as **optional** Rust bridge code in
`intentos-utilities` (offline when the Python tree is absent).
