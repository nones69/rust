#!/usr/bin/env bash
# Verify the IntentKernel Rust prototype happy path.
# Run from repo root: bash scripts/verify-prototype.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/rust"

export PATH="${HOME}/.rustup/toolchains/nightly-2025-12-01-x86_64-unknown-linux-gnu/bin:${PATH}"

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== test (core prototype crates) =="
cargo test -p intentos-kernel -p intentos -p intentos-shell -p intentos-utilities --tests --lib
cargo test -p ikrl-sdk --lib
cargo test -p ik-overlay-stage1 -p ik-overlay-stage2 --lib

echo "== release demos =="
cargo build --release -p intentos -p ransomware-demo -p ikrl-sim
cargo run -p intentos --release -- -c "status" >/tmp/intentos-status.out
grep -q 'kernel' /tmp/intentos-status.out
cargo run -p intentos --release -- -c "intent file read" >/tmp/intentos-intent.out
grep -q 'allowed=true' /tmp/intentos-intent.out
cargo run -p intentos --release -- -c "flow file write" >/tmp/intentos-flow.out
cargo run -p ransomware-demo --release -- --target-dir /tmp/demo_victim_ci
cargo run -p ikrl-sim --release

echo "== C harness (optional) =="
if command -v gcc >/dev/null && command -v make >/dev/null; then
  make -C "$ROOT" test_harness
  "$ROOT/test_harness"
else
  echo "skip: gcc/make not available"
fi

echo "OK — prototype happy path verified."
