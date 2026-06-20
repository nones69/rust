#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/rust"
echo "Attempting PQC build (intentkernel-crypto --features oqs)..."
if cargo build --release -p intentkernel-crypto --features oqs; then
  echo "[OK] liboqs backend linked"
  cargo build --release
else
  echo "[WARN] liboqs unavailable — building with mock PQC"
  cargo build --release
fi