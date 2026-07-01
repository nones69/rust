#!/usr/bin/env bash
# IntentOS test inside WSL2 (Linux VM on Windows 11 Home)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${INTENTOS_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
RUST_ROOT="$REPO/rust"
STATE_DIR="${INTENTOS_STATE_DIR:-/tmp/intentos-wsl-test}"

echo "── IntentOS WSL2 VM test"
echo "   repo:  $RUST_ROOT"
echo "   state: $STATE_DIR"

if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists openssl 2>/dev/null; then
    echo "Missing Linux build deps. Run once in WSL Ubuntu:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install -y pkg-config libssl-dev libldap2-dev build-essential"
    exit 2
fi

mkdir -p "$STATE_DIR"
export INTENTOS_STATE_DIR="$STATE_DIR"
export INTENTOS_SKIP_OOBE=1

cd "$RUST_ROOT"
echo "── Building release..."
cargo build -p intentos --release

BIN="$RUST_ROOT/target/release/intentos"
cmds=(1 2 3 "broker status" "kernel stats" "audit verify" "hal")
fail=0
for c in "${cmds[@]}"; do
    echo ">> $c"
    if ! "$BIN" -c "$c"; then
        echo "[FAIL] $c"
        fail=$((fail + 1))
    else
        echo "[PASS] $c"
    fi
done

if [[ $fail -gt 0 ]]; then
    echo "WSL VM test failed: $fail command(s)"
    exit 1
fi
echo "WSL VM test passed — state at $STATE_DIR"