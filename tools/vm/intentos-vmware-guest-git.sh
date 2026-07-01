#!/usr/bin/env bash
# IntentOS test in VMware guest — clones repo when shared folder is unavailable.
set -euo pipefail

REPO_URL="${INTENTOS_REPO_URL:-https://github.com/nones69/rust.git}"
WORKDIR="${INTENTOS_GUEST_HOME:-$HOME}/rust"

echo "── IntentOS VMware guest test (git clone path)"
echo "   url:  $REPO_URL"
echo "   dir:  $WORKDIR"

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        git pkg-config libssl-dev libldap2-dev build-essential rustc cargo curl
fi

if [[ ! -d "$WORKDIR/rust/Cargo.toml" ]]; then
    rm -rf "$WORKDIR"
    echo "── Cloning repository..."
    git clone --depth 1 "$REPO_URL" "$WORKDIR"
fi

export INTENTOS_REPO="$WORKDIR"
export INTENTOS_STATE_DIR="${INTENTOS_STATE_DIR:-/tmp/intentos-vm-guest}"
export INTENTOS_SKIP_OOBE=1
exec bash "$WORKDIR/tools/vm/intentos-wsl-test.sh"