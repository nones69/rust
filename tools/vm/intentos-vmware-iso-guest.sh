#!/usr/bin/env bash
# Build iso-build on Ubuntu guest and optionally copy ISO to shared folder.
set -euo pipefail

REPO="${HOME}/rust"
ISO_BUILD="${REPO}/iso-build"
ISO_OUT="${ISO_BUILD}/dist/custom-os.iso"
STAGE="${1:-all}"   # network | deps | rust-os | ubuntu-live | iso | all

log() { echo "[iso-guest] $*"; }

fix_network() {
    log "Fixing network (DHCP + DNS) ..."
    sudo ip link set ens33 up 2>/dev/null || sudo ip link set eth0 up 2>/dev/null || true
    sudo dhclient -v ens33 2>/dev/null || sudo dhclient -v eth0 2>/dev/null || sudo dhclient -v
    printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf >/dev/null
    ping -c2 8.8.8.8
    ping -c2 github.com
}

ensure_repo() {
    if [[ ! -d "$REPO/.git" ]]; then
        log "Cloning repository ..."
        git clone https://github.com/nones69/rust.git "$REPO"
    else
        log "Updating repository ..."
        cd "$REPO" && git pull --ff-only
    fi
}

install_deps() {
    log "Installing host prerequisites (sudo) ..."
    cd "$ISO_BUILD"
    sudo bash scripts/bootstrap-host.sh
    # shellcheck disable=SC1090
    [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
}

build_rust_os() {
    cd "$ISO_BUILD"
    source "${HOME}/.cargo/env" 2>/dev/null || true
    make rust-os
    ls -lh build/rust-os/rust-os.elf
}

build_ubuntu_live() {
    cd "$ISO_BUILD"
    sudo make ubuntu-live
}

build_iso() {
    cd "$ISO_BUILD"
    make bootloader
    make iso
    make verify
    ls -lh "$ISO_OUT"
    if [[ -d /mnt/hgfs/IntentOS ]]; then
        mkdir -p /mnt/hgfs/IntentOS/iso-build/dist
        cp -f "$ISO_OUT" /mnt/hgfs/IntentOS/iso-build/dist/
        log "Copied ISO to shared folder: /mnt/hgfs/IntentOS/iso-build/dist/custom-os.iso"
    fi
}

case "$STAGE" in
    network)   fix_network ;;
    deps)      fix_network; ensure_repo; install_deps ;;
    rust-os)   fix_network; ensure_repo; install_deps; build_rust_os ;;
    ubuntu-live) fix_network; ensure_repo; install_deps; build_rust_os; build_ubuntu_live ;;
    iso)       fix_network; ensure_repo; install_deps; build_rust_os; build_ubuntu_live; build_iso ;;
    all)       fix_network; ensure_repo; install_deps; build_rust_os; build_ubuntu_live; build_iso ;;
    *)         echo "Usage: $0 [network|deps|rust-os|ubuntu-live|iso|all]"; exit 1 ;;
esac

log "Stage '$STAGE' complete."