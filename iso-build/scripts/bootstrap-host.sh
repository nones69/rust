#!/usr/bin/env bash
# ── All-In-One ISO Build System — Host Bootstrap Script ─────────────────────────
# Installs all required tools on Ubuntu 22.04+ / Debian 12+.
# Run once on a fresh build host.
# Usage: sudo bash scripts/bootstrap-host.sh
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${BLUE}[bootstrap]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Detect Distribution ───────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
    fail "/etc/os-release not found. This script requires Ubuntu or Debian."
fi
source /etc/os-release

DISTRO="${ID}"
VERSION_CODENAME="${VERSION_CODENAME:-unknown}"

log "Detected distribution: ${DISTRO} ${VERSION_CODENAME} (${PRETTY_NAME})"

case "${DISTRO}" in
    ubuntu|debian|linuxmint) ;;
    *)
        fail "Unsupported distribution: ${DISTRO}. This script supports Ubuntu and Debian only."
        ;;
esac

# ── Root check ────────────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || fail "Run this script as root: sudo bash scripts/bootstrap-host.sh"

# Detect the invoking user (the user who called sudo)
REAL_USER="${SUDO_USER:-${USER}}"
REAL_HOME=$(getent passwd "${REAL_USER}" | cut -d: -f6)

log "Installing tools for user: ${REAL_USER} (home: ${REAL_HOME})"

# ── Step 1: APT Package Installation ─────────────────────────────────────────
log "Step 1/5: Installing APT packages ..."
apt-get update -qq

APT_PACKAGES=(
    # Core build tools
    build-essential gcc g++ gcc-multilib make cmake git git-lfs curl wget
    # Rust & LLVM support
    llvm binutils
    # ISO creation
    xorriso genisoimage
    # Filesystem tools
    squashfs-tools
    # Debian/Ubuntu live build
    debootstrap live-build
    # Bootloader tools
    grub-efi-amd64-bin grub-pc-bin grub-common grub2-common
    syslinux syslinux-efi isolinux
    # QEMU / KVM virtualisation
    qemu-system-x86 ovmf
    # Partition tools
    parted gdisk fdisk e2fsprogs dosfstools
    # Python
    python3 python3-pip python3-venv
    # TLS / security
    ca-certificates gnupg
    # GPG signing
    gpg
    # GitHub CLI (if available)
    gh
    # memtest
    memtest86+
)

apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}"
ok "APT packages installed."

# ── Step 2: Install Rust Nightly via rustup ───────────────────────────────────
log "Step 2/5: Installing Rust nightly toolchain via rustup ..."
RUSTUP_INIT_URL="https://sh.rustup.rs"

if command -v rustup >/dev/null 2>&1; then
    warn "rustup already installed. Updating ..."
    sudo -u "${REAL_USER}" rustup update nightly
else
    sudo -u "${REAL_USER}" bash -c \
        "curl --proto '=https' --tlsv1.2 -sSf ${RUSTUP_INIT_URL} | sh -s -- \
         --default-toolchain nightly \
         --component rust-src llvm-tools-preview rustfmt clippy \
         --target x86_64-unknown-none \
         -y"
fi

# Add cargo to PATH for this session
export PATH="${REAL_HOME}/.cargo/bin:${PATH}"
ok "Rust nightly toolchain installed."

# ── Step 3: Install cargo-binutils ────────────────────────────────────────────
log "Step 3/5: Installing cargo-binutils ..."
sudo -u "${REAL_USER}" "${REAL_HOME}/.cargo/bin/cargo" install cargo-binutils \
    --no-track --quiet 2>/dev/null || warn "cargo-binutils install failed (non-critical)"
ok "cargo-binutils installed (provides cargo size, objdump, etc.)"

# ── Step 4: KVM group membership ──────────────────────────────────────────────
log "Step 4/5: Adding ${REAL_USER} to kvm and libvirt groups ..."
for group in kvm libvirt; do
    if getent group "$group" >/dev/null; then
        usermod -aG "$group" "${REAL_USER}"
        ok "Added ${REAL_USER} to group: ${group}"
    fi
done
warn "Group changes take effect on next login or 'newgrp kvm'"

# ── Step 5: Version checks ────────────────────────────────────────────────────
log "Step 5/5: Verifying installed tool versions ..."
echo ""
echo -e "${BOLD}  Tool Verification Report${RESET}"
echo -e "  ────────────────────────────────────────────────────────"

check_tool() {
    local name="$1"
    local cmd="$2"
    local ver_flag="${3:---version}"
    if command -v "$cmd" >/dev/null 2>&1; then
        local ver
        ver=$("$cmd" "$ver_flag" 2>&1 | head -1)
        echo -e "  ${GREEN}[OK]${RESET}  ${name}: ${ver}"
    else
        echo -e "  ${RED}[MISSING]${RESET}  ${name}: not found"
    fi
}

check_tool "make"           make
check_tool "git"            git
check_tool "xorriso"        xorriso
check_tool "mksquashfs"     mksquashfs
check_tool "lb (live-build)" lb
check_tool "debootstrap"    debootstrap
check_tool "grub-mkstandalone" grub-mkstandalone
check_tool "qemu-system-x86_64" qemu-system-x86_64
check_tool "gpg"            gpg

# Rust (runs as real user)
if command -v "${REAL_HOME}/.cargo/bin/rustup" >/dev/null 2>&1; then
    RUST_VER=$(sudo -u "${REAL_USER}" "${REAL_HOME}/.cargo/bin/rustup" show | grep "nightly" | head -1)
    echo -e "  ${GREEN}[OK]${RESET}  rustup: ${RUST_VER}"
else
    echo -e "  ${RED}[MISSING]${RESET}  rustup: not found"
fi

echo -e "  ────────────────────────────────────────────────────────"
echo ""

echo -e "${BOLD}${GREEN}  Host bootstrap complete!${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "    1. ${YELLOW}Log out and back in${RESET} to activate KVM group membership."
echo -e "    2. Run ${CYAN}make help${RESET} from the repository root."
echo -e "    3. Run ${CYAN}make all${RESET} for a full build."
echo ""
