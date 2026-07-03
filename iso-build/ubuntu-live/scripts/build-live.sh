#!/usr/bin/env bash
# ── All-In-One ISO Build System — Ubuntu Live Build Script ──────────────────────
# Wraps lb config + lb build with logging, error handling, and artifact collection.
# Must be run as root from the ubuntu-live/ directory.
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour codes for terminal output ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Sanity checks ─────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && fail "This script must be run as root (sudo ./build-live.sh)"
command -v lb >/dev/null   || fail "live-build (lb) is not installed. Run: apt install live-build"
[[ -f "scripts/build-live.sh" ]] || fail "Run this script from the ubuntu-live/ directory."

# ── Configuration ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIVE_DIR="$(dirname "$SCRIPT_DIR")"          # ubuntu-live/
BUILD_DIR="${LIVE_DIR}/../build/ubuntu-live"
LOG_FILE="${BUILD_DIR}/lb-build-$(date +%Y%m%d-%H%M%S).log"
ARTIFACT_SQUASHFS="binary/live/filesystem.squashfs"
ARTIFACT_VMLINUZ="binary/live/vmlinuz"
ARTIFACT_INITRD="binary/live/initrd"

mkdir -p "$BUILD_DIR"

log "All-In-One ISO Build System — Ubuntu Live Build"
log "Working directory: $(pwd)"
log "Build log: ${LOG_FILE}"

# ── Stage 1: Clean previous partial build (if any) ────────────────────────────
if [[ -d "chroot" ]]; then
    warn "Previous chroot directory found. Running lb clean --stage chroot ..."
    lb clean --stage chroot 2>&1 | tee -a "$LOG_FILE"
fi

# ── Stage 2: Configure live-build ─────────────────────────────────────────────
log "Stage 2/4: Running lb config ..."
lb config \
    --distribution        noble          \
    --architecture        amd64          \
    --binary-images       iso-hybrid     \
    --bootloaders         "grub-efi,syslinux" \
    --debian-installer    none           \
    --memtest             none           \
    --archive-areas       "main restricted universe multiverse" \
    --cache               true           \
    --compression         xz             \
    --hostname            custom-os      \
    --username            liveuser       \
    --chroot-filesystem   squashfs       \
    --iso-application     "Custom OS 2026" \
    --iso-volume          "CUSTOM_OS_2026" \
    2>&1 | tee -a "$LOG_FILE"
ok "lb config complete."

# ── Stage 3: Run the full live-build pipeline ─────────────────────────────────
log "Stage 3/4: Running lb build (this may take 20-60 minutes) ..."
lb build 2>&1 | tee -a "$LOG_FILE"
ok "lb build complete."

# ── Stage 4: Collect artifacts ────────────────────────────────────────────────
log "Stage 4/4: Collecting artifacts ..."

for artifact in "$ARTIFACT_SQUASHFS" "$ARTIFACT_VMLINUZ" "$ARTIFACT_INITRD"; do
    if [[ -f "$artifact" ]]; then
        cp "$artifact" "$BUILD_DIR/"
        ok "Copied: $artifact → $BUILD_DIR/"
    else
        fail "Expected artifact not found: $artifact"
    fi
done

# Copy the generated lb ISO for reference
if [[ -f "live-image-amd64.hybrid.iso" ]]; then
    cp "live-image-amd64.hybrid.iso" "$BUILD_DIR/ubuntu-live-reference.iso"
    ok "Reference ISO copied: $BUILD_DIR/ubuntu-live-reference.iso"
fi

log "Build artifacts:"
ls -lh "$BUILD_DIR/"

ok "Ubuntu Live build pipeline complete."
echo ""
echo "  squashfs  → ${BUILD_DIR}/filesystem.squashfs"
echo "  vmlinuz   → ${BUILD_DIR}/vmlinuz"
echo "  initrd    → ${BUILD_DIR}/initrd"
