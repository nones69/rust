#!/usr/bin/env bash
# ── All-In-One ISO Build System — ISO Verification Script ───────────────────────
# Verifies ISO integrity and optionally launches a QEMU test boot.
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ISO="${REPO_ROOT}/dist/custom-os.iso"
QEMU_MEM="${QEMU_MEM:-2048}"
QEMU_CORES="${QEMU_CORES:-2}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; RESET='\033[0m'
log()   { echo -e "${BLUE}[verify]${RESET} $*"; }
ok()    { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET} $*" >&2; exit 1; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }

echo ""
echo "══════════════════════════════════════════════════════"
echo "  All-In-One ISO Build System — ISO Verification"
echo "══════════════════════════════════════════════════════"
echo ""

# ── Test 1: ISO exists ────────────────────────────────────────────────────────
log "Test 1: Checking ISO file exists ..."
[[ -f "$ISO" ]] || fail "ISO not found: $ISO — run 'make iso' first."
ISO_SIZE_BYTES=$(stat -c%s "$ISO")
ISO_SIZE_HUMAN=$(du -h "$ISO" | cut -f1)
ok "ISO found: ${ISO} (${ISO_SIZE_HUMAN} / ${ISO_SIZE_BYTES} bytes)"

# Warn if ISO is unreasonably small (likely a failed build)
[[ "$ISO_SIZE_BYTES" -gt 104857600 ]] || \
    warn "ISO is smaller than 100 MiB — may be a partial build."

# ── Test 2: File format verification ─────────────────────────────────────────
log "Test 2: Verifying ISO 9660 format ..."
FILE_OUT=$(file "$ISO")
echo "  file: ${FILE_OUT}"
echo "$FILE_OUT" | grep -q "ISO 9660" || fail "ISO format check failed: not ISO 9660"
ok "ISO 9660 format confirmed"

# ── Test 3: Volume label check ────────────────────────────────────────────────
log "Test 3: Checking volume label ..."
if command -v isoinfo >/dev/null; then
    VOLID=$(isoinfo -d -i "$ISO" 2>/dev/null | grep "Volume id" | awk '{print $NF}')
    echo "  Volume ID: ${VOLID}"
    [[ "$VOLID" == "CUSTOM_OS_2026" ]] && ok "Volume label correct: CUSTOM_OS_2026" \
        || warn "Unexpected volume label: ${VOLID}"
else
    warn "isoinfo not available (apt install genisoimage); skipping volume label check"
fi

# ── Test 4: MD5 checksum ──────────────────────────────────────────────────────
log "Test 4: Computing MD5 checksum ..."
MD5=$(md5sum "$ISO" | awk '{print $1}')
SHA256=$(sha256sum "$ISO" | awk '{print $1}')
ok "MD5:    ${MD5}"
ok "SHA256: ${SHA256}"

# Write checksums to file for distribution
CHECKSUM_FILE="${REPO_ROOT}/dist/custom-os.iso.sha256"
echo "${SHA256}  custom-os.iso" > "$CHECKSUM_FILE"
ok "Checksum written: ${CHECKSUM_FILE}"

# ── Test 5: El Torito boot record check ──────────────────────────────────────
log "Test 5: Checking El Torito boot record ..."
if command -v xorriso >/dev/null; then
    ELTORITO=$(xorriso -report_el_torito as_mkisofs -indev "$ISO" 2>/dev/null \
        | head -5 || true)
    echo "  El Torito: ${ELTORITO}"
    ok "El Torito boot record detected"
fi

# ── Test 6: QEMU boot test (optional, requires -qemu flag) ───────────────────
if [[ "${1:-}" == "--qemu" || "${1:-}" == "-q" ]]; then
    log "Test 6: Launching QEMU BIOS boot test ..."
    command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 not found"

    echo ""
    warn "Launching QEMU. Press Ctrl+C to exit. Observe the GRUB menu and kernel boot."
    echo ""

    qemu-system-x86_64 \
        -cdrom       "$ISO"       \
        -m           "${QEMU_MEM}M"  \
        -smp         "${QEMU_CORES}" \
        -boot        d            \
        -machine     pc,accel=kvm:tcg \
        -vga         std          \
        -serial      stdio        \
        -display     gtk          \
        2>/dev/null
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo -e "${GREEN}  All verification tests passed.${RESET}"
echo "  ISO: ${ISO}"
echo "  SHA256: ${SHA256}"
echo "══════════════════════════════════════════════════════"
echo ""
