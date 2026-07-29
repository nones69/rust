#!/usr/bin/env bash
# ── All-In-One ISO Build System — ISO Assembly Script ───────────────────────────
# Collects all module artifacts, stages them, and runs xorriso to produce
# the final hybrid bootable ISO.
# Dan — v1.0.0 — July 2026
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)][assemble]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*" >&2; exit 1; }

# ── Paths ──────────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
DIST_DIR="${REPO_ROOT}/dist"
STAGE_DIR="${BUILD_DIR}/iso"
ISO_OUT="${DIST_DIR}/custom-os.iso"
ISO_VOLID="CUSTOM_OS_2026"

# Module artifact sources
SRC_RUSTOS="${BUILD_DIR}/rust-os/rust-os.elf"
SRC_SQUASHFS="${BUILD_DIR}/ubuntu-live/filesystem.squashfs"
SRC_VMLINUZ="${BUILD_DIR}/ubuntu-live/vmlinuz"
SRC_INITRD="${BUILD_DIR}/ubuntu-live/initrd"
SRC_GRUB_CFG="${REPO_ROOT}/bootloader/grub/grub.cfg"
SRC_GRUB_THEME="${REPO_ROOT}/bootloader/grub/themes/custom"
SRC_SYSLINUX_CFG="${REPO_ROOT}/bootloader/syslinux/isolinux.cfg"
SRC_EFI_BINARY="${REPO_ROOT}/bootloader/efi/boot/bootx64.efi"
SRC_EFI_IMG="${STAGE_DIR}/EFI/boot/efiboot.img"

# SYSLINUX module files (from host package)
SYSLINUX_MODULES="/usr/lib/syslinux/modules/bios"
ISOLINUX_BIN="/usr/lib/ISOLINUX/isolinux.bin"

log "Starting ISO assembly ..."
log "Staging directory: ${STAGE_DIR}"
log "Output ISO:        ${ISO_OUT}"

# ── Sanity Checks ─────────────────────────────────────────────────────────────
for f in "$SRC_RUSTOS" "$SRC_SQUASHFS" "$SRC_VMLINUZ" "$SRC_INITRD" \
          "$SRC_GRUB_CFG" "$SRC_EFI_BINARY" "$ISOLINUX_BIN"; do
    [[ -f "$f" ]] || fail "Required artifact not found: $f"
done
command -v xorriso   >/dev/null || fail "xorriso is not installed"
command -v isohybrid >/dev/null || fail "isohybrid is not installed (apt install syslinux)"

# ── Step 1: Prepare staging directory ────────────────────────────────────────
log "Step 1: Preparing staging directory ..."
rm -rf "${STAGE_DIR}"
mkdir -p \
    "${STAGE_DIR}/live"       \
    "${STAGE_DIR}/boot/grub/themes/custom" \
    "${STAGE_DIR}/boot/grub/locale" \
    "${STAGE_DIR}/isolinux"   \
    "${STAGE_DIR}/EFI/boot"

# ── Step 2: Copy Rust OS kernel ───────────────────────────────────────────────
log "Step 2: Copying Rust OS kernel ..."
cp "${SRC_RUSTOS}" "${STAGE_DIR}/boot/rust-os.elf"
ok "rust-os.elf → /boot/rust-os.elf ($(du -h "${STAGE_DIR}/boot/rust-os.elf" | cut -f1))"

# ── Step 3: Copy Ubuntu live artifacts ────────────────────────────────────────
log "Step 3: Copying Ubuntu live artifacts ..."
cp "${SRC_SQUASHFS}" "${STAGE_DIR}/live/filesystem.squashfs"
cp "${SRC_VMLINUZ}"  "${STAGE_DIR}/live/vmlinuz"
cp "${SRC_INITRD}"   "${STAGE_DIR}/live/initrd"

# Generate squashfs size file (required by casper/live-boot)
printf "%s" "$(unsquashfs -s "${STAGE_DIR}/live/filesystem.squashfs" \
    | grep "Filesystem size" | awk '{print $3 * 1024}')" \
    > "${STAGE_DIR}/live/filesystem.size"

ok "squashfs → /live/filesystem.squashfs ($(du -h "${STAGE_DIR}/live/filesystem.squashfs" | cut -f1))"
ok "vmlinuz  → /live/vmlinuz"
ok "initrd   → /live/initrd"

# ── Step 4: Copy GRUB configuration ───────────────────────────────────────────
log "Step 4: Copying GRUB configuration and theme ..."
cp "${SRC_GRUB_CFG}" "${STAGE_DIR}/boot/grub/grub.cfg"
cp -r "${SRC_GRUB_THEME}/." "${STAGE_DIR}/boot/grub/themes/custom/"

# Copy GRUB locale files if present
GRUB_LOCALE_SRC="/usr/share/locale/en@quot/LC_MESSAGES/grub.mo"
if [[ -f "$GRUB_LOCALE_SRC" ]]; then
    cp "$GRUB_LOCALE_SRC" "${STAGE_DIR}/boot/grub/locale/en.mo"
fi
ok "GRUB config and theme staged"

# ── Step 5: Copy SYSLINUX / ISOLINUX files ────────────────────────────────────
log "Step 5: Copying SYSLINUX files ..."
cp "${ISOLINUX_BIN}"                                   "${STAGE_DIR}/isolinux/"
cp "${SRC_SYSLINUX_CFG}"                               "${STAGE_DIR}/isolinux/isolinux.cfg"
for mod in ldlinux.c32 libcom32.c32 libutil.c32 vesamenu.c32; do
    cp "${SYSLINUX_MODULES}/${mod}" "${STAGE_DIR}/isolinux/"
done
ok "SYSLINUX/ISOLINUX files staged"

# ── Step 6: Copy EFI files ────────────────────────────────────────────────────
log "Step 6: Staging EFI boot files ..."
cp "${SRC_EFI_BINARY}" "${STAGE_DIR}/EFI/boot/bootx64.efi"

# Build EFI FAT image (if not pre-built by Module 3 Makefile target)
if [[ ! -f "${SRC_EFI_IMG}" ]]; then
    log "  Building EFI FAT16 disk image ..."
    dd if=/dev/zero of="${SRC_EFI_IMG}" bs=1M count=4 status=none
    mkfs.vfat -F 16 -n "EFIBOOT" "${SRC_EFI_IMG}"
    TMP=$(mktemp -d)
    sudo mount "${SRC_EFI_IMG}" "$TMP"
    sudo mkdir -p "$TMP/EFI/boot"
    sudo cp "${SRC_EFI_BINARY}" "$TMP/EFI/boot/"
    sudo umount "$TMP"
    rmdir "$TMP"
fi
ok "EFI files staged"

# ── Step 7: Copy optional memtest86+ ─────────────────────────────────────────
MEMTEST_BIN="/boot/memtest86+.bin"
if [[ -f "$MEMTEST_BIN" ]]; then
    cp "$MEMTEST_BIN" "${STAGE_DIR}/boot/memtest86+.bin"
    ok "memtest86+ staged"
fi

# ── Step 8: Create output directory ──────────────────────────────────────────
mkdir -p "${DIST_DIR}"

# ── Step 9: Run xorriso ───────────────────────────────────────────────────────
log "Step 9: Running xorriso to build hybrid ISO ..."

xorriso -as mkisofs                                         \
    -iso-level 3                                            \
    -full-iso9660-filenames                                 \
    -volid "${ISO_VOLID}"                                   \
    -rational-rock                                          \
    -joliet                                                 \
    -eltorito-boot        isolinux/isolinux.bin             \
    -eltorito-catalog     isolinux/boot.cat                 \
    -no-emul-boot                                           \
    -boot-load-size 4                                       \
    -boot-info-table                                        \
    --eltorito-alt-boot                                     \
    -e EFI/boot/efiboot.img                                 \
    -no-emul-boot                                           \
    --protective-msdos-label                                \
    -output "${ISO_OUT}"                                    \
    "${STAGE_DIR}"

ok "xorriso complete."

# ── Step 10: Make USB-writable with isohybrid ─────────────────────────────────
log "Step 10: Applying isohybrid MBR ..."
isohybrid --uefi "${ISO_OUT}"
ok "isohybrid applied."

# ── Final report ──────────────────────────────────────────────────────────────
ISO_SIZE=$(du -h "${ISO_OUT}" | cut -f1)
ISO_MD5=$(md5sum "${ISO_OUT}" | awk '{print $1}')

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  ISO Build Complete!${RESET}"
echo -e "  Output:  ${ISO_OUT}"
echo -e "  Size:    ${ISO_SIZE}"
echo -e "  MD5:     ${ISO_MD5}"
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo ""
