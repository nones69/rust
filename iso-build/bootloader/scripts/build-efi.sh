#!/usr/bin/env bash
# Build a self-contained GRUB EFI image (bootx64.efi) via grub-mkstandalone.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTLOADER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="$BOOTLOADER_DIR/efi/boot/bootx64.efi"
GRUB_CFG="$BOOTLOADER_DIR/grub/grub.cfg"
WORK_DIR="$(mktemp -d)"

trap 'rm -rf "$WORK_DIR"' EXIT

if ! command -v grub-mkstandalone >/dev/null 2>&1; then
    echo "[build-efi] ERROR: grub-mkstandalone not found (install grub-efi-amd64-bin)" >&2
    exit 1
fi

mkdir -p "$BOOTLOADER_DIR/efi/boot"
mkdir -p "$WORK_DIR/boot/grub"

cp -f "$GRUB_CFG" "$WORK_DIR/boot/grub/grub.cfg"
cp -rf "$BOOTLOADER_DIR/grub/themes" "$WORK_DIR/boot/grub/" 2>/dev/null || true

grub-mkstandalone \
    --format=x86_64-efi \
    --output="$OUTPUT" \
    --compress=xz \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=$WORK_DIR/boot/grub/grub.cfg"

echo "[build-efi] EFI stub written: $OUTPUT"
ls -lh "$OUTPUT"