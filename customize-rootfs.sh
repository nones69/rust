#!/usr/bin/env bash
# Post-squashfs customization helper (manual §4.7)
# Extracts, modifies, and repacks filesystem.squashfs without a full lb rebuild.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SQUASHFS="${1:-$PROJECT_ROOT/build/ubuntu-live/filesystem.squashfs}"
WORKDIR="${PROJECT_ROOT}/build/squashfs-root"
OUTPUT="${SQUASHFS}.new"

if [[ ! -f "$SQUASHFS" ]]; then
    echo "[customize-rootfs] ERROR: squashfs not found: $SQUASHFS" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[customize-rootfs] ERROR: run as root (sudo $0)" >&2
    exit 1
fi

echo "[customize-rootfs] Extracting $SQUASHFS ..."
rm -rf "$WORKDIR"
unsquashfs -d "$WORKDIR" "$SQUASHFS"

mount --bind /dev     "$WORKDIR/dev"
mount --bind /dev/pts "$WORKDIR/dev/pts"
mount --bind /proc    "$WORKDIR/proc"
mount --bind /sys     "$WORKDIR/sys"
mount --bind /run     "$WORKDIR/run"
cp /etc/resolv.conf "$WORKDIR/etc/resolv.conf"

echo "[customize-rootfs] Entering chroot — add modifications to the heredoc below ..."
chroot "$WORKDIR" /bin/bash <<'CHROOT'
export DEBIAN_FRONTEND=noninteractive
# Example: apt-get update && apt-get install -y --no-install-recommends some-package
apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT

umount "$WORKDIR/run"
umount "$WORKDIR/sys"
umount "$WORKDIR/dev/pts"
umount "$WORKDIR/dev"
umount "$WORKDIR/proc"

echo "[customize-rootfs] Repacking squashfs ..."
mksquashfs "$WORKDIR" "$OUTPUT" \
    -comp xz \
    -Xbcj x86 \
    -b 1M \
    -noappend \
    -no-progress \
    -processors "$(nproc)"

mv "$OUTPUT" "$SQUASHFS"
rm -rf "$WORKDIR"

echo "[customize-rootfs] Done. New size: $(du -h "$SQUASHFS" | cut -f1)"