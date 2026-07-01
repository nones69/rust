#!/usr/bin/env bash
# IntentOS smoke test inside VMware Ubuntu guest (shared folder mount).
set -euo pipefail

echo "── IntentOS VMware guest test"

mount_shared() {
    local repo=""
    for candidate in \
        "${INTENTOS_GUEST_REPO:-}" \
        /mnt/hgfs/IntentOS \
        /mnt/hgfs/intentos \
        /media/sf_IntentOS \
        /media/sf_intentos; do
        [[ -z "$candidate" ]] && continue
        if [[ -d "$candidate/rust" ]]; then
            repo="$candidate"
            break
        fi
    done
    if [[ -n "$repo" ]]; then
        echo "$repo"
        return 0
    fi

    echo "── Shared folder not visible; installing VMware tools + mounting..." >&2
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            open-vm-tools open-vm-tools-desktop pkg-config libssl-dev libldap2-dev \
            build-essential rustc cargo 2>/dev/null || \
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            open-vm-tools open-vm-tools-desktop pkg-config libssl-dev libldap2-dev build-essential
    fi

    sudo mkdir -p /mnt/hgfs
    echo "── Shares reported by guest:" >&2
    vmware-hgfsclient 2>/dev/null || true

    if ! mountpoint -q /mnt/hgfs 2>/dev/null; then
        sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other 2>/dev/null || \
        sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other 2>/dev/null || true
    fi

    for candidate in /mnt/hgfs/IntentOS /mnt/hgfs/intentos; do
        if [[ -d "$candidate/rust" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    echo "── vmware-hgfsclient returned no shares; using git clone instead..." >&2
    ls -la /mnt/hgfs/ 2>/dev/null || true
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$script_dir/intentos-vmware-guest-git.sh" ]]; then
        exec bash "$script_dir/intentos-vmware-guest-git.sh"
    fi
    echo "ERROR: Cannot find IntentOS share and git fallback script missing." >&2
    return 1
}

GUEST_REPO="$(mount_shared)"
echo "   repo: $GUEST_REPO"
export INTENTOS_REPO="$GUEST_REPO"
exec bash "$GUEST_REPO/tools/vm/intentos-wsl-test.sh"