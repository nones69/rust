#!/usr/bin/env bash
# IntentOS smoke test inside VMware Ubuntu guest (shared folder mount).
set -euo pipefail

GUEST_REPO="${INTENTOS_GUEST_REPO:-/mnt/hgfs/IntentOS}"
if [[ ! -d "$GUEST_REPO/rust" ]]; then
    for alt in /mnt/hgfs/intentos /media/sf_IntentOS /media/sf_intentos; do
        if [[ -d "$alt/rust" ]]; then
            GUEST_REPO="$alt"
            break
        fi
    done
fi

if [[ ! -d "$GUEST_REPO/rust" ]]; then
    echo "Shared folder not mounted. In VMware: VM → Settings → Options → Shared Folders"
    echo "  Enable IntentOS → host C:\\Users\\Dizzle\\rust"
    echo "  Then in guest:  sudo vmware-hgfsclient"
    exit 2
fi

export INTENTOS_REPO="$GUEST_REPO"
bash "$GUEST_REPO/tools/vm/intentos-wsl-test.sh"