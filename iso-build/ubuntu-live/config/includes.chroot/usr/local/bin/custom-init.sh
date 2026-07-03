#!/bin/bash
# custom-init.sh — Runs at boot via custom-init.service
# Performs live-session runtime initialization.

set -euo pipefail
LOGFILE="/var/log/custom-init.log"
exec >> "$LOGFILE" 2>&1

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] custom-init.sh starting ..."

# Wait for network interface to come up (DHCP timeout guard)
for i in $(seq 1 10); do
    if ip route show default >/dev/null 2>&1; then
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Network available."
        break
    fi
    sleep 2
done

# Print system info to journal
echo "=== Custom OS Live Session ==="
uname -a
free -h
df -h /

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] custom-init.sh completed."
