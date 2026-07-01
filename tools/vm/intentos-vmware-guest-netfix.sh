#!/usr/bin/env bash
# Fix Ubuntu Server guest network/DNS inside VMware VM.
set -euo pipefail

echo "── VMware guest network fix"

IFACE="$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^en|^eth' | head -1 || true)"
if [[ -z "$IFACE" ]]; then
    echo "No ethernet interface found. Interfaces:"
    ip link
    exit 1
fi

echo "   iface: $IFACE"
sudo ip link set "$IFACE" up
sudo dhclient -v "$IFACE" || sudo dhclient -v

printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf >/dev/null

echo "── Addresses"
ip addr show "$IFACE" | grep -E 'inet |state ' || true

echo "── Connectivity"
ping -c2 -W3 8.8.8.8
ping -c2 -W3 github.com
echo "Network OK"