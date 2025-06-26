#!/bin/bash
# Simple script to spoof MAC address and connect to Mullvad VPN
# Interfaces: eth0 (physical) and wg0-mullvad (VPN)

set -e

PHYSICAL_IF="eth0"
VPN_IF="wg0-mullvad"

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Bring down interfaces
ip link set "$PHYSICAL_IF" down

# Spoof MAC address using macchanger
if command -v macchanger >/dev/null; then
    macchanger -r "$PHYSICAL_IF"
else
    echo "macchanger not installed. Please install it." >&2
    exit 1
fi

# Bring interface up with new MAC
ip link set "$PHYSICAL_IF" up

# Restart Mullvad VPN interface if present
if ip link show "$VPN_IF" >/dev/null 2>&1; then
    ip link set "$VPN_IF" down
    ip link set "$VPN_IF" up
else
    echo "VPN interface $VPN_IF not found." >&2
fi

echo "MAC spoofing completed. VPN interface restarted."
