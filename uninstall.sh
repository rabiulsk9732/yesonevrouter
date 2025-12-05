#!/bin/bash
# Uninstall script for YESRouter vBNG

set -e

echo "========================================="
echo "Uninstalling YESRouter vBNG"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo ./uninstall.sh)"
    exit 1
fi

echo "[1/4] Stopping and disabling service..."
systemctl stop yesrouter.service 2>/dev/null || true
systemctl disable yesrouter.service 2>/dev/null || true
echo "  ✓ Service stopped"

echo "[2/4] Removing service file..."
rm -f /etc/systemd/system/yesrouter.service
systemctl daemon-reload
echo "  ✓ Service file removed"

echo "[3/4] Removing binaries..."
rm -f /usr/local/bin/yesrouter
rm -f /usr/local/bin/yesrouterctl
echo "  ✓ Binaries removed"

echo "[4/4] Cleaning up runtime files..."
rm -rf /run/yesrouter
rm -f /var/run/dpdk/rte/config
echo "  ✓ Runtime files cleaned"

echo ""
echo "========================================="
echo "Uninstall Complete!"
echo "========================================="
echo ""
echo "Configuration files preserved in /etc/yesrouter/"
echo "To remove configs: sudo rm -rf /etc/yesrouter"
echo "To remove logs: sudo rm -rf /var/log/yesrouter"
echo ""
