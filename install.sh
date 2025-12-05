#!/bin/bash
# Installation script for YESRouter vBNG
# Makes it work like VPP - install once, runs automatically

set -e

echo "========================================="
echo "Installing YESRouter vBNG"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo ./install.sh)"
    exit 1
fi

# Check if binaries exist
if [ ! -f "build/yesrouter" ] || [ ! -f "build/yesrouterctl" ]; then
    echo "ERROR: Binaries not found. Run ./compile.sh first"
    exit 1
fi

echo "[1/6] Installing binaries..."
cp build/yesrouter /usr/local/bin/
cp build/yesrouterctl /usr/local/bin/
chmod +x /usr/local/bin/yesrouter
chmod +x /usr/local/bin/yesrouterctl
echo "  ✓ Installed to /usr/local/bin/"

echo "[2/6] Creating directories..."
mkdir -p /etc/yesrouter
mkdir -p /run/yesrouter
mkdir -p /var/log/yesrouter
echo "  ✓ Created /etc/yesrouter, /run/yesrouter, /var/log/yesrouter"

echo "[3/6] Installing configuration files..."
if [ -f "startup.conf" ]; then
    cp startup.conf /etc/yesrouter/
    echo "  ✓ Copied startup.conf"
fi
if [ -f "startup.gate" ]; then
    cp startup.gate /etc/yesrouter/
    echo "  ✓ Copied startup.gate"
fi

echo "[4/6] Installing systemd service..."
cp yesrouter.service /etc/systemd/system/
systemctl daemon-reload
echo "  ✓ Systemd service installed"

echo "[5/6] Enabling service..."
systemctl enable yesrouter.service
echo "  ✓ Service will start on boot"

echo "[6/6] Starting service..."
systemctl start yesrouter.service
sleep 2
echo "  ✓ Service started"

echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "YESRouter is now running as a system service."
echo ""
echo "Usage:"
echo "  yesrouterctl                 # Connect to CLI"
echo "  yesrouterctl show interfaces # Run single command"
echo ""
echo "Service management:"
echo "  systemctl status yesrouter   # Check status"
echo "  systemctl stop yesrouter     # Stop service"
echo "  systemctl restart yesrouter  # Restart service"
echo "  systemctl disable yesrouter  # Disable auto-start"
echo ""
echo "Configuration:"
echo "  /etc/yesrouter/startup.conf"
echo "  /etc/yesrouter/startup.gate"
echo ""
echo "Logs:"
echo "  journalctl -u yesrouter -f   # View logs"
echo ""
