#!/bin/bash
# Build and install yesrouter in one command

set -e

cd "$(dirname "$0")"

echo "=========================================="
echo "Building and Installing yesrouter vBNG"
echo "=========================================="
echo ""

# Clean and create build directory
echo "[1/5] Preparing build directory..."
rm -rf build
mkdir -p build
cd build

# Configure
echo "[2/5] Configuring with CMake..."
cmake .. || {
    echo "ERROR: CMake configuration failed!"
    exit 1
}

# Build
echo "[3/5] Building..."
make -j$(nproc) || {
    echo "ERROR: Build failed!"
    exit 1
}

# Verify
echo "[4/5] Verifying build..."
if [ ! -f yesrouter ]; then
    echo "ERROR: Executable not found!"
    exit 1
fi

echo "Build successful: $(pwd)/yesrouter"
ls -lh yesrouter
echo ""

# Install
echo "[5/5] Installing..."
sudo systemctl stop yesrouter 2>/dev/null || true
sudo cp yesrouter /usr/local/bin/
sudo systemctl start yesrouter 2>/dev/null || true

echo ""
echo "=========================================="
echo "INSTALLATION COMPLETE!"
echo "=========================================="
echo ""
echo "Service status:"
sudo systemctl status yesrouter --no-pager -l | head -10 || true
echo ""
echo "To test NAT statistics:"
echo "  yesrouterctl show nat statistics"
