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
cmake -DCMAKE_BUILD_TYPE=Debug .. || {
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
# Check for required configuration files (commented out to avoid overwriting current config)
# if [ ! -f "../yesrouter.conf" ]; then
#     echo "ERROR: yesrouter.conf is required but not found in project root!"
#     exit 1
# fi
# if [ ! -f "../startup.gate" ]; then
#     echo "ERROR: startup.gate is required but not found in project root!"
#     exit 1
# fi

sudo systemctl stop yesrouter 2>/dev/null || true
sudo cp yesrouter /usr/local/bin/
sudo mkdir -p /etc/yesrouter
# Commented out to avoid overwriting current configuration during development
sudo cp ../yesrouter.conf /etc/yesrouter/
sudo cp ../startup.gate /etc/yesrouter/
sudo cp ../yesrouter.service /etc/systemd/system/
sudo systemctl daemon-reload
# echo "  ✓ Copied yesrouter.conf to /etc/yesrouter/"
# echo "  ✓ Copied startup.gate to /etc/yesrouter/"
echo "  ✓ Updated systemd service file"
sudo rm -f /run/yesrouter/cli.sock
sudo systemctl start yesrouter 2>/dev/null || true

echo "Waiting for router to start..."
for i in {1..10}; do
    if [ -S "/run/yesrouter/cli.sock" ]; then
        break
    fi
    sleep 1
done

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
