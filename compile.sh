#!/bin/bash
# Compile script for yesrouter

set -e

cd "$(dirname "$0")"

echo "=========================================="
echo "Compiling yesrouter vBNG"
echo "=========================================="
echo ""

# Clean and create build directory
echo "[1/4] Preparing build directory..."
rm -rf build
mkdir -p build
cd build

# Configure
echo "[2/4] Configuring with CMake..."
cmake .. || {
    echo "ERROR: CMake configuration failed!"
    exit 1
}

# Build
echo "[3/4] Building..."
make -j$(nproc) || {
    echo "ERROR: Build failed!"
    exit 1
}

# Verify
echo "[4/4] Verifying build..."
if [ -f yesrouter ]; then
    echo ""
    echo "=========================================="
    echo "BUILD SUCCESSFUL!"
    echo "=========================================="
    echo ""
    ls -lh yesrouter
    echo ""
    file yesrouter
    echo ""
    echo "Executable: $(pwd)/yesrouter"

    # Create symlinks to config files for running from build/
    echo ""
    echo "Creating symlinks to config files..."
    ln -sf ../startup.conf startup.conf
    ln -sf ../startup.gate startup.gate
    echo "  ✓ startup.conf -> ../startup.conf"
    echo "  ✓ startup.gate -> ../startup.gate"
else
    echo "ERROR: Executable not found!"
    exit 1
fi
