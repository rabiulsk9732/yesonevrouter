#!/bin/bash
# Rebuild script for YESRouter vBNG

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "YESRouter vBNG - Rebuild Script"
echo "=========================================="
echo ""

# Clean previous build
echo "[1/4] Cleaning previous build..."
rm -rf build
mkdir -p build
cd build

# Configure with CMake
echo "[2/4] Configuring with CMake..."
if ! cmake ..; then
    echo "ERROR: CMake configuration failed!"
    exit 1
fi

# Build
echo "[3/4] Building project..."
if ! make -j$(nproc); then
    echo "ERROR: Build failed!"
    echo ""
    echo "Checking for common issues..."
    echo "- OpenSSL: $(pkg-config --modversion openssl 2>/dev/null || echo 'Not found')"
    echo "- DPDK: $(pkg-config --modversion libdpdk 2>/dev/null || echo 'Not found')"
    exit 1
fi

# Verify executable
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
    echo "Executable location: $(pwd)/yesrouter"
else
    echo "ERROR: Executable not found!"
    exit 1
fi
