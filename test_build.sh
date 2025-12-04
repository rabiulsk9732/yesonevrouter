#!/bin/bash
# Simple build test script

set -e
cd /root/vbng

echo "=== Build Test Script ==="
echo "Current directory: $(pwd)"
echo "Checking build tools..."

if ! command -v cmake &> /dev/null; then
    echo "ERROR: cmake not found"
    exit 1
fi

if ! command -v make &> /dev/null; then
    echo "ERROR: make not found"
    exit 1
fi

echo "CMake version: $(cmake --version | head -1)"
echo "Make version: $(make --version | head -1)"

echo ""
echo "Cleaning build directory..."
rm -rf build
mkdir -p build
cd build

echo "Running CMake..."
cmake .. || {
    echo "CMake failed!"
    exit 1
}

echo ""
echo "Building..."
make -j$(nproc) 2>&1 | tee build_output.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo "=== BUILD SUCCESSFUL ==="
    if [ -f yesrouter ]; then
        ls -lh yesrouter
        echo ""
        echo "Executable created successfully!"
    fi
else
    echo ""
    echo "=== BUILD FAILED ==="
    echo "Last 30 lines of build output:"
    tail -30 build_output.log
    exit 1
fi
