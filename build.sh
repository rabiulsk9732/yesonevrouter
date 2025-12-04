#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Cleaning build directory..."
rm -rf build
mkdir -p build
cd build

echo "Running CMake..."
cmake .. 2>&1 | tee cmake.log

echo ""
echo "Building..."
make -j$(nproc) 2>&1 | tee build.log

if [ $? -eq 0 ]; then
    echo ""
    echo "Build successful!"
    ls -lh yesrouter
else
    echo ""
    echo "Build failed. Check build.log for errors."
    exit 1
fi
