#!/bin/bash
# YESRouter Build Script

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_TYPE="${1:-Release}"

echo "========================================"
echo "YESRouter vBNG Build Script"
echo "========================================"
echo "Project Root: ${PROJECT_ROOT}"
echo "Build Type: ${BUILD_TYPE}"
echo ""

# Clean old build
if [ "$2" == "clean" ]; then
    echo "Cleaning old build..."
    rm -rf "${BUILD_DIR}"
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure with CMake
echo "Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DENABLE_DPDK=OFF \
    -DENABLE_TESTS=ON \
    -DENABLE_BENCHMARKS=OFF

# Build
echo ""
echo "Building..."
make -j$(nproc)

echo ""
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo "Build directory: ${BUILD_DIR}"
echo ""
