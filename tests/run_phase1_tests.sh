#!/bin/bash
#
# Phase 1 Test Runner
# Runs all Phase 1 tests one by one
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

cd "$PROJECT_ROOT"

echo "=========================================="
echo "YESRouter vBNG - Phase 1 Test Suite"
echo "=========================================="
echo ""

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Always configure CMake to ensure tests are included
echo "Configuring CMake..."
cmake .. -DENABLE_TESTS=ON

# Build all targets first (libraries needed by tests)
echo "Building project..."
cmake --build . 2>&1 || true

# Build tests
echo "Building Phase 1 tests..."
cmake --build . --target test_phase1_build 2>&1 || true
cmake --build . --target test_phase1_dpdk 2>&1 || true
cmake --build . --target test_phase1_packet 2>&1 || true
cmake --build . --target test_phase1_config 2>&1 || true
cmake --build . --target test_phase1_logging 2>&1 || true
cmake --build . --target test_phase1_interfaces 2>&1 || true

echo ""
echo "=========================================="
echo "Running Phase 1 Tests"
echo "=========================================="
echo ""

# Test 1.1: Build System
echo ">>> Test 1.1: Project Setup & Build System"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_build" ]; then
    ./tests/test_phase1_build
    TEST1_1_RESULT=$?
else
    echo "ERROR: test_phase1_build not found"
    TEST1_1_RESULT=1
fi
echo ""

# Test 1.2: DPDK Integration
echo ">>> Test 1.2: DPDK Integration & Initialization"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_dpdk" ]; then
    ./tests/test_phase1_dpdk
    TEST1_2_RESULT=$?
else
    echo "ERROR: test_phase1_dpdk not found"
    TEST1_2_RESULT=1
fi
echo ""

# Test 1.3: Packet Buffer Management
echo ">>> Test 1.3: Packet Buffer Management"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_packet" ]; then
    ./tests/test_phase1_packet
    TEST1_3_RESULT=$?
else
    echo "ERROR: test_phase1_packet not found"
    TEST1_3_RESULT=1
fi
echo ""

# Test 1.4: Configuration Management
echo ">>> Test 1.4: Configuration Management Framework"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_config" ]; then
    ./tests/test_phase1_config
    TEST1_4_RESULT=$?
else
    echo "ERROR: test_phase1_config not found"
    TEST1_4_RESULT=1
fi
echo ""

# Test 1.5: Logging Framework
echo ">>> Test 1.5: Logging & Monitoring Framework"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_logging" ]; then
    ./tests/test_phase1_logging
    TEST1_5_RESULT=$?
else
    echo "ERROR: test_phase1_logging not found"
    TEST1_5_RESULT=1
fi
echo ""

# Test 1.6: Interface Abstraction
echo ">>> Test 1.6: Interface Abstraction Layer"
echo "-------------------------------------------"
if [ -f "tests/test_phase1_interfaces" ]; then
    ./tests/test_phase1_interfaces
    TEST1_6_RESULT=$?
else
    echo "ERROR: test_phase1_interfaces not found"
    TEST1_6_RESULT=1
fi
echo ""

# Summary
echo "=========================================="
echo "Phase 1 Test Summary"
echo "=========================================="
echo ""

TOTAL_FAILED=0

if [ $TEST1_1_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.1: Build System"
else
    echo "  [FAIL] Test 1.1: Build System"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

if [ $TEST1_2_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.2: DPDK Integration"
else
    echo "  [FAIL] Test 1.2: DPDK Integration"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

if [ $TEST1_3_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.3: Packet Buffer Management"
else
    echo "  [FAIL] Test 1.3: Packet Buffer Management"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

if [ $TEST1_4_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.4: Configuration Management"
else
    echo "  [FAIL] Test 1.4: Configuration Management"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

if [ $TEST1_5_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.5: Logging & Monitoring"
else
    echo "  [FAIL] Test 1.5: Logging & Monitoring"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

if [ $TEST1_6_RESULT -eq 0 ]; then
    echo "  [PASS] Test 1.6: Interface Abstraction"
else
    echo "  [FAIL] Test 1.6: Interface Abstraction"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

echo ""
echo "=========================================="
if [ $TOTAL_FAILED -eq 0 ]; then
    echo "All Phase 1 tests PASSED!"
    echo "=========================================="
    exit 0
else
    echo "$TOTAL_FAILED test(s) FAILED"
    echo "=========================================="
    exit 1
fi
