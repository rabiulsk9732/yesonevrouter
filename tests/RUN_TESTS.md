# Running Phase 1 Tests - Manual Instructions

Since automated test execution is not available in this environment, here are manual instructions to run the Phase 1 tests.

## Prerequisites

1. Ensure you have CMake installed: `cmake --version`
2. Ensure you have a C compiler (gcc/clang): `gcc --version`
3. Navigate to the project root: `cd /root/vbng`

## Step 1: Configure and Build

```bash
cd /root/vbng
mkdir -p build
cd build
cmake .. -DENABLE_TESTS=ON
cmake --build . --target test_phase1_build test_phase1_dpdk test_phase1_packet \
      test_phase1_config test_phase1_logging test_phase1_interfaces
```

## Step 2: Run Tests Individually

### Test 1.1: Build System
```bash
cd /root/vbng/build
./tests/test_phase1_build
```

**Expected Output:**
- All build artifacts exist
- Source files exist
- Header files exist
- Build system files exist
- Documentation exists
- Summary showing all tests passed

### Test 1.2: DPDK Integration
```bash
./tests/test_phase1_dpdk
```

**Expected Output:**
- DPDK initialization handles gracefully (even without DPDK library)
- Memory pool creation works or handles missing DPDK
- CPU core functions return valid values
- DPDK cleanup executes without crash
- Configuration structure accessible

### Test 1.3: Packet Buffer Management
```bash
./tests/test_phase1_packet
```

**Expected Output:**
- Packet buffer initialization succeeds
- Packet allocation/deallocation works
- Metadata extraction executes
- Packet cloning/copying works (if implemented)
- High allocation rate succeeds
- Statistics are collected correctly
- Packet utilities work

### Test 1.4: Configuration Management
```bash
./tests/test_phase1_config
```

**Expected Output:**
- Configuration initialization succeeds
- Default configuration is set correctly
- Configuration get/validation works
- IP address parsing works
- IP to string conversion works
- Backup/rollback functions execute
- Configuration reload works

### Test 1.5: Logging Framework
```bash
./tests/test_phase1_logging
```

**Expected Output:**
- Logging initialization succeeds
- Log level setting works
- All log levels (EMERGENCY through DEBUG) execute
- Formatted log messages work
- Log rotation executes
- Structured logging works

### Test 1.6: Interface Abstraction
```bash
./tests/test_phase1_interfaces
```

**Expected Output:**
- Interface subsystem initialization succeeds
- Interface creation works (physical, VLAN)
- Interface lookup works (by name, by index)
- Interface state transitions work
- Link state detection works
- Interface statistics collection works
- VLAN interface creation works
- Interface count tracking works
- Helper functions work

## Step 3: Run All Tests with Script

Alternatively, use the test runner script:

```bash
cd /root/vbng
./tests/run_phase1_tests.sh
```

This will:
1. Configure CMake if needed
2. Build all test executables
3. Run each test sequentially
4. Print a summary of results

## Step 4: Use CTest (if available)

```bash
cd /root/vbng/build
ctest -R Phase1 -V
```

## Expected Test Results

All Phase 1 tests should pass if the implementation is complete. Some tests may gracefully handle:
- Missing DPDK library (tests will still pass)
- Optional features not yet implemented (tests handle gracefully)
- Missing configuration files (tests handle gracefully)

## Troubleshooting

### Build Errors
- Check that all source files exist
- Verify CMakeLists.txt files are correct
- Ensure all dependencies are installed

### Test Failures
- Check the test output for specific failure messages
- Verify the implementation matches the test expectations
- Some tests may need root privileges for DPDK functionality

### Missing Functions
- If a function is not implemented, the test may fail
- Update the implementation or mark the test as expected to fail

## Test Coverage Summary

- **Task 1.1**: 5 test groups, ~15 individual assertions
- **Task 1.2**: 5 test groups, ~10 individual assertions
- **Task 1.3**: 8 test groups, ~20 individual assertions
- **Task 1.4**: 10 test groups, ~15 individual assertions
- **Task 1.5**: 6 test groups, ~12 individual assertions
- **Task 1.6**: 10 test groups, ~25 individual assertions

**Total**: ~44 test groups, ~97 individual test assertions
