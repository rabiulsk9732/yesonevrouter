# Phase 1 Test Plan

This document describes the test suite for Phase 1: Foundation & Core Infrastructure.

## Test Files Created

### 1. test_phase1_build.c
**Tests Task 1.1: Project Setup & Build System**
- Build artifacts exist (CMakeLists.txt, directories)
- Source files exist
- Header files exist
- Build system files exist
- Documentation exists

### 2. test_phase1_dpdk.c
**Tests Task 1.2: DPDK Integration & Initialization**
- DPDK initialization (handles missing DPDK gracefully)
- Memory pool creation
- CPU core functions (lcore count, socket ID, affinity)
- DPDK cleanup
- Configuration structure

### 3. test_phase1_packet.c
**Tests Task 1.3: Packet Buffer Management**
- Packet buffer initialization
- Packet allocation/deallocation
- Packet metadata extraction
- Packet cloning
- Packet copying
- High allocation rate handling
- Packet statistics
- Packet utilities

### 4. test_phase1_config.c
**Tests Task 1.4: Configuration Management Framework**
- Configuration initialization
- Default configuration
- Configuration get/validation
- IP address parsing
- IP address to string conversion
- Configuration backup/rollback
- Configuration reload
- Configuration print

### 5. test_phase1_logging.c
**Tests Task 1.5: Logging & Monitoring Framework**
- Logging initialization
- Log level setting
- All log level messages (EMERGENCY through DEBUG)
- Formatted log messages
- Log rotation
- Structured logging

### 6. test_phase1_interfaces.c
**Tests Task 1.6: Interface Abstraction Layer**
- Interface subsystem initialization
- Interface creation (physical, VLAN)
- Interface lookup (by name, by index)
- Interface state transitions (UP/DOWN)
- Link state detection
- Interface statistics
- VLAN interface creation
- Interface count
- Helper functions
- Interface print

## Running Tests

### Option 1: Run All Tests with Script
```bash
cd /root/vbng
./tests/run_phase1_tests.sh
```

### Option 2: Run Tests Individually
```bash
cd /root/vbng/build

# Build all tests
cmake --build . --target test_phase1_build test_phase1_dpdk test_phase1_packet \
      test_phase1_config test_phase1_logging test_phase1_interfaces

# Run individual tests
./tests/test_phase1_build
./tests/test_phase1_dpdk
./tests/test_phase1_packet
./tests/test_phase1_config
./tests/test_phase1_logging
./tests/test_phase1_interfaces
```

### Option 3: Use CTest
```bash
cd /root/vbng/build
ctest -R Phase1
```

## Test Coverage

Each test file covers the test cases specified in `docs/task.md` for the corresponding Phase 1 task:

- **Task 1.1**: Build system verification
- **Task 1.2**: DPDK initialization, memory pools, CPU affinity, ring buffers, statistics
- **Task 1.3**: Allocation/free, metadata extraction, cloning, leak detection, high rate
- **Task 1.4**: Parse valid/invalid configs, hot-reload, rollback, validation
- **Task 1.5**: Log levels, syslog, rotation, statistics, metrics, health checks
- **Task 1.6**: Interface init, link detection, statistics, VLAN, state transitions

## Expected Results

All tests should pass if Phase 1 implementation is complete. Some tests may gracefully handle missing optional features (e.g., DPDK library) and still pass.

## Notes

- Tests are designed to be non-destructive and can be run multiple times
- Some tests may require root privileges for DPDK functionality
- Tests handle missing optional dependencies gracefully
- Each test prints a summary of passed/failed tests
