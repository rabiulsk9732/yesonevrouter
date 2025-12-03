# Tests CMakeLists.txt

# Phase 1 Tests

# Test 1.1: Build System (no library dependencies)
add_executable(test_phase1_build test_phase1_build.c)
add_test(NAME Phase1_Build COMMAND test_phase1_build)

# Test 1.2: DPDK Integration
add_executable(test_phase1_dpdk test_phase1_dpdk.c)
target_link_libraries(test_phase1_dpdk
    yesrouter_dpdk
    pthread
)
add_test(NAME Phase1_DPDK COMMAND test_phase1_dpdk)

# Test 1.3: Packet Buffer Management
add_executable(test_phase1_packet test_phase1_packet.c)
target_link_libraries(test_phase1_packet
    yesrouter_core
    yesrouter_dpdk
    pthread
)
add_test(NAME Phase1_Packet COMMAND test_phase1_packet)

# Test 1.4: Configuration Management
add_executable(test_phase1_config test_phase1_config.c)
target_link_libraries(test_phase1_config
    yesrouter_config
)
add_test(NAME Phase1_Config COMMAND test_phase1_config)

# Test 1.5: Logging Framework
add_executable(test_phase1_logging test_phase1_logging.c)
target_link_libraries(test_phase1_logging
    yesrouter_logging
    pthread
)
add_test(NAME Phase1_Logging COMMAND test_phase1_logging)

# Test 1.6: Interface Abstraction
add_executable(test_phase1_interfaces test_phase1_interfaces.c)
target_link_libraries(test_phase1_interfaces
    yesrouter_interfaces
    yesrouter_dpdk
    yesrouter_logging
    pthread
)
add_test(NAME Phase1_Interfaces COMMAND test_phase1_interfaces)
