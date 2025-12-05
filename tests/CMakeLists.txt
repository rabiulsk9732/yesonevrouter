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
    yesrouter_cli
    yesrouter_interfaces
    yesrouter_network
    yesrouter_routing
    yesrouter_logging
    yesrouter_nat
    yesrouter_ha
    yesrouter_auth
    yesrouter_pppoe
    yesrouter_dpdk
    yesrouter_ippool
    yesrouter_radius
    yesrouter_config
    yesrouter_cli
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
    yesrouter_network
    yesrouter_core
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_config
    pthread
)
add_test(NAME Phase1_Interfaces COMMAND test_phase1_interfaces)

# VLAN and LACP Fetcher Tests
add_executable(test_vlan_lacp test_vlan_lacp.c)
target_link_libraries(test_vlan_lacp
    yesrouter_interfaces
    yesrouter_network
    yesrouter_core
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_config
    pthread
)
add_test(NAME VLAN_LACP_Fetchers COMMAND test_vlan_lacp)

# Phase 2 Tests
add_executable(test_phase2_arp test_phase2_arp.c)
target_link_libraries(test_phase2_arp
    yesrouter_network
    yesrouter_core
    yesrouter_dpdk
    yesrouter_logging
    pthread
)
add_test(NAME Phase2_ARP COMMAND test_phase2_arp)

# NAT Per-Worker Tables Test
add_executable(test_nat_worker test_nat_worker.c)
target_link_libraries(test_nat_worker
    yesrouter_nat
    yesrouter_core
    yesrouter_network
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_config
    pthread
)
add_test(NAME NAT_Worker COMMAND test_nat_worker)

# ARP Queue Test
add_executable(test_arp_queue test_arp_queue.c)
target_link_libraries(test_arp_queue
    yesrouter_network
    yesrouter_core
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_interfaces
    yesrouter_forwarding
    pthread
)
add_test(NAME ARP_Queue COMMAND test_arp_queue)
