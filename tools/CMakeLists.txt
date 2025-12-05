# Tools CMakeLists.txt

# NAT Load Test Tool
add_executable(nat_load_test nat_load_test.c)
target_link_libraries(nat_load_test
    yesrouter_nat
    yesrouter_core
    yesrouter_network
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_interfaces
    yesrouter_forwarding
    yesrouter_config
    yesrouter_routing
    yesrouter_cli
    yesrouter_ha
    pthread
)
