# Tests CMakeLists.txt

# PPPoE Unit Tests
add_executable(pppoe_unit_tests pppoe_unit_tests.c)
target_link_libraries(pppoe_unit_tests
    yesrouter_pppoe
    yesrouter_radius
    yesrouter_qos
    yesrouter_ippool
    yesrouter_auth
    yesrouter_core
    yesrouter_network
    yesrouter_dpdk
    yesrouter_logging
    yesrouter_interfaces
    yesrouter_forwarding
    yesrouter_config
    yesrouter_routing
    yesrouter_nat
    yesrouter_ipv6
    yesrouter_natexport
    yesrouter_ha
    yesrouter_cli
    pthread
)

# RADIUS Unit Tests
add_executable(radius_unit_tests radius_unit_tests.c)
target_link_libraries(radius_unit_tests
    yesrouter_radius
    yesrouter_dpdk
    yesrouter_logging
    pthread
)

# RADIUS Integration Tests (requires FreeRADIUS)
add_executable(radius_integration_test radius_integration_test.c)
target_link_libraries(radius_integration_test
    yesrouter_radius
    yesrouter_dpdk
    yesrouter_logging
    pthread
)

# IPv6 Pool Test
add_executable(ipv6_pool_test ipv6_pool_test.c)
target_link_libraries(ipv6_pool_test
    yesrouter_ipv6
    yesrouter_logging
    pthread
)

# IPv6 Route Test
add_executable(ipv6_route_test ipv6_route_test.c)
target_link_libraries(ipv6_route_test
    yesrouter_ipv6
    yesrouter_logging
    pthread
)

# Register tests with CTest
enable_testing()

add_test(NAME pppoe_unit_tests COMMAND pppoe_unit_tests)
add_test(NAME radius_unit_tests COMMAND radius_unit_tests)
add_test(NAME ipv6_pool_test COMMAND ipv6_pool_test)
add_test(NAME ipv6_route_test COMMAND ipv6_route_test)
