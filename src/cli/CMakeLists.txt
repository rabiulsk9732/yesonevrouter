# CLI Module CMakeLists.txt

set(CLI_SOURCES
    cli.c
    cli_socket.c
    cli_interface.c
    cli_route.c
    cli_arp.c
    cli_system.c
    cli_config.c
    cli_vlan.c
    cli_debug.c
    cli_nat.c
    cli_pppoe.c
    cli_ha.c
)

add_library(yesrouter_cli STATIC ${CLI_SOURCES})

target_include_directories(yesrouter_cli PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_cli
    yesrouter_interfaces
    yesrouter_network
    yesrouter_routing
    yesrouter_logging
    yesrouter_nat
    yesrouter_export
    pthread
)

# Link readline if available
if(HAVE_READLINE)
    target_link_libraries(yesrouter_cli ${READLINE_LIBRARY})
endif()
