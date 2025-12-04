# CLI Module CMakeLists.txt

set(CLI_SOURCES
    cli.c
    cli_interface.c
    cli_route.c
    cli_arp.c
    cli_system.c
    cli_auth.c
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
    yesrouter_auth
)
