# CLI Module CMakeLists.txt
# Clean Cisco IOS / FRR Style CLI Implementation

set(CLI_SOURCES
    vty.c
    command.c
    cli_pppoe.c
    cli_interface.c
    cli_system.c
    cli_radius.c
    cli_ippool.c
    cli_route.c
)

add_library(yesrouter_cli STATIC ${CLI_SOURCES})

target_include_directories(yesrouter_cli PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(yesrouter_cli
    pthread
)
