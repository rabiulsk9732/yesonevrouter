# Network Module CMakeLists.txt

set(NETWORK_SOURCES
    arp.c
    dns.c
    neighbor.c
)

add_library(yesrouter_network STATIC ${NETWORK_SOURCES})

target_include_directories(yesrouter_network PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_network
    yesrouter_interfaces
    yesrouter_logging
    pthread
)
