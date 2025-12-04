# src/forwarding/CMakeLists.txt

add_library(yesrouter_forwarding STATIC
    packet_rx.c
    packet_tx.c
)

target_link_libraries(yesrouter_forwarding
    yesrouter_core
    yesrouter_interfaces
    yesrouter_network
    yesrouter_routing
    yesrouter_logging
)
