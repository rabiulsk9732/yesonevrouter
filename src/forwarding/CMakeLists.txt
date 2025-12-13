# src/forwarding/CMakeLists.txt

add_library(yesrouter_forwarding STATIC
    packet_rx.c
    packet_tx.c
    dpdk_lpm.c
    tx_batch.c
    session_table.c
    dpdk_flow.c
    dpdk_numa.c
    dpdk_timers.c
    pcap_tap.c
)

target_link_libraries(yesrouter_forwarding
    yesrouter_core
    yesrouter_interfaces
    yesrouter_network
    yesrouter_routing
    yesrouter_logging
    yesrouter_pppoe
    yesrouter_radius
    yesrouter_ippool
    yesrouter_qos
    yesrouter_natexport
)
