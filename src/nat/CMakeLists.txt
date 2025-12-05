# NAT Module CMakeLists

add_library(yesrouter_nat
    nat_core.c
    nat_session.c
    nat_translate.c
    nat_portblock.c
    nat_deterministic.c
    nat_hairpin.c
    alg_icmp.c
    nat_log.c
    nat_ipfix.c
    nat_netflow.c
    nat_worker.c
)

target_link_libraries(yesrouter_nat
    yesrouter_core
    yesrouter_network
    pthread
)
