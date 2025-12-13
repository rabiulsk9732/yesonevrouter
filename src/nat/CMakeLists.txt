# NAT Module CMakeLists

add_library(yesrouter_nat
    nat_core.c
    nat_session.c
    nat_translate.c
    nat_portblock.c
    nat_deterministic.c
    nat_hairpin.c
    alg_icmp.c
    alg_sip.c
    alg_ftp.c
    nat_alg.c
    nat_log.c
    nat_worker.c
    nat_fastpath.c
    nat64.c
    nat_ha.c
    nat_rss.c
    nat_dpdk_fastpath.c
)

target_link_libraries(yesrouter_nat
    yesrouter_core
    yesrouter_network
    yesrouter_natexport
    pthread
)
