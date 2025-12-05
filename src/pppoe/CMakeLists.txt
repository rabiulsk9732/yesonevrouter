set(PPPOE_SOURCES
    pppoe.c
    ppp_lcp.c
    ppp_ipcp.c
    ppp_auth.c
    pppoe_security.c
    service_profile.c
    arp_protect.c
    ppp_debug.c
    mschap.c
)

add_library(yesrouter_pppoe STATIC ${PPPOE_SOURCES})

target_include_directories(yesrouter_pppoe PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
