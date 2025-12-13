add_library(yesrouter_ipv6
    ipv6_core.c
    ipv6_fetcher.c
    ipv6_pool.c
    ipv6_route.c
    ipv6_ndp.c
    ipv6_dhcpv6pd.c
)

target_include_directories(yesrouter_ipv6 PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(yesrouter_ipv6 yesrouter_logging pthread)
