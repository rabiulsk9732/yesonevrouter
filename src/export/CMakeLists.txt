add_library(yesrouter_export STATIC
    exporter_core.c
    flow_cache.c
    nat_logger.c
)

target_include_directories(yesrouter_export PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yesrouter_export PUBLIC
    yesrouter_logging
    ${DPDK_LIBRARIES}
)
