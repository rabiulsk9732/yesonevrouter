set(ACCESS_SOURCES
    # Empty for now, or remove directory if fully migrated
)

target_include_directories(yesrouter_access PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_access PUBLIC
    yesrouter_core
    yesrouter_interfaces
    ${DPDK_LIBRARIES}
)
