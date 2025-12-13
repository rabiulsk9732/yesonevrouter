# Core Module CMakeLists.txt

# Create core library (for tests and reuse)
set(CORE_LIB_SOURCES
    cpu_scheduler.c
    packet.c
    missing_stubs.c
    control_plane.c
    daemon.c
)

add_library(yesrouter_core STATIC ${CORE_LIB_SOURCES})

target_include_directories(yesrouter_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_core
    yesrouter_dpdk
    ${CMAKE_THREAD_LIBS_INIT}
    pthread
)

if(ENABLE_DPDK AND DPDK_FOUND)
    target_link_libraries(yesrouter_core ${DPDK_LIBRARIES})
endif()
