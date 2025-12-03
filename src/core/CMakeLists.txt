# Core Module CMakeLists.txt

# Create core library (for tests and reuse)
set(CORE_LIB_SOURCES
    cpu_scheduler.c
    packet.c
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

# Main executable
add_executable(yesrouter main.c)

target_include_directories(yesrouter PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter
    yesrouter_core
    yesrouter_dpdk
    yesrouter_config
    yesrouter_logging
    yesrouter_monitoring
    yesrouter_interfaces
    ${CMAKE_THREAD_LIBS_INIT}
    pthread
)

if(ENABLE_DPDK AND DPDK_FOUND)
    target_link_libraries(yesrouter ${DPDK_LIBRARIES})
endif()

# Installation
install(TARGETS yesrouter DESTINATION bin)
