# DPDK Module CMakeLists.txt

set(DPDK_SOURCES
    dpdk_init.c
)

add_library(yesrouter_dpdk STATIC ${DPDK_SOURCES})

target_include_directories(yesrouter_dpdk PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

if(ENABLE_DPDK AND DPDK_FOUND)
    target_link_libraries(yesrouter_dpdk ${DPDK_LIBRARIES})
endif()
