add_library(yesrouter_natexport STATIC
    natexport.c
)

target_include_directories(yesrouter_natexport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link with required libraries for DPDK send path
target_link_libraries(yesrouter_natexport PRIVATE
    yesrouter_interfaces
    yesrouter_routing
    yesrouter_network
    pthread
)

# Add DPDK flags if available
if(DPDK_FOUND)
    target_link_libraries(yesrouter_natexport PRIVATE ${DPDK_LIBRARIES})
endif()
