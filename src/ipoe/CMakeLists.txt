# IPoE Module CMakeLists.txt (DPDK Only)

set(IPOE_SOURCES
    ipoe.c
    ipoe_session.c
    ipoe_dhcp.c
    ipoe_radius.c
    ipoe_profile.c
    ipoe_timer.c
    ipoe_security.c
    ipoe_coa.c
    ipoe_pool_allocator.c
)

# Create static library
add_library(yesrouter_ipoe STATIC ${IPOE_SOURCES})

# Include directories
target_include_directories(yesrouter_ipoe
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src
)

# Link dependencies
target_link_libraries(yesrouter_ipoe
    PUBLIC pthread
)

# DPDK support (conditional)
if(DPDK_FOUND)
    target_compile_definitions(yesrouter_ipoe PRIVATE HAVE_DPDK)
    target_link_libraries(yesrouter_ipoe PUBLIC ${DPDK_LIBRARIES})
endif()

# Compiler options
target_compile_options(yesrouter_ipoe PRIVATE
    -Wall
    -Wextra
    -O2
)
