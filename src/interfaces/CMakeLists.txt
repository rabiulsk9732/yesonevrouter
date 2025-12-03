# Interfaces Module CMakeLists.txt

set(INTERFACES_SOURCES
    interface.c
    physical.c
    virtual.c
)

add_library(yesrouter_interfaces STATIC ${INTERFACES_SOURCES})

target_include_directories(yesrouter_interfaces PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_interfaces
    yesrouter_dpdk
    ${CMAKE_THREAD_LIBS_INIT}
)
