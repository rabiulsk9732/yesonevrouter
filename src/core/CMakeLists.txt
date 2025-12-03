# Core Module CMakeLists.txt

set(CORE_SOURCES
    main.c
    cpu_scheduler.c
)

add_executable(yesrouter ${CORE_SOURCES})

target_include_directories(yesrouter PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter
    yesrouter_dpdk
    ${CMAKE_THREAD_LIBS_INIT}
    pthread
)

if(ENABLE_DPDK AND DPDK_FOUND)
    target_link_libraries(yesrouter ${DPDK_LIBRARIES})
endif()

# Installation
install(TARGETS yesrouter DESTINATION bin)
