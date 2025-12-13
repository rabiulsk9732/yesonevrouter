# Routing Module CMakeLists.txt

set(ROUTING_SOURCES
    routing_table.c
)

add_library(yesrouter_routing STATIC ${ROUTING_SOURCES})

target_include_directories(yesrouter_routing PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_routing
    ${CMAKE_THREAD_LIBS_INIT}
    pthread
)
