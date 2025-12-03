# Monitoring Module CMakeLists.txt

set(MONITORING_SOURCES
    stats.c
)

add_library(yesrouter_monitoring STATIC ${MONITORING_SOURCES})

target_include_directories(yesrouter_monitoring PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_monitoring
    yesrouter_logging
    pthread
    m
)
