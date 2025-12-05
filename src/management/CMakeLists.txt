# src/management/CMakeLists.txt

add_library(yesrouter_management STATIC
    metrics.c
    session_export.c
    syslog_logger.c
    rest_api.c
)

target_include_directories(yesrouter_management PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_management
    yesrouter_logging
    pthread
)
