# Logging Module CMakeLists.txt

set(LOGGING_SOURCES
    log.c
)

add_library(yesrouter_logging STATIC ${LOGGING_SOURCES})

target_include_directories(yesrouter_logging PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_logging
    pthread
)
