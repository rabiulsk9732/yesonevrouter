set(IPPOOL_SOURCES
    ippool.c
)

add_library(yesrouter_ippool STATIC ${IPPOOL_SOURCES})

target_include_directories(yesrouter_ippool PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
