set(RADIUS_SOURCES
    radius.c
)

add_library(yesrouter_radius STATIC ${RADIUS_SOURCES})

target_include_directories(yesrouter_radius PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
