# Configuration Module CMakeLists.txt
# Using only env_config.c (.env Bison-style) - removed legacy yesrouter_config.c

set(CONFIG_SOURCES
    config.c
    env_config.c
    startup_json.c
)

add_library(yesrouter_config STATIC ${CONFIG_SOURCES})

target_include_directories(yesrouter_config PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link libyang if available
if(ENABLE_LIBYANG AND LIBYANG_FOUND)
    target_link_libraries(yesrouter_config ${LIBYANG_LIBRARIES})
    target_include_directories(yesrouter_config PRIVATE ${LIBYANG_INCLUDE_DIRS})
endif()
