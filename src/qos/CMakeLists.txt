set(QOS_SOURCES
    qos.c
    hqos.c
)

add_library(yesrouter_qos STATIC ${QOS_SOURCES})

target_include_directories(yesrouter_qos PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
