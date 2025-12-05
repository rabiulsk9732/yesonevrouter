set(HA_SOURCES
    ha.c
    ha_active_active.c
    ha_accounting_sync.c
    worker_manager.c
)

add_library(yesrouter_ha STATIC ${HA_SOURCES})

target_include_directories(yesrouter_ha PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
