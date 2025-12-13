# Authentication Module CMakeLists.txt

set(AUTH_SOURCES
    user_db.c
    auth.c
    authz.c
    session.c
    local_auth.c
    password_hash.c
    audit_log.c
)

add_library(yesrouter_auth STATIC ${AUTH_SOURCES})

target_include_directories(yesrouter_auth PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(yesrouter_auth
    yesrouter_logging
    OpenSSL::Crypto
    pthread
)
