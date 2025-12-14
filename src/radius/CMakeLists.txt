set(RADIUS_SOURCES
    radius_lockless.c
)

add_library(yesrouter_radius STATIC ${RADIUS_SOURCES})

target_include_directories(yesrouter_radius PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link OpenSSL for crypto (MD5, HMAC)
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    target_link_libraries(yesrouter_radius PUBLIC OpenSSL::Crypto)
    target_compile_definitions(yesrouter_radius PRIVATE HAVE_OPENSSL)
endif()
