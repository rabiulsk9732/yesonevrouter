cmake_minimum_required(VERSION 3.16)
project(yesrouter VERSION 1.0.0 LANGUAGES C CXX)

# Set C/C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -march=native")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -mtune=native -funroll-loops -ffast-math -DNDEBUG")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

# Options
option(ENABLE_DPDK "Enable DPDK support" ON)
option(ENABLE_TESTS "Build unit tests" OFF)
option(ENABLE_BENCHMARKS "Build performance benchmarks" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

# AddressSanitizer support
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Find required packages
find_package(PkgConfig REQUIRED)

# DPDK support
if(ENABLE_DPDK)
    pkg_check_modules(DPDK libdpdk)
    if(DPDK_FOUND)
        include_directories(${DPDK_INCLUDE_DIRS})
        link_directories(${DPDK_LIBRARY_DIRS})
        add_definitions(-DHAVE_DPDK)
        message(STATUS "DPDK found: ${DPDK_VERSION}")
    else()
        message(WARNING "DPDK not found, building without DPDK support")
        set(ENABLE_DPDK OFF)
    endif()
endif()

# libyang for configuration
option(ENABLE_LIBYANG "Enable libyang support for YANG configuration" ON)
if(ENABLE_LIBYANG)
    pkg_check_modules(LIBYANG libyang)
    if(LIBYANG_FOUND)
        include_directories(${LIBYANG_INCLUDE_DIRS})
        link_directories(${LIBYANG_LIBRARY_DIRS})
        add_definitions(-DHAVE_LIBYANG)
        message(STATUS "libyang found: ${LIBYANG_VERSION}")
    else()
        message(WARNING "libyang not found, YANG configuration support disabled")
        message(WARNING "  Configuration will use simple key-value parser")
        set(ENABLE_LIBYANG OFF)
    endif()
else()
    message(STATUS "libyang support disabled by user")
endif()

# Threading
find_package(Threads REQUIRED)

# OpenSSL for password hashing
find_package(OpenSSL REQUIRED)

# GNU readline for CLI tab completion and history
find_library(READLINE_LIBRARY NAMES readline)
find_path(READLINE_INCLUDE_DIR readline/readline.h)
if(READLINE_LIBRARY AND READLINE_INCLUDE_DIR)
    include_directories(${READLINE_INCLUDE_DIR})
    add_definitions(-DHAVE_READLINE)
    message(STATUS "GNU readline found: ${READLINE_LIBRARY}")
    set(HAVE_READLINE TRUE)
else()
    message(WARNING "GNU readline not found, CLI will use basic line input")
    set(HAVE_READLINE FALSE)
endif()

# Source files - will be populated as modules are implemented
set(YESROUTER_SOURCES
    # Core
    # src/core/main.c
    # src/core/packet.c

    # DPDK
    # src/dpdk/dpdk_init.c

    # Configuration
    # src/config/config.c

    # Logging
    # src/logging/log.c

    # Add more source files as implemented
)

# Main executable
add_executable(yesrouter src/core/main.c)
target_link_libraries(yesrouter
    -Wl,--start-group
    yesrouter_interfaces
    yesrouter_network
    yesrouter_routing
    yesrouter_logging
    yesrouter_config
    yesrouter_auth
    yesrouter_forwarding
    yesrouter_dpdk
    yesrouter_radius
    yesrouter_ippool
    yesrouter_qos
    yesrouter_nat
    yesrouter_natexport
    yesrouter_management
    yesrouter_pppoe
    yesrouter_ipoe
    yesrouter_ipv6
    yesrouter_cli
    yesrouter_core
    pthread
    -Wl,--end-group
)

# Subdirectories
add_subdirectory(src/core)
add_subdirectory(src/interfaces)
add_subdirectory(src/network)
add_subdirectory(src/routing)
add_subdirectory(src/logging)
add_subdirectory(src/config)
add_subdirectory(src/auth)
add_subdirectory(src/forwarding)
add_subdirectory(src/dpdk)
add_subdirectory(src/nat)
add_subdirectory(src/ipv6)
add_subdirectory(src/radius)
add_subdirectory(src/ippool)
add_subdirectory(src/qos)
add_subdirectory(src/ha)
add_subdirectory(src/pppoe)
add_subdirectory(src/ipoe)
add_subdirectory(src/cli)
add_subdirectory(src/management)
add_subdirectory(src/natexport)

# yesrouterctl client tool (DEPRECATED - use vbng_cli instead)
# add_executable(yesrouterctl src/cli/yesrouterctl.c)
# if(HAVE_READLINE)
#     target_link_libraries(yesrouterctl ${READLINE_LIBRARY})
# endif()

# Testing
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Tools
# add_subdirectory(tools)  # Removed during cleanup

# Installation
# install(TARGETS yesrouter DESTINATION bin)
# install(DIRECTORY ${CMAKE_SOURCE_DIR}/docs/ DESTINATION share/doc/yesrouter)

# Print configuration summary
message(STATUS "")
message(STATUS "YESRouter vBNG Configuration Summary:")
message(STATUS "  Build Type:         ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler:         ${CMAKE_C_COMPILER}")
message(STATUS "  C++ Compiler:       ${CMAKE_CXX_COMPILER}")
message(STATUS "  DPDK Support:       ${ENABLE_DPDK}")
message(STATUS "  Tests:              ${ENABLE_TESTS}")
message(STATUS "  Benchmarks:         ${ENABLE_BENCHMARKS}")
message(STATUS "  AddressSanitizer:   ${ENABLE_ASAN}")
message(STATUS "")
