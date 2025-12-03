# Tests CMakeLists.txt

# Find GTest
find_package(GTest)

if(NOT GTEST_FOUND)
    message(STATUS "GTest not found, downloading from source...")
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Test executables will be added here as modules are implemented

# Example:
# add_executable(test_packet test_packet.c)
# target_link_libraries(test_packet GTest::GTest GTest::Main)
# add_test(NAME PacketTest COMMAND test_packet)
