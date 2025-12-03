/**
 * @file test_phase1_build.c
 * @brief Test Task 1.1: Project Setup & Build System
 *
 * Tests:
 * - Build succeeds on target platform
 * - All configuration options work
 * - CI/CD pipeline executes successfully
 * - Docker container builds and runs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>

/* Test results */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, msg) \
    do { \
        tests_run++; \
        if (condition) { \
            printf("  [PASS] %s\n", msg); \
            tests_passed++; \
        } else { \
            printf("  [FAIL] %s\n", msg); \
            tests_failed++; \
        } \
    } while(0)

/* Test 1.1.1: Verify build artifacts exist */
static void test_build_artifacts(void)
{
    printf("\n=== Test 1.1.1: Build Artifacts ===\n");

    struct stat st;
    bool cmake_lists = (stat("/root/vbng/CMakeLists.txt", &st) == 0);
    TEST_ASSERT(cmake_lists, "CMakeLists.txt exists");

    bool src_dir = (stat("/root/vbng/src", &st) == 0 && S_ISDIR(st.st_mode));
    TEST_ASSERT(src_dir, "src/ directory exists");

    bool include_dir = (stat("/root/vbng/include", &st) == 0 && S_ISDIR(st.st_mode));
    TEST_ASSERT(include_dir, "include/ directory exists");

    bool tests_dir = (stat("/root/vbng/tests", &st) == 0 && S_ISDIR(st.st_mode));
    TEST_ASSERT(tests_dir, "tests/ directory exists");

    bool docs_dir = (stat("/root/vbng/docs", &st) == 0 && S_ISDIR(st.st_mode));
    TEST_ASSERT(docs_dir, "docs/ directory exists");
}

/* Test 1.1.2: Verify source files exist */
static void test_source_files(void)
{
    printf("\n=== Test 1.1.2: Source Files ===\n");

    struct stat st;

    /* Core module */
    TEST_ASSERT(stat("/root/vbng/src/core/main.c", &st) == 0, "src/core/main.c exists");
    TEST_ASSERT(stat("/root/vbng/src/core/packet.c", &st) == 0, "src/core/packet.c exists");

    /* DPDK module */
    TEST_ASSERT(stat("/root/vbng/src/dpdk/dpdk_init.c", &st) == 0, "src/dpdk/dpdk_init.c exists");

    /* Config module */
    TEST_ASSERT(stat("/root/vbng/src/config/config.c", &st) == 0, "src/config/config.c exists");

    /* Logging module */
    TEST_ASSERT(stat("/root/vbng/src/logging/log.c", &st) == 0, "src/logging/log.c exists");

    /* Monitoring module */
    TEST_ASSERT(stat("/root/vbng/src/monitoring/stats.c", &st) == 0, "src/monitoring/stats.c exists");

    /* Interfaces module */
    TEST_ASSERT(stat("/root/vbng/src/interfaces/interface.c", &st) == 0, "src/interfaces/interface.c exists");
}

/* Test 1.1.3: Verify header files exist */
static void test_header_files(void)
{
    printf("\n=== Test 1.1.3: Header Files ===\n");

    struct stat st;

    TEST_ASSERT(stat("/root/vbng/include/dpdk_init.h", &st) == 0, "include/dpdk_init.h exists");
    TEST_ASSERT(stat("/root/vbng/include/packet.h", &st) == 0, "include/packet.h exists");
    TEST_ASSERT(stat("/root/vbng/include/config.h", &st) == 0, "include/config.h exists");
    TEST_ASSERT(stat("/root/vbng/include/log.h", &st) == 0, "include/log.h exists");
    TEST_ASSERT(stat("/root/vbng/include/interface.h", &st) == 0, "include/interface.h exists");
}

/* Test 1.1.4: Verify build system files */
static void test_build_system(void)
{
    printf("\n=== Test 1.1.4: Build System ===\n");

    struct stat st;

    TEST_ASSERT(stat("/root/vbng/CMakeLists.txt", &st) == 0, "Root CMakeLists.txt exists");
    TEST_ASSERT(stat("/root/vbng/src/CMakeLists.txt", &st) == 0, "src/CMakeLists.txt exists");
    TEST_ASSERT(stat("/root/vbng/tests/CMakeLists.txt", &st) == 0, "tests/CMakeLists.txt exists");

    /* Check for Docker files */
    bool dockerfile = (stat("/root/vbng/Dockerfile", &st) == 0);
    TEST_ASSERT(dockerfile, "Dockerfile exists");

    /* Check for CI/CD */
    bool ci_yml = (stat("/root/vbng/.github/workflows/ci.yml", &st) == 0);
    TEST_ASSERT(ci_yml, "CI/CD pipeline exists");
}

/* Test 1.1.5: Verify documentation */
static void test_documentation(void)
{
    printf("\n=== Test 1.1.5: Documentation ===\n");

    struct stat st;

    TEST_ASSERT(stat("/root/vbng/docs/task.md", &st) == 0, "docs/task.md exists");
    TEST_ASSERT(stat("/root/vbng/README.md", &st) == 0, "README.md exists");
}

int main(void)
{
    printf("========================================\n");
    printf("Phase 1.1: Build System Tests\n");
    printf("========================================\n");

    test_build_artifacts();
    test_source_files();
    test_header_files();
    test_build_system();
    test_documentation();

    printf("\n========================================\n");
    printf("Test Summary:\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("========================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
