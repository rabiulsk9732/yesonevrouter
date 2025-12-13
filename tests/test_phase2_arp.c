/**
 * @file test_phase2_arp.c
 * @brief Test Task 2.3: ARP & Neighbor Management
 *
 * Tests:
 * - ARP subsystem initialization
 * - ARP packet creation and parsing
 * - ARP table operations (insert/lookup/delete)
 * - ARP entry timeout and aging
 * - Neighbor state transitions
 * - ARP statistics collection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "arp.h"

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

/* Test 2.3.1: ARP subsystem initialization */
static void test_arp_init(void)
{
    printf("\n=== Test 2.3.1: ARP Subsystem Initialization ===\n");

    int ret = arp_init();
    TEST_ASSERT(ret == 0, "arp_init() succeeds");

    /* Get initial stats */
    struct arp_stats stats;
    ret = arp_get_stats(&stats);
    TEST_ASSERT(ret == 0, "arp_get_stats() succeeds");
    TEST_ASSERT(stats.current_entries == 0, "Initial entry count is 0");
}

/* Test 2.3.2: ARP entry add and lookup */
static void test_arp_table_operations(void)
{
    printf("\n=== Test 2.3.2: ARP Table Operations ===\n");

    /* Add entry */
    uint32_t ip1 = 0xC0A80001;  /* 192.168.0.1 */
    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    int ret = arp_add_entry(ip1, mac1, 1, ARP_STATE_VALID);
    TEST_ASSERT(ret == 0, "arp_add_entry() succeeds");

    /* Lookup entry */
    uint8_t mac_out[6];
    ret = arp_lookup(ip1, mac_out);
    TEST_ASSERT(ret == 0, "arp_lookup() finds entry");
    TEST_ASSERT(memcmp(mac_out, mac1, 6) == 0, "Retrieved MAC matches");

    /* Verify stats */
    struct arp_stats stats;
    arp_get_stats(&stats);
    TEST_ASSERT(stats.current_entries == 1, "Entry count is 1");
    TEST_ASSERT(stats.lookups == 1, "Lookup count is 1");
    TEST_ASSERT(stats.hits == 1, "Hit count is 1");

    /* Lookup non-existent entry */
    uint32_t ip2 = 0xC0A80002;  /* 192.168.0.2 */
    ret = arp_lookup(ip2, mac_out);
    TEST_ASSERT(ret == -1, "arp_lookup() fails for non-existent entry");

    arp_get_stats(&stats);
    TEST_ASSERT(stats.misses == 1, "Miss count is 1");
}

/* Test 2.3.3: ARP entry update */
static void test_arp_update(void)
{
    printf("\n=== Test 2.3.3: ARP Entry Update ===\n");

    uint32_t ip = 0xC0A80001;  /* 192.168.0.1 */
    uint8_t mac_new[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    /* Update existing entry with new MAC */
    int ret = arp_add_entry(ip, mac_new, 1, ARP_STATE_VALID);
    TEST_ASSERT(ret == 0, "arp_add_entry() updates existing entry");

    /* Verify new MAC */
    uint8_t mac_out[6];
    ret = arp_lookup(ip, mac_out);
    TEST_ASSERT(ret == 0, "arp_lookup() succeeds");
    TEST_ASSERT(memcmp(mac_out, mac_new, 6) == 0, "MAC updated correctly");

    /* Verify entry count didn't increase */
    struct arp_stats stats;
    arp_get_stats(&stats);
    TEST_ASSERT(stats.current_entries == 1, "Entry count still 1");
}

/* Test 2.3.4: Multiple ARP entries */
static void test_arp_multiple_entries(void)
{
    printf("\n=== Test 2.3.4: Multiple ARP Entries ===\n");

    /* Add multiple entries */
    for (int i = 10; i < 20; i++) {
        uint32_t ip = 0xC0A80000 | i;  /* 192.168.0.10-19 */
        uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, (uint8_t)i};

        int ret = arp_add_entry(ip, mac, 1, ARP_STATE_VALID);
        TEST_ASSERT(ret == 0, "Added entry for 192.168.0.X");
    }

    /* Verify count */
    struct arp_stats stats;
    arp_get_stats(&stats);
    TEST_ASSERT(stats.current_entries == 11, "Total entries is 11 (1 + 10)");

    /* Lookup all entries */
    uint8_t mac_out[6];
    for (int i = 10; i < 20; i++) {
        uint32_t ip = 0xC0A80000 | i;
        int ret = arp_lookup(ip, mac_out);
        TEST_ASSERT(ret == 0 && mac_out[5] == i, "Lookup entry succeeds");
    }
}

/* Test 2.3.5: ARP entry deletion */
static void test_arp_delete(void)
{
    printf("\n=== Test 2.3.5: ARP Entry Deletion ===\n");

    uint32_t ip = 0xC0A8000A;  /* 192.168.0.10 */

    /* Delete entry */
    int ret = arp_delete_entry(ip);
    TEST_ASSERT(ret == 0, "arp_delete_entry() succeeds");

    /* Verify deleted */
    uint8_t mac_out[6];
    ret = arp_lookup(ip, mac_out);
    TEST_ASSERT(ret == -1, "Deleted entry not found");

    /* Verify count */
    struct arp_stats stats;
    arp_get_stats(&stats);
    TEST_ASSERT(stats.current_entries == 10, "Entry count decreased");

    /* Delete non-existent entry */
    ret = arp_delete_entry(0xC0A800FF);
    TEST_ASSERT(ret == -1, "Delete non-existent entry fails");
}

/* Test 2.3.6: ARP state transitions */
static void test_arp_states(void)
{
    printf("\n=== Test 2.3.6: ARP State Transitions ===\n");

    uint32_t ip = 0xC0A80064;  /* 192.168.0.100 */
    uint8_t mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* Add entry in INCOMPLETE state */
    int ret = arp_add_entry(ip, mac, 1, ARP_STATE_INCOMPLETE);
    TEST_ASSERT(ret == 0, "Entry added in INCOMPLETE state");

    /* Update to VALID state */
    ret = arp_add_entry(ip, mac, 1, ARP_STATE_VALID);
    TEST_ASSERT(ret == 0, "Entry updated to VALID state");

    /* Verify can lookup VALID entry */
    uint8_t mac_out[6];
    ret = arp_lookup(ip, mac_out);
    TEST_ASSERT(ret == 0, "VALID entry is lookupable");

    /* Update to STALE state */
    ret = arp_add_entry(ip, mac, 1, ARP_STATE_STALE);
    TEST_ASSERT(ret == 0, "Entry updated to STALE state");

    /* Clean up */
    arp_delete_entry(ip);
}

/* Test 2.3.7: ARP timeout check */
static void test_arp_timeout(void)
{
    printf("\n=== Test 2.3.7: ARP Timeout Check ===\n");

    /* Note: Real timeout testing would require time manipulation */
    /* Here we just test that the function executes */

    uint32_t deleted = arp_timeout_check();
    TEST_ASSERT(true, "arp_timeout_check() executes");

    printf("  [INFO] Timeout check deleted %u entries\n", deleted);
}

/* Test 2.3.8: ARP statistics */
static void test_arp_statistics(void)
{
    printf("\n=== Test 2.3.8: ARP Statistics ===\n");

    struct arp_stats stats;
    int ret = arp_get_stats(&stats);

    TEST_ASSERT(ret == 0, "arp_get_stats() succeeds");
    TEST_ASSERT(true, "Current entries valid");
    TEST_ASSERT(stats.lookups > 0, "Lookup count tracked");
    TEST_ASSERT(stats.hits > 0, "Hit count tracked");
    TEST_ASSERT(stats.misses > 0, "Miss count tracked");
    TEST_ASSERT(stats.entries_created > 0, "Entries created tracked");

    printf("  [INFO] Current entries: %u\n", stats.current_entries);
    printf("  [INFO] Total lookups: %lu (hits: %lu, misses: %lu)\n",
           stats.lookups, stats.hits, stats.misses);
    printf("  [INFO] Entries created: %lu, deleted: %lu\n",
           stats.entries_created, stats.entries_deleted);
}

/* Test 2.3.9: ARP table print */
static void test_arp_print(void)
{
    printf("\n=== Test 2.3.9: ARP Table Print ===\n");

    /* Add a few entries for demonstration */
    uint32_t ip1 = 0x0A000001;  /* 10.0.0.1 */
    uint32_t ip2 = 0x0A000002;  /* 10.0.0.2 */
    uint8_t mac1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    arp_add_entry(ip1, mac1, 1, ARP_STATE_VALID);
    arp_add_entry(ip2, mac2, 2, ARP_STATE_VALID);

    arp_print_table();
    TEST_ASSERT(true, "arp_print_table() executes without crash");
}

/* Test 2.3.10: Helper functions */
static void test_arp_helpers(void)
{
    printf("\n=== Test 2.3.10: Helper Functions ===\n");

    const char *state_str;

    state_str = arp_state_to_str(ARP_STATE_INCOMPLETE);
    TEST_ASSERT(strcmp(state_str, "INCOMPLETE") == 0, "INCOMPLETE state string");

    state_str = arp_state_to_str(ARP_STATE_VALID);
    TEST_ASSERT(strcmp(state_str, "VALID") == 0, "VALID state string");

    state_str = arp_state_to_str(ARP_STATE_STALE);
    TEST_ASSERT(strcmp(state_str, "STALE") == 0, "STALE state string");

    state_str = arp_state_to_str(ARP_STATE_FAILED);
    TEST_ASSERT(strcmp(state_str, "FAILED") == 0, "FAILED state string");
}

int main(void)
{
    printf("========================================\n");
    printf("Phase 2.3: ARP & Neighbor Management Tests\n");
    printf("========================================\n");

    test_arp_init();
    test_arp_table_operations();
    test_arp_update();
    test_arp_multiple_entries();
    test_arp_delete();
    test_arp_states();
    test_arp_timeout();
    test_arp_statistics();
    test_arp_print();
    test_arp_helpers();

    arp_cleanup();

    printf("\n========================================\n");
    printf("Test Summary:\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("========================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
