/**
 * @file test_nat_worker.c
 * @brief Test per-worker NAT session tables
 */

#include "../include/nat.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test 1: Worker ID assignment */
static void test_worker_assignment(void)
{
    printf("Test 1: Worker ID assignment\n");

    /* Set up 4 workers */
    nat_set_num_workers(4);
    assert(nat_get_num_workers() == 4);

    printf("  ✓ Worker count set to 4\n");
}

/* Test 2: Session creation with worker assignment */
static void test_session_worker_assignment(void)
{
    printf("Test 2: Session creation with worker assignment\n");

    /* Create a session */
    uint32_t inside_ip = 0xAC101002;  /* 172.16.16.2 */
    uint16_t inside_port = 12345;
    uint32_t outside_ip = 0x67AEF743; /* 103.174.247.67 */
    uint16_t outside_port = 54321;
    uint8_t protocol = IPPROTO_TCP;

    struct nat_session *session = nat_session_create(
        inside_ip, inside_port, outside_ip, outside_port, protocol, 0, 0);

    assert(session != NULL);
    printf("  ✓ Session created\n");

    /* Verify session data */
    assert(session->inside_ip == inside_ip);
    assert(session->inside_port == inside_port);
    assert(session->outside_ip == outside_ip);
    assert(session->outside_port == outside_port);
    assert(session->protocol == protocol);
    printf("  ✓ Session data correct\n");

    /* Cleanup */
    nat_session_delete(session);
    printf("  ✓ Session deleted\n");
}

/* Test 3: Per-worker statistics */
static void test_worker_statistics(void)
{
    printf("Test 3: Per-worker statistics\n");

    /* Get stats pointer for worker 0 */
    struct nat_worker_data *stats = nat_get_worker_stats_ptr(0);
    assert(stats != NULL);
    printf("  ✓ Worker 0 stats retrieved\n");
    printf("    In2Out hits: %lu\n", stats->in2out_hits);
    printf("    In2Out misses: %lu\n", stats->in2out_misses);
    printf("    Sessions created: %lu\n", stats->sessions_created);
}

int main(void)
{
    printf("========================================\n");
    printf("NAT Per-Worker Tables Test\n");
    printf("========================================\n\n");

    /* Initialize NAT */
    if (nat_init() != 0) {
        fprintf(stderr, "Failed to initialize NAT\n");
        return 1;
    }

    if (nat_session_init() != 0) {
        fprintf(stderr, "Failed to initialize NAT sessions\n");
        return 1;
    }

    /* Create a NAT pool for testing */
    nat_pool_create("TEST", 0x67AEF743, 0x67AEF743, 0xFFFFFF00);

    test_worker_assignment();
    test_session_worker_assignment();
    test_worker_statistics();

    printf("\n========================================\n");
    printf("All tests passed!\n");
    printf("========================================\n");

    nat_cleanup();
    return 0;
}
