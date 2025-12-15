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

/* Test 4: 10M Session Distribution */
static void test_10m_session_distribution(void)
{
    printf("Test 4: 10M Session Distribution (Simplified - Test 1000 sessions)\n");

    /* Set up 4 workers */
    nat_set_num_workers(4);

    /* Create 1000 sessions and check distribution */
    uint32_t worker_counts[4] = {0, 0, 0, 0};
    uint32_t num_sessions = 1000;

    printf("  Creating %u test sessions...\n", num_sessions);

    for (uint32_t i = 0; i < num_sessions; i++) {
        uint32_t inside_ip = 0xAC100000 | (i >> 8); /* 172.16.X.X */
        uint16_t inside_port = 1024 + (i % 64512);
        uint32_t outside_ip = 0x67AEF743; /* 103.174.247.67 */
        uint16_t outside_port = 1024 + i;
        uint8_t protocol = (i % 3 == 0) ? IPPROTO_TCP : (i % 3 == 1) ? IPPROTO_UDP : IPPROTO_ICMP;

        struct nat_session *session = nat_session_create(inside_ip, inside_port, outside_ip,
                                                         outside_port, protocol, 0, 0);

        if (session) {
            worker_counts[session->owner_worker]++;
        }

        /* Print progress every 100 sessions */
        if ((i + 1) % 100 == 0) {
            printf("  Created %u sessions...\n", i + 1);
        }
    }

    printf("\n  Session distribution across workers:\n");
    for (int i = 0; i < 4; i++) {
        double percent = (double)worker_counts[i] / num_sessions * 100.0;
        printf("    Worker %d: %u sessions (%.1f%%)\n", i, worker_counts[i], percent);
    }

    /* Check that distribution is reasonably even (within 15% of expected 25%) */
    for (int i = 0; i < 4; i++) {
        double percent = (double)worker_counts[i] / num_sessions * 100.0;
        assert(percent >= 10.0 && percent <= 40.0);
    }

    printf("  ✓ Session distribution is reasonably even\n");

    /* Print load balance statistics if function is available */
#ifdef HAVE_DPDK
    printf("\n");
    nat_worker_print_load_balance();
#endif
}

/* Test 5: ICMP Session Creation and Lookup */
static void test_icmp_sessions(void)
{
    printf("Test 5: ICMP Session Creation and Lookup\n");

    /* Create ICMP session */
    uint32_t inside_ip = 0xAC101003;  /* 172.16.16.3 */
    uint16_t inside_port = 1234;      /* ICMP identifier */
    uint32_t outside_ip = 0x67AEF744; /* 103.174.247.68 */
    uint16_t outside_port = 1234;     /* Should be same as inside for ICMP */
    uint8_t protocol = IPPROTO_ICMP;

    /* Create session */
    struct nat_session *session = nat_session_create(inside_ip, inside_port, outside_ip,
                                                     outside_port, protocol, 0, 0);

    assert(session != NULL);
    printf("  ✓ ICMP session created\n");

    /* Verify EIM: inside_port == outside_port for ICMP */
    assert(session->inside_port == session->outside_port);
    printf("  ✓ ICMP EIM verified (inside_port == outside_port)\n");

    /* Lookup by inside */
    struct nat_session *lookup_in = nat_session_lookup_inside(inside_ip, inside_port, protocol);
    assert(lookup_in != NULL);
    printf("  ✓ ICMP inside lookup successful\n");

    /* Lookup by outside */
    struct nat_session *lookup_out = nat_session_lookup_outside(outside_ip, outside_port, protocol);
    assert(lookup_out != NULL);
    printf("  ✓ ICMP outside lookup successful\n");

    /* Verify same session returned */
    assert(lookup_in == lookup_out);
    printf("  ✓ ICMP session consistency verified\n");

    /* Cleanup */
    nat_session_delete(session);
    printf("  ✓ ICMP session deleted\n");
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
    test_10m_session_distribution();
    test_icmp_sessions();

    printf("\n========================================\n");
    printf("All tests passed!\n");
    printf("========================================\n");

    nat_cleanup();
    return 0;
}
