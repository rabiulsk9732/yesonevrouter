/**
 * @file test_nat_session.c
 * @brief Unit tests for NAT session table
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "nat.h"

#define TEST_PASS() printf("✓ %s PASSED\n", __func__)
#define TEST_FAIL() do { printf("✗ %s FAILED at line %d\n", __func__, __LINE__); return -1; } while(0)

/* Test: NAT initialization */
static int test_nat_init(void)
{
    assert(nat_init() == 0);
    TEST_PASS();
    return 0;
}

/* Test: NAT pool creation */
static int test_nat_pool_create(void)
{
    uint32_t start_ip, end_ip, netmask;
    struct in_addr addr;

    /* 192.168.1.1 - 192.168.1.255 */
    inet_pton(AF_INET, "192.168.1.1", &addr);
    start_ip = ntohl(addr.s_addr);

    inet_pton(AF_INET, "192.168.1.255", &addr);
    end_ip = ntohl(addr.s_addr);

    netmask = 0xFFFFFF00;  /* 255.255.255.0 */

    assert(nat_pool_create("TEST_POOL", start_ip, end_ip, netmask) == 0);

    TEST_PASS();
    return 0;
}

/* Test: NAT session creation */
static int test_nat_session_create(void)
{
    uint32_t inside_ip, outside_ip;
    uint16_t inside_port = 12345;
    uint16_t outside_port = 54321;
    uint8_t protocol = IPPROTO_TCP;
    struct in_addr addr;

    /* Inside IP: 10.0.0.100 */
    inet_pton(AF_INET, "10.0.0.100", &addr);
    inside_ip = ntohl(addr.s_addr);

    /* Outside IP: 192.168.1.10 */
    inet_pton(AF_INET, "192.168.1.10", &addr);
    outside_ip = ntohl(addr.s_addr);

    struct nat_session *session = nat_session_create(inside_ip, inside_port,
                                                      outside_ip, outside_port,
                                                      protocol, 0, 0);

    assert(session != NULL);
    assert(session->inside_ip == inside_ip);
    assert(session->inside_port == inside_port);
    assert(session->outside_ip == outside_ip);
    assert(session->outside_port == outside_port);
    assert(session->protocol == protocol);
    assert(session->session_id > 0);

    TEST_PASS();
    return 0;
}

/* Test: NAT session lookup by inside tuple */
static int test_nat_session_lookup_inside(void)
{
    uint32_t inside_ip;
    uint16_t inside_port = 12345;
    uint8_t protocol = IPPROTO_TCP;
    struct in_addr addr;

    inet_pton(AF_INET, "10.0.0.100", &addr);
    inside_ip = ntohl(addr.s_addr);

    struct nat_session *session = nat_session_lookup_inside(inside_ip, inside_port, protocol);

    assert(session != NULL);
    assert(session->inside_ip == inside_ip);
    assert(session->inside_port == inside_port);

    TEST_PASS();
    return 0;
}

/* Test: NAT session lookup by outside tuple */
static int test_nat_session_lookup_outside(void)
{
    uint32_t outside_ip;
    uint16_t outside_port = 54321;
    uint8_t protocol = IPPROTO_TCP;
    struct in_addr addr;

    inet_pton(AF_INET, "192.168.1.10", &addr);
    outside_ip = ntohl(addr.s_addr);

    struct nat_session *session = nat_session_lookup_outside(outside_ip, outside_port, protocol);

    assert(session != NULL);
    assert(session->outside_ip == outside_ip);
    assert(session->outside_port == outside_port);

    TEST_PASS();
    return 0;
}

/* Test: NAT statistics */
static int test_nat_stats(void)
{
    struct nat_stats stats;

    assert(nat_get_stats(&stats) == 0);
    assert(stats.total_sessions > 0);
    assert(stats.active_sessions > 0);

    printf("  Active sessions: %lu\n", stats.active_sessions);
    printf("  Total sessions: %lu\n", stats.total_sessions);

    TEST_PASS();
    return 0;
}

/* Test: Clear all sessions */
static int test_nat_clear_sessions(void)
{
    nat_clear_sessions();

    struct nat_stats stats;
    nat_get_stats(&stats);

    assert(stats.active_sessions == 0);

    TEST_PASS();
    return 0;
}

int main(void)
{
    printf("\n========================================\n");
    printf("NAT Session Table Unit Tests\n");
    printf("========================================\n\n");

    if (test_nat_init() != 0) return 1;
    if (test_nat_pool_create() != 0) return 1;
    if (test_nat_session_create() != 0) return 1;
    if (test_nat_session_lookup_inside() != 0) return 1;
    if (test_nat_session_lookup_outside() != 0) return 1;
    if (test_nat_stats() != 0) return 1;
    if (test_nat_clear_sessions() != 0) return 1;

    printf("\n========================================\n");
    printf("✅ All NAT tests PASSED!\n");
    printf("========================================\n\n");

    nat_cleanup();
    return 0;
}
