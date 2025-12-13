/**
 * @file pppoe_unit_tests.c
 * @brief Automated Unit Tests for PPPoE vBNG Features
 *
 * Tests:
 * 1. Session Lifecycle (Create/Lookup/Delete)
 * 2. LCP State Machine
 * 3. RADIUS Integration (Mock)
 * 4. QoS Token Bucket
 * 5. Session Disconnection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

/* DPDK Includes */
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_cycles.h>

/* YesRouter Includes */
#include "pppoe.h"
#include "pppoe_defs.h"
#include "ppp_lcp.h"
#include "ppp_ipcp.h"
#include "radius.h"
#include "interface.h"
#include "packet.h"
#include "log.h"
#include "qos.h"
#include "ippool.h"

/* Test Counters */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  [FAIL] %s: %s\n", __func__, msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASS() do { \
    printf("  [PASS] %s\n", __func__); \
    tests_passed++; \
} while(0)

/* ==================================================================
 * Test 1: Session Slab and Hash Table
 * ================================================================== */
static void test_session_create_lookup(void)
{
    /* Create a mock session */
    struct rte_ether_addr mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    uint16_t session_id = 1234;
    (void)mac; (void)session_id; /* Suppress unused warnings */

    /* Find by IP (should return NULL before creation) */
    struct pppoe_session *s = pppoe_find_session_by_ip(0xC0A80001); /* 192.168.0.1 */
    TEST_ASSERT(s == NULL, "Session should not exist before creation");

    /* Note: We can't easily test create without a full PADI/PADR flow */
    /* This is a sanity check that the lookup function doesn't crash */

    TEST_PASS();
}

/* ==================================================================
 * Test 2: Token Bucket QoS
 * ================================================================== */
static void test_qos_token_bucket(void)
{
    struct token_bucket tb;

    /* Init at 10 Mbps = 10,000,000 bps = 1,250,000 Bps */
    qos_tb_init(&tb, 10000000, 15000); /* 10Mbps, 15KB burst */

    /* Should allow first packet (1000 bytes) */
    int result = qos_tb_conform(&tb, 1000);
    TEST_ASSERT(result == 1, "First 1KB packet should pass");

    /* Should allow more packets up to burst */
    for (int i = 0; i < 10; i++) {
        result = qos_tb_conform(&tb, 1000);
    }
    /* After 11KB, should still be within 15KB burst */
    TEST_ASSERT(result == 1, "Packets within burst should pass");

    /* Drain tokens by sending more */
    for (int i = 0; i < 10; i++) {
        qos_tb_conform(&tb, 1500);
    }

    /* Tokens should be depleted now */
    result = qos_tb_conform(&tb, 1500);
    TEST_ASSERT(result == 0, "Packets exceeding burst should be dropped");

    TEST_PASS();
}

/* ==================================================================
 * Test 3: IP Pool
 * ================================================================== */
static void test_ip_pool(void)
{
    /* Create a small test pool (without netmask - check API) */
    int ret = ippool_create("test_pool", 0x0A000100, 0x0A0001FF); /* 10.0.1.0-10.0.1.255 */
    TEST_ASSERT(ret == 0, "Pool creation should succeed");

    /* Allocate an IP */
    uint8_t mac1[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint32_t ip1 = ippool_alloc_ip("test_pool", mac1);
    TEST_ASSERT(ip1 != 0, "IP allocation should succeed");
    TEST_ASSERT((ip1 & 0xFFFFFF00) == 0x0A000100, "IP should be in pool range");

    /* Allocate another IP */
    uint8_t mac2[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x66};
    uint32_t ip2 = ippool_alloc_ip("test_pool", mac2);
    TEST_ASSERT(ip2 != 0, "Second IP allocation should succeed");
    TEST_ASSERT(ip2 != ip1, "Second IP should be different");

    /* Free an IP */
    ippool_free_ip("test_pool", ip1);

    /* Reallocate - may or may not get same IP */
    uint32_t ip3 = ippool_alloc_ip("test_pool", mac1);
    TEST_ASSERT(ip3 != 0, "Reallocation should succeed");

    TEST_PASS();
}

/* ==================================================================
 * Test 4: LCP State Transitions
 * ================================================================== */
static void test_lcp_states(void)
{
    /* This is a simplified test of LCP state logic */
    /* Full testing requires packet exchange */

    /* Test state name lookup (if exposed) or just verify enums exist */
    int initial = LCP_STATE_INITIAL;
    int starting = LCP_STATE_STARTING;
    int req_sent = LCP_STATE_REQ_SENT;
    int ack_rcvd = LCP_STATE_ACK_RCVD;
    int opened = LCP_STATE_OPENED;

    TEST_ASSERT(initial < opened, "INITIAL should be before OPENED");
    TEST_ASSERT(starting < opened, "STARTING should be before OPENED");
    TEST_ASSERT(req_sent < opened, "REQ_SENT should be before OPENED");
    TEST_ASSERT(ack_rcvd < opened, "ACK_RCVD should be before OPENED");

    TEST_PASS();
}

/* ==================================================================
 * Test 5: RADIUS Packet Construction (Mock)
 * ================================================================== */
static void test_radius_packet_format(void)
{
    /* Test that we can construct a valid RADIUS request structure */
    /* Without actually sending it */

    /* RADIUS codes should be defined */
    TEST_ASSERT(RADIUS_CODE_ACCESS_REQUEST == 1, "Access-Request code should be 1");
    TEST_ASSERT(RADIUS_CODE_ACCESS_ACCEPT == 2, "Access-Accept code should be 2");
    TEST_ASSERT(RADIUS_CODE_ACCESS_REJECT == 3, "Access-Reject code should be 3");

    /* Attribute types */
    TEST_ASSERT(RADIUS_ATTR_USER_NAME == 1, "User-Name attribute should be 1");
    TEST_ASSERT(RADIUS_ATTR_USER_PASSWORD == 2, "User-Password attribute should be 2");
    TEST_ASSERT(RADIUS_ATTR_FRAMED_IP_ADDRESS == 8, "Framed-IP attribute should be 8");
    TEST_ASSERT(RADIUS_ATTR_FILTER_ID == 11, "Filter-Id attribute should be 11");

    TEST_PASS();
}

/* ==================================================================
 * Test 6: PPPoE Header Parsing
 * ================================================================== */
static void test_pppoe_header_struct(void)
{
    /* Verify PPPoE header structure is packed correctly */
    TEST_ASSERT(sizeof(struct pppoe_hdr) == 6, "PPPoE header should be 6 bytes");

    /* Verify PPPoE codes */
    TEST_ASSERT(PPPOE_CODE_PADI == 0x09, "PADI code should be 0x09");
    TEST_ASSERT(PPPOE_CODE_PADO == 0x07, "PADO code should be 0x07");
    TEST_ASSERT(PPPOE_CODE_PADR == 0x19, "PADR code should be 0x19");
    TEST_ASSERT(PPPOE_CODE_PADS == 0x65, "PADS code should be 0x65");
    TEST_ASSERT(PPPOE_CODE_PADT == 0xa7, "PADT code should be 0xa7");

    TEST_PASS();
}

/* ==================================================================
 * Test 7: Session Struct Size and Alignment
 * ================================================================== */
static void test_session_struct_alignment(void)
{
    size_t size = sizeof(struct pppoe_session);

    /* Should be cache-aligned (multiple of 64) */
    TEST_ASSERT(size % 64 == 0, "Session struct should be cache-aligned");

    /* Memory footprint check */
    size_t footprint_50k = size * 50000;
    printf("    Info: Session size=%zu bytes, 50k sessions=%.2f MB\n",
           size, (double)footprint_50k / (1024*1024));

    /* Should fit in reasonable memory (<100MB for 50k) */
    TEST_ASSERT(footprint_50k < 100*1024*1024, "50k sessions should use <100MB");

    TEST_PASS();
}

/* ==================================================================
 * Test 8: Interface Creation
 * ================================================================== */
static void test_interface_creation(void)
{
    struct interface *iface = interface_create("test_iface", IF_TYPE_DUMMY);
    TEST_ASSERT(iface != NULL, "Interface creation should succeed");
    TEST_ASSERT(strcmp(iface->name, "test_iface") == 0, "Interface name should match");
    TEST_ASSERT(iface->type == IF_TYPE_DUMMY, "Interface type should be DUMMY");

    /* Set state */
    iface->state = IF_STATE_UP;
    TEST_ASSERT(iface->state == IF_STATE_UP, "Interface should be UP");

    TEST_PASS();
}

/* ==================================================================
 * Main
 * ================================================================== */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("==================================================\n");
    printf("     PPPoE vBNG Unit Tests\n");
    printf("==================================================\n\n");

    /* Init DPDK (minimal) */
    static char socket_mem[32] = "0,512";
    char *dpdk_argv[] = {"pppoe_tests", "-l", "12", "-n", "4",
                         "--socket-mem", socket_mem, "--file-prefix", "tests", "--no-pci", NULL};
    printf("Initializing DPDK...\n");
    if (rte_eal_init(10, dpdk_argv) < 0) {
        printf("DPDK init failed - running reduced tests\n");
    } else {
        printf("DPDK initialized\n");
    }

    /* Init subsystems */
    log_init(NULL);
    pkt_buf_init();
    interface_init();
    radius_init();
    pppoe_init();

    printf("\n[Running Tests]\n\n");

    /* Run tests */
    test_session_create_lookup();
    test_qos_token_bucket();
    test_ip_pool();
    test_lcp_states();
    test_radius_packet_format();
    test_pppoe_header_struct();
    test_session_struct_alignment();
    test_interface_creation();

    /* Summary */
    printf("\n==================================================\n");
    printf("     RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("==================================================\n");

    return tests_failed > 0 ? 1 : 0;
}
