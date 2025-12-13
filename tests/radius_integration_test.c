/**
 * @file radius_integration_test.c
 * @brief RADIUS Integration Tests with FreeRADIUS
 *
 * Prerequisites:
 *   - FreeRADIUS installed and running
 *   - User 'testuser' configured with password 'testpass'
 *   - Shared secret 'testing123'
 *
 * Setup FreeRADIUS:
 *   1. Add to /etc/freeradius/3.0/users:
 *      testuser Cleartext-Password := "testpass"
 *
 *   2. Add to /etc/freeradius/3.0/clients.conf:
 *      client localhost {
 *          ipaddr = 127.0.0.1
 *          secret = testing123
 *      }
 *
 *   3. Start: sudo radiusd -X
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "radius.h"

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Response tracking */
static volatile bool g_auth_response_received = false;
static volatile bool g_auth_success = false;
static volatile uint32_t g_framed_ip = 0;

#define TEST_TIMEOUT_SEC 5

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

#define TEST_SKIP(msg) do { \
    printf("  [SKIP] %s: %s\n", __func__, msg); \
    return; \
} while(0)

/*
 * ==========================================================================
 * Auth Callback
 * ==========================================================================
 */
static void auth_callback(uint16_t session_id, const struct radius_auth_result *result)
{
    (void)session_id;
    g_auth_response_received = true;
    g_auth_success = result->success;
    g_framed_ip = result->framed_ip;
}

/*
 * ==========================================================================
 * Helper: Drain any pending responses
 * ==========================================================================
 */
static void drain_responses(void)
{
    /* Poll several times to drain any stale responses */
    for (int i = 0; i < 10; i++) {
        radius_client_poll();
        usleep(10000);
    }
    g_auth_response_received = false;
    g_auth_success = false;
}

/*
 * ==========================================================================
 * Helper: Wait for auth response
 * ==========================================================================
 */
static bool wait_for_response(int timeout_sec)
{
    g_auth_response_received = false;
    g_auth_success = false;

    for (int i = 0; i < timeout_sec * 100; i++) {
        radius_client_poll();

        if (g_auth_response_received) {
            return true;
        }

        usleep(10000);  /* 10ms */
    }

    return false;
}

/*
 * ==========================================================================
 * Helper: Check if FreeRADIUS is running
 * ==========================================================================
 */
static bool freeradius_available(void)
{
    /* Try to send a test packet and see if we get any response */
    uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    radius_client_auth_pap("probe", "probe", 1, mac);

    /* Wait briefly for response */
    for (int i = 0; i < 50; i++) {
        radius_client_poll();

        if (g_auth_response_received) {
            return true;
        }

        usleep(20000);  /* 20ms */
    }

    return false;
}

/*
 * ==========================================================================
 * Test: Valid Authentication
 * ==========================================================================
 */
static void test_auth_valid_user(void)
{
    drain_responses();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    int ret = radius_client_auth_pap("testuser", "testpass", 100, mac);
    TEST_ASSERT(ret == 0, "Auth request should be sent");

    bool got_response = wait_for_response(TEST_TIMEOUT_SEC);
    TEST_ASSERT(got_response, "Should receive response");
    TEST_ASSERT(g_auth_success, "Should be Access-Accept");

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Invalid Password
 * ==========================================================================
 */
static void test_auth_invalid_password(void)
{
    drain_responses();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};

    int ret = radius_client_auth_pap("testuser", "wrongpassword", 101, mac);
    TEST_ASSERT(ret == 0, "Auth request should be sent");

    bool got_response = wait_for_response(TEST_TIMEOUT_SEC);
    TEST_ASSERT(got_response, "Should receive response");
    TEST_ASSERT(!g_auth_success, "Should be Access-Reject");

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Invalid Username
 * ==========================================================================
 */
static void test_auth_invalid_username(void)
{
    drain_responses();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x57};

    int ret = radius_client_auth_pap("nonexistent_user", "password", 102, mac);
    TEST_ASSERT(ret == 0, "Auth request should be sent");

    bool got_response = wait_for_response(TEST_TIMEOUT_SEC);
    TEST_ASSERT(got_response, "Should receive response");
    TEST_ASSERT(!g_auth_success, "Should be Access-Reject");

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Accounting Start
 * ==========================================================================
 */
static void test_accounting_start(void)
{
    int ret = radius_client_accounting(RADIUS_ACCT_STATUS_START, 100,
                                       "testuser", 0x0A000001, 0, 0, 0);
    TEST_ASSERT(ret == 0, "Acct START should be sent");

    /* Wait briefly for response (usually fast) */
    usleep(100000);
    radius_client_poll();

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Accounting Interim
 * ==========================================================================
 */
static void test_accounting_interim(void)
{
    int ret = radius_client_accounting(RADIUS_ACCT_STATUS_INTERIM, 100,
                                       "testuser", 0x0A000001,
                                       1000000, 2000000, 300);
    TEST_ASSERT(ret == 0, "Acct INTERIM should be sent");

    usleep(100000);
    radius_client_poll();

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Accounting Stop
 * ==========================================================================
 */
static void test_accounting_stop(void)
{
    int ret = radius_client_accounting(RADIUS_ACCT_STATUS_STOP, 100,
                                       "testuser", 0x0A000001,
                                       5000000, 10000000, 600);
    TEST_ASSERT(ret == 0, "Acct STOP should be sent");

    usleep(100000);
    radius_client_poll();

    TEST_PASS();
}

/*
 * ==========================================================================
 * Test: Multiple Concurrent Auth
 * ==========================================================================
 */
static void test_concurrent_auth(void)
{
    int count = 10;
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00};

    /* Send multiple requests */
    for (int i = 0; i < count; i++) {
        mac[5] = (uint8_t)i;
        radius_client_auth_pap("testuser", "testpass", (uint16_t)(200 + i), mac);
    }

    /* Wait and poll */
    int responses = 0;
    for (int t = 0; t < TEST_TIMEOUT_SEC * 100; t++) {
        radius_client_poll();

        if (g_auth_response_received) {
            responses++;
            g_auth_response_received = false;
        }

        if (responses >= count) break;

        usleep(10000);
    }

    TEST_ASSERT(responses >= count / 2, "Should receive most responses");

    printf("    (Received %d/%d responses)\n", responses, count);
    TEST_PASS();
}

/*
 * ==========================================================================
 * Main
 * ==========================================================================
 */
int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf("RADIUS Integration Tests\n");
    printf("========================================\n");
    printf("\n");

    /* Initialize RADIUS */
    printf("Initializing RADIUS client...\n");
    if (radius_client_init() != 0) {
        fprintf(stderr, "Failed to initialize RADIUS client\n");
        return 1;
    }

    /* Add localhost server */
    struct in_addr addr;
    inet_pton(AF_INET, "127.0.0.1", &addr);
    radius_client_add_server(ntohl(addr.s_addr), 1812, 1813, "testing123", 1);

    /* Set callback */
    radius_client_set_auth_callback(auth_callback);

    /* Set Source IP (NAS-IP-Address) to 127.0.0.1 */
    struct in_addr src_addr;
    inet_pton(AF_INET, "127.0.0.1", &src_addr);
    radius_client_set_source_ip(ntohl(src_addr.s_addr));

    /* Check if FreeRADIUS is available */
    printf("Checking for FreeRADIUS server...\n");
    if (!freeradius_available()) {
        printf("\n");
        printf("WARNING: FreeRADIUS not responding on 127.0.0.1:1812\n");
        printf("         Start FreeRADIUS with: sudo radiusd -X\n");
        printf("         Or install with: sudo apt install freeradius\n");
        printf("\n");
        printf("Running tests anyway (will fail without server)...\n");
    } else {
        printf("FreeRADIUS server detected!\n");
    }
    printf("\n");

    /* Run tests */
    test_auth_valid_user();
    test_auth_invalid_password();
    test_auth_invalid_username();
    test_accounting_start();
    test_accounting_interim();
    test_accounting_stop();
    test_concurrent_auth();

    /* Print stats */
    printf("\n");
    printf("RADIUS Client Statistics:\n");
    radius_client_print_stats();

    /* Summary */
    printf("========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    printf("\n");

    /* Cleanup */
    radius_client_cleanup();

    return tests_failed > 0 ? 1 : 0;
}
