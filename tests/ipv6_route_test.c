/*
 * ipv6_route_test.c
 * Unit tests for IPv6 Routing Table
 */

#include "ipv6/ipv6.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

/* Mock logging for tests */
int g_log_level = 7;
void log_msg(int level, const char *file, int line, const char *func, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)func; (void)fmt;
}

static void set_ipv6(struct ipv6_addr *addr, const char *str) {
    inet_pton(AF_INET6, str, addr->addr);
}

int main(void) {
    printf("Running IPv6 Route Tests...\n");

    ipv6_route_init();

    struct ipv6_addr dest1, dest2, gw, lookup_addr;
    struct ipv6_route *rt;

    /* Route 1: 2001:db8:1::/48 -> eth1 */
    set_ipv6(&dest1, "2001:db8:1::");
    set_ipv6(&gw, "fe80::1");

    printf("Test 1: Add Route /48\n");
    if (ipv6_route_add(&dest1, 48, &gw, "eth1", 10) != 0) {
        printf("FAILED: add route 1\n");
        return 1;
    }
    printf("PASSED: Add Route /48\n");

    /* Route 2: 2001:db8:1:1::/64 -> eth2 (More specific) */
    set_ipv6(&dest2, "2001:db8:1:1::");
    set_ipv6(&gw, "fe80::2");

    printf("Test 2: Add Route /64\n");
    if (ipv6_route_add(&dest2, 64, &gw, "eth2", 5) != 0) {
        printf("FAILED: add route 2\n");
        return 1;
    }
    printf("PASSED: Add Route /64\n");

    printf("Test 3: Lookup LPM (Should match /64)\n");
    set_ipv6(&lookup_addr, "2001:db8:1:1::100");
    rt = ipv6_route_lookup(&lookup_addr);
    if (!rt) {
        printf("FAILED: Lookup failed for specific address\n");
        return 1;
    }
    if (rt->prefix_len != 64 || strcmp(rt->interface, "eth2") != 0) {
        printf("FAILED: LPM incorrect (Got /%u -> %s)\n", rt->prefix_len, rt->interface);
        return 1;
    }
    printf("PASSED: Lookup LPM /64\n");

    printf("Test 4: Lookup Fallback (Should match /48)\n");
    set_ipv6(&lookup_addr, "2001:db8:1:2::100"); /* Different subnet in /48 */
    rt = ipv6_route_lookup(&lookup_addr);
    if (!rt) {
        printf("FAILED: Lookup failed for general address\n");
        return 1;
    }
    if (rt->prefix_len != 48 || strcmp(rt->interface, "eth1") != 0) {
        printf("FAILED: LPM incorrect (Got /%u -> %s)\n", rt->prefix_len, rt->interface);
        return 1;
    }
    printf("PASSED: Lookup Fallback /48\n");

    printf("Test 5: Lookup No Match\n");
    set_ipv6(&lookup_addr, "2001:beef::1");
    rt = ipv6_route_lookup(&lookup_addr);
    if (rt) {
        printf("FAILED: Found route for unrelated address\n");
        return 1;
    }
    printf("PASSED: Lookup No Match\n");

    printf("Test 6: Delete Route\n");
    if (ipv6_route_del(&dest2, 64) != 0) {
        printf("FAILED: Delete route\n");
        return 1;
    }
    /* Now specific lookup should fall back to /48 */
    set_ipv6(&lookup_addr, "2001:db8:1:1::100");
    rt = ipv6_route_lookup(&lookup_addr);
    if (!rt || rt->prefix_len != 48) {
        printf("FAILED: Fallback after delete incorrect\n");
        return 1;
    }
    printf("PASSED: Delete Route\n");

    printf("ALL TESTS PASSED\n");
    return 0;
}
