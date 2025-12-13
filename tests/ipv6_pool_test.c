/*
 * ipv6_pool_test.c
 * Unit tests for IPv6 Pool Management
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

static void print_ipv6(const char *label, struct ipv6_addr *addr) {
    char str[64];
    inet_ntop(AF_INET6, addr->addr, str, sizeof(str));
    printf("%s: %s\n", label, str);
}

int main(void) {
    printf("Running IPv6 Pool Tests...\n");

    ipv6_pool_init();

    struct ipv6_addr base = {0};
    /* 2001:db8:: / 48 */
    base.addr[0] = 0x20; base.addr[1] = 0x01;
    base.addr[2] = 0x0d; base.addr[3] = 0xb8;

    printf("Test 1: Create Pool\n");
    if (ipv6_pool_create("test_pool", &base, 48, 64) != 0) {
        printf("FAILED: ipv6_pool_create\n");
        return 1;
    }
    printf("PASSED: ipv6_pool_create\n");

    printf("Test 2: Allocate Prefix 1\n");
    struct ipv6_addr p1;
    if (ipv6_pool_alloc("test_pool", &p1) != 0) {
        printf("FAILED: allocate 1\n");
        return 1;
    }
    print_ipv6("Allocated 1", &p1);
    /* Should be base (idx 0) */
    if (memcmp(p1.addr, base.addr, 16) != 0) {
        printf("FAILED: Allocation 1 incorrect\n");
        return 1;
    }
    printf("PASSED: Allocate Prefix 1\n");

    printf("Test 3: Allocate Prefix 2\n");
    struct ipv6_addr p2;
    if (ipv6_pool_alloc("test_pool", &p2) != 0) {
        printf("FAILED: allocate 2\n");
        return 1;
    }
    print_ipv6("Allocated 2", &p2);
    /* Should be base + 1 in subnet field */
    /* /48 -> /64 means modifying byte 6/7. 0001 */
    struct ipv6_addr expected = base;
    expected.addr[7] = 0x01;
    if (memcmp(p2.addr, expected.addr, 16) != 0) {
        printf("FAILED: Allocation 2 incorrect\n");
        return 1;
    }
    printf("PASSED: Allocate Prefix 2\n");

    printf("Test 4: Get Pool\n");
    struct ipv6_pool *pool = ipv6_pool_get("test_pool");
    if (!pool || strcmp(pool->name, "test_pool") != 0) {
         printf("FAILED: ipv6_pool_get\n");
         return 1;
    }
    if (pool->used_prefixes != 2) {
        printf("FAILED: Used prefixes count %u != 2\n", pool->used_prefixes);
        return 1;
    }
    printf("PASSED: Get Pool\n");

    printf("Test 5: Delete Pool\n");
    if (ipv6_pool_delete("test_pool") != 0) {
         printf("FAILED: ipv6_pool_delete\n");
         return 1;
    }
    if (ipv6_pool_get("test_pool") != NULL) {
        printf("FAILED: Pool still exists\n");
        return 1;
    }
    printf("PASSED: Delete Pool\n");

    printf("ALL TESTS PASSED\n");
    return 0;
}
