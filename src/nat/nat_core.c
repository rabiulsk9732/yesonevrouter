/**
 * @file nat_core.c
 * @brief NAT Core Engine
 *
 * Core NAT functionality including initialization, pool management,
 * and main packet translation logic
 */

#include "log.h"
#include "nat.h"
#include "nat_log.h"
#include "packet.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* Global NAT configuration */
struct nat_config g_nat_config;

/**
 * Initialize NAT subsystem
 */
int nat_init(void)
{
    memset(&g_nat_config, 0, sizeof(g_nat_config));

    g_nat_config.enabled = false;
    g_nat_config.hairpinning_enabled = false;
    g_nat_config.eim_enabled = true; /* Default to EIM */
    g_nat_config.eim_enabled = true; /* Default to EIM */
    g_nat_config.deterministic_enabled = false;

    /* Initialize session table locks */
    if (nat_session_init() != 0) {
        YLOG_ERROR("Failed to initialize NAT session locks");
        return -1;
    }

    /* Initialize port block pool (10000 blocks max = ~640K ports) */
    if (nat_portblock_init(10000) != 0) {
        YLOG_ERROR("Failed to initialize port block pool");
        return -1;
    }

    /* Initialize NAT logging (default collector 127.0.0.1:4739) */
    /* In production, this would be configured via CLI */
    nat_log_init(0x7F000001, 4739);

    YLOG_INFO("NAT subsystem initialized");
    return 0;
}

/**
 * Check if NAT is enabled
 */
bool nat_is_enabled(void)
{
    return g_nat_config.enabled;
}

/**
 * Cleanup NAT subsystem
 */
void nat_cleanup(void)
{
    /* Clear all sessions */
    nat_clear_sessions();

    /* Cleanup port block pool */
    nat_portblock_cleanup();

    YLOG_INFO("NAT subsystem cleanup complete");
}

/**
 * Create a NAT pool
 */
int nat_pool_create(const char *name, uint32_t start_ip, uint32_t end_ip, uint32_t netmask)
{
    if (!name || g_nat_config.num_pools >= NAT_MAX_POOLS) {
        return -1;
    }

    /* Find empty slot */
    int idx = g_nat_config.num_pools;
    struct nat_pool *pool = &g_nat_config.pools[idx];

    /* Initialize pool */
    strncpy(pool->name, name, sizeof(pool->name) - 1);
    pool->start_ip = start_ip;
    pool->end_ip = end_ip;
    pool->netmask = netmask;
    pool->current_ip = start_ip;
    pool->total_ips = (end_ip - start_ip) + 1;
    pool->used_ips = 0;
    pool->active = true;

    g_nat_config.num_pools++;

    YLOG_INFO("Created NAT pool '%s': %u IPs", name, pool->total_ips);
    return 0;
}

/**
 * Delete a NAT pool
 */
int nat_pool_delete(const char *name)
{
    if (!name)
        return -1;

    for (int i = 0; i < g_nat_config.num_pools; i++) {
        if (strcmp(g_nat_config.pools[i].name, name) == 0) {
            g_nat_config.pools[i].active = false;
            YLOG_INFO("Deleted NAT pool '%s'", name);
            return 0;
        }
    }

    return -1;
}

/**
 * Allocate public IP from NAT pool
 *
 * VPP note: For NAT44-EI with EIM (Endpoint Independent Mapping),
 * the same public IP can be used by multiple sessions with different ports.
 * We don't actually "exhaust" IPs in this mode - we just track usage.
 *
 * For single-IP pools, we always return the same IP since port differentiation
 * handles session uniqueness.
 */
uint32_t nat_pool_allocate_ip(struct nat_pool *pool)
{
    if (!pool || !pool->active) {
        return 0;
    }

    /* For single-IP NAT pool, always return the same IP */
    /* Port allocation (or ICMP ID for EIM) provides session uniqueness */
    if (pool->total_ips == 1) {
        pool->used_ips = 1; /* Track that this IP is in use */
        return pool->start_ip;
    }

    /* Multi-IP pool: round-robin allocation */
    if (pool->used_ips >= pool->total_ips) {
        return 0; /* Pool exhausted */
    }

    uint32_t ip = pool->current_ip;

    /* Round-robin to next IP */
    pool->current_ip++;
    if (pool->current_ip > pool->end_ip) {
        pool->current_ip = pool->start_ip;
    }

    pool->used_ips++;
    return ip;
}

/**
 * Release public IP back to NAT pool
 * Note: For a single-IP pool, this just decrements used_ips
 */
void nat_pool_release_ip(struct nat_pool *pool, uint32_t ip)
{
    (void)ip; /* Not used for simple pool - just track count */
    if (!pool || !pool->active || pool->used_ips == 0) {
        return;
    }
    pool->used_ips--;
}

/**
 * Allocate public port using port block allocation
 */
uint16_t nat_allocate_port(uint32_t public_ip, uint8_t protocol)
{
    /* Use port block allocation - subscriber ID is the inside IP for now */
    /* This will be called from nat_translate.c with proper subscriber ID */

    /* Simple sequential allocation as fallback if PBA not configured */
    static uint16_t port_counter = 10000;

    (void)public_ip; /* Unused for now */
    (void)protocol;  /* Unused for now */

    uint16_t port = port_counter++;
    if (port_counter > 65000) {
        port_counter = 10000;
    }

    g_nat_config.stats.ports_allocated++;
    return port;
}

/**
 * Get NAT statistics
 */
int nat_get_stats(struct nat_stats *stats)
{
    if (!stats)
        return -1;
    memcpy(stats, &g_nat_config.stats, sizeof(*stats));
    return 0;
}

/**
 * Print NAT configuration
 */
void nat_print_config(void)
{
    printf("\nNAT Configuration:\n");
    printf("  Status: %s\n", g_nat_config.enabled ? "Enabled" : "Disabled");
    printf("  Hairpinning: %s\n", g_nat_config.hairpinning_enabled ? "Enabled" : "Disabled");
    printf("  EIM: %s\n", g_nat_config.eim_enabled ? "Enabled" : "Disabled");
    printf("  Deterministic NAT: %s\n",
           g_nat_config.deterministic_enabled ? "Enabled" : "Disabled");

    printf("\n  NAT Pools (%d):\n", g_nat_config.num_pools);
    for (int i = 0; i < g_nat_config.num_pools; i++) {
        struct nat_pool *pool = &g_nat_config.pools[i];
        if (!pool->active)
            continue;

        char start_ip[16], end_ip[16];
        struct in_addr addr;

        addr.s_addr = htonl(pool->start_ip);
        inet_ntop(AF_INET, &addr, start_ip, sizeof(start_ip));
        addr.s_addr = htonl(pool->end_ip);
        inet_ntop(AF_INET, &addr, end_ip, sizeof(end_ip));

        printf("    %s: %s - %s (%u IPs, %u used)\n", pool->name, start_ip, end_ip, pool->total_ips,
               pool->used_ips);
    }

    printf("\n  Statistics:\n");
    printf("    Total sessions: %lu\n", g_nat_config.stats.total_sessions);
    printf("    Active sessions: %lu\n", g_nat_config.stats.active_sessions);
    printf("    Sessions created: %lu\n", g_nat_config.stats.sessions_created);
    printf("    Sessions deleted: %lu\n", g_nat_config.stats.sessions_deleted);
    printf("    Sessions timed out: %lu\n", g_nat_config.stats.sessions_timeout);
    printf("    Packets translated: %lu\n", g_nat_config.stats.packets_translated);
    printf("    SNAT packets: %lu\n", g_nat_config.stats.snat_packets);
    printf("    DNAT packets: %lu\n", g_nat_config.stats.dnat_packets);
    printf("\n");
    printf("  Lookup Statistics:\n");
    printf("    In2Out hits: %lu\n", g_nat_config.stats.in2out_hits);
    printf("    In2Out misses: %lu\n", g_nat_config.stats.in2out_misses);
    printf("    Out2In hits: %lu\n", g_nat_config.stats.out2in_hits);
    printf("    Out2In misses: %lu\n", g_nat_config.stats.out2in_misses);
    printf("\n");
    printf("  ICMP Statistics:\n");
    printf("    ICMP echo requests: %lu\n", g_nat_config.stats.icmp_echo_requests);
    printf("    ICMP echo replies: %lu\n", g_nat_config.stats.icmp_echo_replies);
    printf("    ICMP identifier mismatches: %lu\n", g_nat_config.stats.icmp_identifier_mismatches);
    printf("    ICMP session race failures: %lu\n", g_nat_config.stats.icmp_session_race_failures);
    printf("\n");
    printf("  Diagnostic Statistics:\n");
    printf("    SNAT function calls: %lu\n", g_nat_config.stats.snat_function_calls);
    printf("    SNAT early returns: %lu\n", g_nat_config.stats.snat_early_returns);
    printf("\n");
}
