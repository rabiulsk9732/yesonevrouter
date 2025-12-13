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

    /* Initialize NAT logging subsystem (no default collector - must be configured via CLI) */
    nat_log_init(0, 0);

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
 * Enable or disable NAT globally
 */
void nat_enable(bool enable)
{
    g_nat_config.enabled = enable;
    YLOG_INFO("NAT %s globally", enable ? "enabled" : "disabled");
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

    /* Allocate Port Bitmaps (1024 uint64 words per IP = 65536 bits) */
    /* Size = TotalIPs * 8KB */
    uint32_t bitmap_size = pool->total_ips * 1024 * sizeof(uint64_t);
    pool->ip_port_bitmaps = calloc(1, bitmap_size);
    if (!pool->ip_port_bitmaps) {
        YLOG_ERROR("Failed to allocate port bitmaps for pool '%s'", name);
        return -1;
    }

    /* Lock init removed in V2 (using atomic bitmaps) */

    g_nat_config.num_pools++;

    YLOG_INFO("Created NAT pool '%s': %u IPs, Bitmap Size: %u bytes", name, pool->total_ips, bitmap_size);
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

            /* Free bitmap memory */
            if (g_nat_config.pools[i].ip_port_bitmaps) {
                free(g_nat_config.pools[i].ip_port_bitmaps);
                g_nat_config.pools[i].ip_port_bitmaps = NULL;
                /* Lock destroy removed */
            }

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

    /* Multi-IP pool: round-robin allocation with IP reuse
     * Since ports provide session uniqueness, we can reuse IPs.
     * With 65K ports per IP, each IP can handle thousands of sessions.
     * We use round-robin for load distribution across the pool. */
    uint32_t ip = pool->current_ip;

    /* Round-robin to next IP for next allocation */
    pool->current_ip++;
    if (pool->current_ip > pool->end_ip) {
        pool->current_ip = pool->start_ip;
    }

    /* Track unique IPs that have been used at least once */
    if (pool->used_ips < pool->total_ips) {
        pool->used_ips++;
    }

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
/**
 * Allocate public port using safe bitmap allocator
 * Implements RFC 6888 REQ-1 Port Parity: Try to allocate same port as internal
 */
uint16_t nat_allocate_port(struct nat_pool *pool, uint32_t public_ip, uint8_t protocol)
{
    if (!pool || !pool->active || !pool->ip_port_bitmaps) {
        return 0;
    }
    (void)protocol; /* Unused for now as we share port space for all protocols */

    /* Calculate offset for this IP */
    /* Safety check */
    if (public_ip < pool->start_ip || public_ip > pool->end_ip) {
        return 0;
    }

    uint32_t ip_offset = public_ip - pool->start_ip;
    uint64_t *base_bitmap = (uint64_t *)pool->ip_port_bitmaps + (ip_offset * 1024);

    /* RANDOMIZED START OFFSET to reduce contention between cores */
    /* Use TSC to pick a random starting cache line (0-1023) */
    uint32_t start_word = (uint32_t)(rte_rdtsc() >> 4) % 1024;

    /* Ensure we skip reserved ports (0-1023). Word 0-15 cover ports 0-1023. */
    if (start_word < 16) start_word = 16;

    /* Scan 1024 words per IP. Wrap around if needed. */
    for (int count = 0; count < 1024; count++) {
        int i = (start_word + count) % 1024;
        if (i < 16) continue; /* Skip reserved ports */

        uint64_t word = __atomic_load_n(&base_bitmap[i], __ATOMIC_RELAXED);

        /* If not all bits set (UINT64_MAX), there is a free port */
        if (word != UINT64_MAX) {
            /* Try to claim a bit */
            /* Calculate free bit */
            int bit = __builtin_ctzl(~word);
            uint64_t mask = (1ULL << bit);

            /* Atomic Test-and-Set with CAS */
            uint64_t expected = word;
            uint64_t desired = word | mask;

            if ((expected & mask) == 0) { /* Check if bit is still free */
                 if (__atomic_compare_exchange_n(&base_bitmap[i], &expected, desired, 0,
                                                 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                     /* Success! We flipped the bit from 0 to 1. */
                     uint16_t port = (i * 64) + bit;
                     __atomic_fetch_add(&g_nat_config.stats.ports_allocated, 1, __ATOMIC_RELAXED);
                     return port;
                 }
                 /* CAS failed - continue to next word */
            }
        }
    }

    return 0; /* Pool exhausted for this IP */
}

/**
 * Allocate public port with parity preference (RFC 6888 REQ-1)
 * First tries to allocate the preferred port (same as internal),
 * then falls back to random allocation if unavailable.
 *
 * @param pool NAT pool
 * @param public_ip Public IP address
 * @param protocol Protocol (TCP/UDP)
 * @param preferred_port Preferred port (usually the internal port)
 * @return Allocated port, 0 on failure
 */
uint16_t nat_allocate_port_with_parity(struct nat_pool *pool, uint32_t public_ip,
                                       uint8_t protocol, uint16_t preferred_port)
{
    if (!pool || !pool->active || !pool->ip_port_bitmaps) {
        return 0;
    }
    (void)protocol;

    if (public_ip < pool->start_ip || public_ip > pool->end_ip) {
        return 0;
    }

    uint32_t ip_offset = public_ip - pool->start_ip;
    uint64_t *base_bitmap = (uint64_t *)pool->ip_port_bitmaps + (ip_offset * 1024);

    /* RFC 6888 Port Parity: Try preferred port first if it's valid (>1023) */
    if (preferred_port > 1023) {
        int word_idx = preferred_port / 64;
        int bit_idx = preferred_port % 64;
        uint64_t mask = (1ULL << bit_idx);

        uint64_t expected = __atomic_load_n(&base_bitmap[word_idx], __ATOMIC_RELAXED);

        /* Check if preferred port is free */
        if ((expected & mask) == 0) {
            uint64_t desired = expected | mask;
            if (__atomic_compare_exchange_n(&base_bitmap[word_idx], &expected, desired, 0,
                                            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                /* Got the preferred port! */
                __atomic_fetch_add(&g_nat_config.stats.ports_allocated, 1, __ATOMIC_RELAXED);
                return preferred_port;
            }
        }
    }

    /* Preferred port unavailable, fall back to random allocation */
    return nat_allocate_port(pool, public_ip, protocol);
}

/**
 * Release public port
 */
void nat_release_port(struct nat_pool *pool, uint32_t public_ip, uint16_t port, uint8_t protocol)
{
    if (!pool || !pool->active || !pool->ip_port_bitmaps) {
        return;
    }
    (void)protocol;


    if (public_ip < pool->start_ip || public_ip > pool->end_ip) {
        return;
    }

    if (port < 1024) return; /* Should not happen as we don't alloc them */

    uint32_t ip_offset = public_ip - pool->start_ip;
    uint64_t *base_bitmap = (uint64_t *)pool->ip_port_bitmaps + (ip_offset * 1024);

    uint32_t word_idx = port / 64;
    uint32_t bit_idx = port % 64;

    if (word_idx >= 1024) return;

    /* Atomic Clear */
    __atomic_fetch_and(&base_bitmap[word_idx], ~(1ULL << bit_idx), __ATOMIC_RELEASE);

    /* Removed lock */

    __atomic_fetch_add(&g_nat_config.stats.ports_released, 1, __ATOMIC_RELAXED);
}

/**
 * Find NAT pool by public IP
 */
struct nat_pool *nat_pool_get_by_ip(uint32_t ip)
{
    for (int i = 0; i < g_nat_config.num_pools; i++) {
        struct nat_pool *pool = &g_nat_config.pools[i];
        if (pool->active && ip >= pool->start_ip && ip <= pool->end_ip) {
            return pool;
        }
    }
    return NULL;
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
