/**
 * @file routing_dpdk_fib.c
 * @brief DPDK-Optimized FIB (Forwarding Information Base)
 * @details High-performance LPM using DPDK rte_lpm/rte_fib for line-rate routing
 *          Targets: 10M+ routes, 100+ Mpps forwarding rate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef HAVE_DPDK
#include <rte_lpm.h>
#include <rte_fib.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#endif

#include "routing_table.h"
#include "log.h"

/*============================================================================
 * DPDK FIB Configuration
 *============================================================================*/

#define DPDK_FIB_MAX_ROUTES     10000000    /* 10M routes */
#define DPDK_FIB_NUM_TBL8       (1 << 16)   /* 64K TBL8 groups */
#define DPDK_FIB_SOCKET         0           /* NUMA socket */

#define BATCH_SIZE              64          /* Packet batch for lookup */
#define PREFETCH_OFFSET         4           /* Prefetch ahead */

/*============================================================================
 * DPDK FIB Structures
 *============================================================================*/

#ifdef HAVE_DPDK

struct dpdk_fib_stats {
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
    uint64_t routes_added;
    uint64_t routes_deleted;
    uint64_t lookup_cycles;
    uint64_t lookup_count;
};

struct dpdk_fib {
    struct rte_lpm *lpm;            /* IPv4 LPM table */
    struct rte_fib *fib;            /* Alternative: FIB with DIR-24-8 */
    bool use_fib;                   /* Use FIB instead of LPM */
    uint32_t route_count;
    uint32_t max_routes;
    struct dpdk_fib_stats stats;
};

static struct dpdk_fib g_dpdk_fib = {0};

/*============================================================================
 * DPDK FIB Initialization
 *============================================================================*/

int dpdk_fib_init(uint32_t max_routes, bool use_fib)
{
    struct rte_lpm_config lpm_config = {
        .max_rules = max_routes > 0 ? max_routes : DPDK_FIB_MAX_ROUTES,
        .number_tbl8s = DPDK_FIB_NUM_TBL8,
        .flags = 0
    };

    g_dpdk_fib.max_routes = lpm_config.max_rules;
    g_dpdk_fib.use_fib = use_fib;

    if (use_fib) {
        /* Use rte_fib with DIR-24-8 algorithm for best performance */
        struct rte_fib_conf fib_conf = {
            .type = RTE_FIB_DIR24_8,
            .default_nh = 0,
            .max_routes = lpm_config.max_rules,
            .dir24_8 = {
                .nh_sz = RTE_FIB_DIR24_8_4B,  /* 4-byte next-hop */
                .num_tbl8 = DPDK_FIB_NUM_TBL8
            }
        };

        g_dpdk_fib.fib = rte_fib_create("dpdk_fib", DPDK_FIB_SOCKET, &fib_conf);
        if (!g_dpdk_fib.fib) {
            YLOG_ERROR("DPDK FIB: Failed to create FIB");
            return -1;
        }

        YLOG_INFO("DPDK FIB: Created DIR-24-8 FIB (max %u routes)", lpm_config.max_rules);
    } else {
        /* Use rte_lpm */
        g_dpdk_fib.lpm = rte_lpm_create("dpdk_lpm", DPDK_FIB_SOCKET, &lpm_config);
        if (!g_dpdk_fib.lpm) {
            YLOG_ERROR("DPDK FIB: Failed to create LPM");
            return -1;
        }

        YLOG_INFO("DPDK FIB: Created LPM table (max %u routes)", lpm_config.max_rules);
    }

    return 0;
}

/*============================================================================
 * Route Management
 *============================================================================*/

int dpdk_fib_add_route(uint32_t prefix, uint8_t prefix_len, uint32_t next_hop_id)
{
    int ret;

    if (g_dpdk_fib.use_fib && g_dpdk_fib.fib) {
        ret = rte_fib_add(g_dpdk_fib.fib, prefix, prefix_len, next_hop_id);
    } else if (g_dpdk_fib.lpm) {
        ret = rte_lpm_add(g_dpdk_fib.lpm, prefix, prefix_len, next_hop_id);
    } else {
        return -1;
    }

    if (ret == 0) {
        g_dpdk_fib.route_count++;
        g_dpdk_fib.stats.routes_added++;
    }

    return ret;
}

int dpdk_fib_delete_route(uint32_t prefix, uint8_t prefix_len)
{
    int ret;

    if (g_dpdk_fib.use_fib && g_dpdk_fib.fib) {
        ret = rte_fib_delete(g_dpdk_fib.fib, prefix, prefix_len);
    } else if (g_dpdk_fib.lpm) {
        ret = rte_lpm_delete(g_dpdk_fib.lpm, prefix, prefix_len);
    } else {
        return -1;
    }

    if (ret == 0) {
        g_dpdk_fib.route_count--;
        g_dpdk_fib.stats.routes_deleted++;
    }

    return ret;
}

/*============================================================================
 * Single Lookup
 *============================================================================*/

int dpdk_fib_lookup(uint32_t ip, uint32_t *next_hop_id)
{
    int ret;
    g_dpdk_fib.stats.lookups++;

    uint64_t start = rte_get_tsc_cycles();

    if (g_dpdk_fib.use_fib && g_dpdk_fib.fib) {
        uint64_t nh;
        ret = rte_fib_lookup_bulk(g_dpdk_fib.fib, &ip, &nh, 1);
        if (ret == 0 && nh != 0) {
            *next_hop_id = (uint32_t)nh;
            g_dpdk_fib.stats.hits++;
        } else {
            g_dpdk_fib.stats.misses++;
            ret = -1;
        }
    } else if (g_dpdk_fib.lpm) {
        ret = rte_lpm_lookup(g_dpdk_fib.lpm, ip, next_hop_id);
        if (ret == 0) {
            g_dpdk_fib.stats.hits++;
        } else {
            g_dpdk_fib.stats.misses++;
        }
    } else {
        return -1;
    }

    g_dpdk_fib.stats.lookup_cycles += rte_get_tsc_cycles() - start;
    g_dpdk_fib.stats.lookup_count++;

    return ret;
}

/*============================================================================
 * Batch Lookup (High Performance)
 *============================================================================*/

int dpdk_fib_lookup_bulk(uint32_t *ips, uint32_t *next_hops, uint32_t count)
{
    g_dpdk_fib.stats.lookups += count;

    uint64_t start = rte_get_tsc_cycles();
    int ret;

    if (g_dpdk_fib.use_fib && g_dpdk_fib.fib) {
        uint64_t *nh64 = rte_malloc(NULL, count * sizeof(uint64_t), 0);
        if (!nh64) return -1;

        ret = rte_fib_lookup_bulk(g_dpdk_fib.fib, ips, nh64, count);

        for (uint32_t i = 0; i < count; i++) {
            next_hops[i] = (uint32_t)nh64[i];
            if (nh64[i] != 0) {
                g_dpdk_fib.stats.hits++;
            } else {
                g_dpdk_fib.stats.misses++;
            }
        }

        rte_free(nh64);
    } else if (g_dpdk_fib.lpm) {
        int16_t status[BATCH_SIZE];

        /* Process in batches with prefetching */
        for (uint32_t i = 0; i < count; i += BATCH_SIZE) {
            uint32_t batch = (count - i > BATCH_SIZE) ? BATCH_SIZE : (count - i);

            /* Prefetch next batch */
            if (likely(i + batch < count)) {
                for (uint32_t j = 0; j < PREFETCH_OFFSET && (i + batch + j) < count; j++) {
                    rte_prefetch0(&ips[i + batch + j]);
                }
            }

            ret = rte_lpm_lookup_bulk(g_dpdk_fib.lpm, &ips[i], &next_hops[i], batch);
            (void)status;
        }

        for (uint32_t i = 0; i < count; i++) {
            if (next_hops[i] != 0) {
                g_dpdk_fib.stats.hits++;
            } else {
                g_dpdk_fib.stats.misses++;
            }
        }
    } else {
        return -1;
    }

    g_dpdk_fib.stats.lookup_cycles += rte_get_tsc_cycles() - start;
    g_dpdk_fib.stats.lookup_count += count;

    return 0;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void dpdk_fib_get_stats(uint64_t *lookups, uint64_t *hits, uint64_t *misses,
                        uint32_t *routes, double *ns_per_lookup)
{
    if (lookups) *lookups = g_dpdk_fib.stats.lookups;
    if (hits) *hits = g_dpdk_fib.stats.hits;
    if (misses) *misses = g_dpdk_fib.stats.misses;
    if (routes) *routes = g_dpdk_fib.route_count;

    if (ns_per_lookup && g_dpdk_fib.stats.lookup_count > 0) {
        double cycles_per_lookup = (double)g_dpdk_fib.stats.lookup_cycles /
                                   g_dpdk_fib.stats.lookup_count;
        *ns_per_lookup = cycles_per_lookup * 1e9 / rte_get_tsc_hz();
    }
}

void dpdk_fib_print_stats(void)
{
    double ns_per_lookup = 0;
    if (g_dpdk_fib.stats.lookup_count > 0) {
        double cycles_per_lookup = (double)g_dpdk_fib.stats.lookup_cycles /
                                   g_dpdk_fib.stats.lookup_count;
        ns_per_lookup = cycles_per_lookup * 1e9 / rte_get_tsc_hz();
    }

    double mpps = 0;
    if (ns_per_lookup > 0) {
        mpps = 1000.0 / ns_per_lookup;
    }

    printf("DPDK FIB Statistics\n");
    printf("===================\n");
    printf("Algorithm:      %s\n", g_dpdk_fib.use_fib ? "DIR-24-8" : "LPM");
    printf("Routes:         %u / %u\n", g_dpdk_fib.route_count, g_dpdk_fib.max_routes);
    printf("Lookups:        %lu (hits: %lu, misses: %lu)\n",
           g_dpdk_fib.stats.lookups, g_dpdk_fib.stats.hits, g_dpdk_fib.stats.misses);
    printf("Hit rate:       %.2f%%\n",
           g_dpdk_fib.stats.lookups > 0 ?
           100.0 * g_dpdk_fib.stats.hits / g_dpdk_fib.stats.lookups : 0);
    printf("Lookup perf:    %.1f ns/lookup (%.1f Mpps)\n", ns_per_lookup, mpps);
}

void dpdk_fib_cleanup(void)
{
    if (g_dpdk_fib.fib) {
        rte_fib_free(g_dpdk_fib.fib);
        g_dpdk_fib.fib = NULL;
    }
    if (g_dpdk_fib.lpm) {
        rte_lpm_free(g_dpdk_fib.lpm);
        g_dpdk_fib.lpm = NULL;
    }
    g_dpdk_fib.route_count = 0;
    memset(&g_dpdk_fib.stats, 0, sizeof(g_dpdk_fib.stats));
    YLOG_INFO("DPDK FIB: Cleanup complete");
}

#else /* !HAVE_DPDK */

/* Stubs for non-DPDK builds */
int dpdk_fib_init(uint32_t max_routes, bool use_fib) { (void)max_routes; (void)use_fib; return 0; }
int dpdk_fib_add_route(uint32_t prefix, uint8_t prefix_len, uint32_t next_hop_id)
    { (void)prefix; (void)prefix_len; (void)next_hop_id; return 0; }
int dpdk_fib_delete_route(uint32_t prefix, uint8_t prefix_len)
    { (void)prefix; (void)prefix_len; return 0; }
int dpdk_fib_lookup(uint32_t ip, uint32_t *next_hop_id)
    { (void)ip; (void)next_hop_id; return -1; }
int dpdk_fib_lookup_bulk(uint32_t *ips, uint32_t *next_hops, uint32_t count)
    { (void)ips; (void)next_hops; (void)count; return -1; }
void dpdk_fib_get_stats(uint64_t *l, uint64_t *h, uint64_t *m, uint32_t *r, double *ns)
    { (void)l; (void)h; (void)m; (void)r; (void)ns; }
void dpdk_fib_print_stats(void) { printf("DPDK FIB: Not available (no DPDK)\n"); }
void dpdk_fib_cleanup(void) {}

#endif /* HAVE_DPDK */
