/**
 * @file routing_dpdk_fib.h
 * @brief DPDK-Optimized FIB Header
 */

#ifndef ROUTING_DPDK_FIB_H
#define ROUTING_DPDK_FIB_H

#include <stdint.h>
#include <stdbool.h>

/* Initialize DPDK FIB
 * @param max_routes Maximum route capacity (0 = default 10M)
 * @param use_fib Use DIR-24-8 FIB (true) or LPM (false)
 */
int dpdk_fib_init(uint32_t max_routes, bool use_fib);

/* Route management */
int dpdk_fib_add_route(uint32_t prefix, uint8_t prefix_len, uint32_t next_hop_id);
int dpdk_fib_delete_route(uint32_t prefix, uint8_t prefix_len);

/* Single lookup */
int dpdk_fib_lookup(uint32_t ip, uint32_t *next_hop_id);

/* Batch lookup (high performance) */
int dpdk_fib_lookup_bulk(uint32_t *ips, uint32_t *next_hops, uint32_t count);

/* Statistics */
void dpdk_fib_get_stats(uint64_t *lookups, uint64_t *hits, uint64_t *misses,
                        uint32_t *routes, double *ns_per_lookup);
void dpdk_fib_print_stats(void);

/* Cleanup */
void dpdk_fib_cleanup(void);

#endif /* ROUTING_DPDK_FIB_H */
