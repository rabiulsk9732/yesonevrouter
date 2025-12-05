/**
 * @file dpdk_lpm.h
 * @brief DPDK LPM Routing API
 */

#ifndef DPDK_LPM_H
#define DPDK_LPM_H

#include <stdint.h>

/**
 * Initialize DPDK LPM table
 */
int dpdk_lpm_init(void);

/**
 * Cleanup DPDK LPM
 */
void dpdk_lpm_cleanup(void);

/**
 * Add route to LPM table
 * @param network Network address (host order)
 * @param prefix_len Prefix length (0-32)
 * @param gateway Next-hop gateway (host order)
 * @param ifindex Egress interface index
 */
int dpdk_lpm_add_route(uint32_t network, uint8_t prefix_len, uint32_t gateway, uint32_t ifindex);

/**
 * Delete route from LPM table
 */
int dpdk_lpm_del_route(uint32_t network, uint8_t prefix_len);

/**
 * Lookup route in LPM table
 * @param ip Destination IP (host order)
 * @param gateway Output: gateway IP
 * @param ifindex Output: egress interface
 * @return 0 on success, -1 if no route
 */
int dpdk_lpm_lookup(uint32_t ip, uint32_t *gateway, uint32_t *ifindex);

/**
 * Bulk lookup (high performance)
 */
int dpdk_lpm_lookup_bulk(const uint32_t *ips, uint32_t *next_hops, int count);

/**
 * Add /32 host route for PPPoE session
 */
void dpdk_lpm_add_host_route(uint32_t host_ip, uint32_t ifindex);

/**
 * Delete host route
 */
void dpdk_lpm_del_host_route(uint32_t host_ip);

#endif /* DPDK_LPM_H */
