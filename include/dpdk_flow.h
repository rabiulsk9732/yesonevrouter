/**
 * @file dpdk_flow.h
 * @brief DPDK Flow API Classification and RSS API
 */

#ifndef DPDK_FLOW_H
#define DPDK_FLOW_H

#include <stdint.h>

/**
 * Initialize DPDK flow subsystem
 */
int dpdk_flow_init(uint16_t port_id);

/**
 * Cleanup DPDK flow
 */
void dpdk_flow_cleanup(void);

/**
 * Create flow rule to direct PPPoE Discovery to specific queue
 */
int dpdk_flow_pppoe_discovery_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Create flow rule to direct PPPoE Session to specific queue
 */
int dpdk_flow_pppoe_session_queue(uint16_t port_id, uint16_t queue_id);

/**
 * Configure RSS for PPPoE traffic distribution
 * @param queues Array of queue IDs to distribute across
 * @param num_queues Number of queues
 */
int dpdk_flow_configure_rss(uint16_t port_id, uint16_t *queues, uint16_t num_queues);

/**
 * Flush all flow rules
 */
void dpdk_flow_flush(uint16_t port_id);

#endif /* DPDK_FLOW_H */
