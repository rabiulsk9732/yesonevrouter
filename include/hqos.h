/**
 * @file hqos.h
 * @brief Hierarchical QoS API
 */

#ifndef HQOS_H
#define HQOS_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Initialize HQoS subsystem
 */
int hqos_init(void);

/**
 * Cleanup HQoS
 */
void hqos_cleanup(void);

/**
 * Initialize HQoS for a port
 * @param port_rate Port rate limit in bps
 */
int hqos_port_init(uint16_t port_id, uint64_t port_rate);

/**
 * Add a traffic class
 * @param priority 0-7, higher = more priority
 * @param weight WFQ weight (if not strict priority)
 * @param min_rate Guaranteed rate in bps
 * @param max_rate Maximum rate in bps
 * @param strict True for strict priority, false for WFQ
 */
int hqos_add_class(uint16_t port_id, const char *name, uint8_t priority,
                   uint64_t weight, uint64_t min_rate, uint64_t max_rate, bool strict);

/**
 * Classify packet based on DSCP
 * @return Traffic class ID (0-7)
 */
uint8_t hqos_classify_packet(uint8_t dscp);

/**
 * Enqueue packet to HQoS (returns 0 on success)
 * Takes ownership of packet buffer/mbuf.
 */
int hqos_enqueue(uint16_t port_id, uint8_t class_id, void *packet);

/**
 * Run HQoS Scheduler (to be called by TX/Worker thread)
 */
void hqos_run(void);

/**
 * Dequeue next packet using SP/WFQ scheduling (deprecated)
 */
void *hqos_dequeue(uint16_t port_id) __attribute__((deprecated));

/**
 * Check if HQoS is active on port
 */
bool hqos_is_active(uint16_t port_id);

/**
 * Show HQoS configuration
 */
void hqos_show_config(uint16_t port_id);

#endif /* HQOS_H */
