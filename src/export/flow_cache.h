#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

#include "export_common.h"
#include <rte_mbuf.h>

/**
 * @brief Initialize per-core flow cache
 * @param lcore_id ID of the core initializing the cache
 * @return 0 on success, <0 on failure
 */
int flow_cache_init(unsigned int lcore_id);

/**
 * @brief Update flow cache with a packet
 * @param m Packet buffer
 * @param direction Flow direction (Ingress, Egress, Forward)
 */
void flow_cache_update(struct rte_mbuf *m, enum flow_direction direction);

/**
 * @brief Check for expired flows and push to exporter ring
 * @param now_ms Current timestamp in milliseconds
 * @return Number of flows active
 */
void flow_cache_expire(uint64_t now_ms);

/**
 * @brief Flush all flows to exporter (e.g., on shutdown)
 */
void flow_cache_flush(void);

#endif /* FLOW_CACHE_H */
