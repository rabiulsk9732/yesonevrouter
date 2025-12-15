/*
 * NAT Worker Flow Affinity
 * VPP-style deterministic worker selection
 */

#ifndef __NAT_FLOW_AFFINITY_H__
#define __NAT_FLOW_AFFINITY_H__

#include <stdint.h>

/* VPP-style: Hash inside tuple to determine owning worker
 * Same (src_ip, src_port, proto) always goes to same worker
 */
static inline uint32_t nat_flow_to_worker(uint32_t inside_ip, uint16_t inside_port, uint8_t proto,
                                          uint32_t num_workers)
{
    if (num_workers <= 1)
        return 0;

    /* Simple but effective hash - XOR components */
    uint32_t hash = inside_ip;
    hash ^= (uint32_t)inside_port << 16;
    hash ^= (uint32_t)proto << 8;

    /* Distribute across workers */
    return hash % num_workers;
}

/* Check if current worker owns this flow */
static inline int nat_worker_owns_flow(uint32_t worker_id, uint32_t inside_ip, uint16_t inside_port,
                                       uint8_t proto, uint32_t num_workers)
{
    uint32_t owner = nat_flow_to_worker(inside_ip, inside_port, proto, num_workers);
    return (owner == worker_id);
}

#endif /* __NAT_FLOW_AFFINITY_H__ */
