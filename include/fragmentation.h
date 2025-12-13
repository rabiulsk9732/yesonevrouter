/**
 * @file fragmentation.h
 * @brief IP Fragmentation Support (RFC 791)
 */

#ifndef FRAGMENTATION_H
#define FRAGMENTATION_H

#include "packet.h"
#include "interface.h"
#include <stdint.h>
#include <stdbool.h>

/* Fragmentation statistics */
struct fragmentation_stats {
    uint64_t packets_fragmented;        /* Packets that were fragmented */
    uint64_t fragments_created;         /* Total fragments created */
    uint64_t fragmentation_needed_sent; /* ICMP Fragmentation Needed sent */
    uint64_t packets_too_large;         /* Packets dropped (too large) */
};

/**
 * @brief Initialize fragmentation subsystem
 * @return 0 on success, -1 on error
 */
int ip_fragmentation_init(void);

/**
 * @brief Check if packet needs fragmentation
 * @param pkt Packet buffer
 * @param mtu Interface MTU
 * @return true if fragmentation needed
 */
bool ip_needs_fragmentation(struct pkt_buf *pkt, uint16_t mtu);

/**
 * @brief Fragment a packet if it exceeds MTU
 * @param pkt Original packet
 * @param mtu Maximum transmission unit
 * @param egress_iface Egress interface
 * @return 0 on success, -1 on error
 */
int ip_fragment_packet(struct pkt_buf *pkt, uint16_t mtu,
                       struct interface *egress_iface);

/**
 * @brief Send ICMP Fragmentation Needed message (Type 3, Code 4)
 * @param pkt Original packet that couldn't be fragmented
 * @param mtu Next-hop MTU
 * @param ingress_iface Interface to send ICMP on
 * @return 0 on success, -1 on error
 */
int send_icmp_fragmentation_needed(struct pkt_buf *pkt, uint16_t mtu,
                                   struct interface *ingress_iface);

/**
 * @brief Get fragmentation statistics
 * @param stats Output buffer for statistics
 */
void ip_fragmentation_get_stats(struct fragmentation_stats *stats);

/**
 * @brief Cleanup fragmentation subsystem
 */
void ip_fragmentation_cleanup(void);

#endif /* FRAGMENTATION_H */
