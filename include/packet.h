/**
 * @file packet.h
 * @brief Packet Buffer Management
 *
 * Provides packet buffer structures and utilities for efficient packet handling.
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#endif

/* Maximum packet size */
#define PKT_MAX_SIZE        2048
#define PKT_DEFAULT_HEADROOM 128

/* Packet flags */
#define PKT_FLAG_L2_VALID   (1 << 0)
#define PKT_FLAG_L3_VALID   (1 << 1)
#define PKT_FLAG_L4_VALID   (1 << 2)
#define PKT_FLAG_CKSUM_OK   (1 << 3)
#define PKT_FLAG_FRAGMENTED (1 << 4)

/* Layer 2 types */
enum pkt_l2_type {
    PKT_L2_ETHERNET = 0,
    PKT_L2_VLAN,
    PKT_L2_PPPOE,
    PKT_L2_UNKNOWN
};

/* Layer 3 types */
enum pkt_l3_type {
    PKT_L3_IPV4 = 0,
    PKT_L3_IPV6,
    PKT_L3_ARP,
    PKT_L3_UNKNOWN
};

/* Layer 4 types */
enum pkt_l4_type {
    PKT_L4_TCP = 0,
    PKT_L4_UDP,
    PKT_L4_ICMP,
    PKT_L4_UNKNOWN
};

/* Packet metadata */
struct pkt_metadata {
    /* Layer offsets */
    uint16_t l2_offset;
    uint16_t l3_offset;
    uint16_t l4_offset;
    uint16_t payload_offset;

    /* Layer types */
    enum pkt_l2_type l2_type;
    enum pkt_l3_type l3_type;
    enum pkt_l4_type l4_type;

    /* Parsed fields */
    uint16_t vlan_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    /* Flow information */
    uint32_t flow_hash;

    /* Interface information */
    uint32_t ingress_ifindex;
    uint32_t egress_ifindex;
};

/* Packet buffer structure */
struct pkt_buf {
#ifdef HAVE_DPDK
    struct rte_mbuf *mbuf;      /* DPDK mbuf pointer */
#endif
    uint8_t *buf;               /* Software buffer */
    size_t buf_size;            /* Buffer size */

    uint8_t *data;              /* Pointer to packet data */
    uint16_t len;               /* Packet length */
    uint16_t headroom;          /* Available headroom */
    uint32_t flags;             /* Packet flags */

    struct pkt_metadata meta;   /* Packet metadata */

    /* Reference counting */
    uint32_t refcnt;

    /* Timestamp */
    uint64_t timestamp;

    /* Private data for driver-specific use */
    void *priv_data;
};

/**
 * Initialize packet buffer subsystem
 * @return 0 on success, -1 on failure
 */
int pkt_buf_init(void);

/**
 * Allocate a packet buffer
 * @return Pointer to packet buffer or NULL on failure
 */
struct pkt_buf *pkt_alloc(void);

/**
 * Free a packet buffer
 * @param pkt Packet buffer to free
 */
void pkt_free(struct pkt_buf *pkt);

/**
 * Clone a packet buffer (share data)
 * @param pkt Packet buffer to clone
 * @return Cloned packet buffer or NULL on failure
 */
struct pkt_buf *pkt_clone(struct pkt_buf *pkt);

/**
 * Copy a packet buffer (deep copy)
 * @param pkt Packet buffer to copy
 * @return Copied packet buffer or NULL on failure
 */
struct pkt_buf *pkt_copy(struct pkt_buf *pkt);

/**
 * Add headroom to packet
 * @param pkt Packet buffer
 * @param len Number of bytes to reserve
 * @return Pointer to new data start or NULL on failure
 */
uint8_t *pkt_push(struct pkt_buf *pkt, uint16_t len);

/**
 * Remove headroom from packet
 * @param pkt Packet buffer
 * @param len Number of bytes to remove
 * @return Pointer to new data start or NULL on failure
 */
uint8_t *pkt_pull(struct pkt_buf *pkt, uint16_t len);

/**
 * Extract packet metadata
 * @param pkt Packet buffer
 * @return 0 on success, -1 on failure
 */
int pkt_extract_metadata(struct pkt_buf *pkt);

/**
 * Calculate flow hash for packet
 * @param pkt Packet buffer
 * @return Flow hash value
 */
uint32_t pkt_calc_flow_hash(struct pkt_buf *pkt);

/**
 * Get packet data pointer
 * @param pkt Packet buffer
 * @return Pointer to packet data
 */
static inline uint8_t *pkt_data(struct pkt_buf *pkt)
{
    return pkt ? pkt->data : NULL;
}

/**
 * Get packet length
 * @param pkt Packet buffer
 * @return Packet length
 */
static inline uint16_t pkt_len(struct pkt_buf *pkt)
{
    return pkt ? pkt->len : 0;
}

/**
 * Increment packet reference count
 * @param pkt Packet buffer
 */
static inline void pkt_ref(struct pkt_buf *pkt)
{
    if (pkt) {
        __atomic_add_fetch(&pkt->refcnt, 1, __ATOMIC_SEQ_CST);
    }
}

/**
 * Get packet statistics
 * @param allocated Number of allocated packets (output)
 * @param freed Number of freed packets (output)
 */
void pkt_get_stats(uint64_t *allocated, uint64_t *freed);

/**
 * Cleanup packet buffer subsystem
 */
void pkt_buf_cleanup(void);

#endif /* PACKET_H */
