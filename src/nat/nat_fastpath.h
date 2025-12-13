/**
 * @file nat_fastpath.h
 * @brief Lockless NAT44 Fast Path - NetElastic/Bison Style
 *
 * Architecture:
 * - Per-core session pools (no global lock)
 * - Per-core port allocators
 * - RSS flow pinning (same flow = same core)
 * - Prefetch-optimized lookups
 * - Batched translation
 */

#ifndef NAT_FASTPATH_H
#define NAT_FASTPATH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_DPDK
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_prefetch.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <netinet/in.h>
#endif

/* Per-core configuration */
#define NAT_MAX_LCORES          16
#define NAT_SESSIONS_PER_CORE   (1024 * 1024 / NAT_MAX_LCORES)  /* 64K per core */
#define NAT_PORTS_PER_CORE      (65536 / NAT_MAX_LCORES)        /* Port block per core */
#define NAT_BATCH_SIZE          64  /* Process 64 packets at once */
#define NAT_PREFETCH_OFFSET     3   /* Prefetch 3 packets ahead */

/* Session key for hash lookup */
struct nat_session_key {
    uint32_t ip;
    uint16_t port;
    uint8_t  proto;
    uint8_t  _pad;
} __rte_packed;

/* Compact session entry (cache-line optimized) */
struct nat_session_fast {
    /* First cache line - hot data */
    uint32_t inside_ip;
    uint16_t inside_port;
    uint8_t  protocol;
    uint8_t  flags;
    uint32_t outside_ip;
    uint16_t outside_port;
    uint16_t _pad1;
    uint64_t last_used;      /* TSC timestamp */
    uint64_t packets;
    uint64_t bytes;
    /* 40 bytes - fits in cache line with padding */
    uint32_t dest_ip;
    uint16_t dest_port;
    uint16_t _pad2;
    uint32_t _reserved[2];
} __rte_cache_aligned;

/* Per-core NAT state (LOCKLESS) */
struct nat_lcore_state {
    /* Session hash table (per-core, no lock needed) */
    struct rte_hash *in2out_hash;
    struct rte_hash *out2in_hash;

    /* Session pool (per-core slab) */
    struct nat_session_fast *sessions;
    uint32_t *free_list;
    uint32_t free_count;
    uint32_t max_sessions;

    /* Port allocator (per-core block) */
    uint16_t port_base;      /* Starting port for this core */
    uint16_t port_count;     /* Number of ports */
    uint64_t port_bitmap[1024]; /* 64K ports / 64 bits = 1024 words */
    uint16_t next_port;      /* Round-robin hint */

    /* Statistics */
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t nat_hits;
    uint64_t nat_misses;
    uint64_t nat_creates;
    uint64_t nat_drops;

    /* Padding to cache line */
    uint8_t _pad[0] __rte_cache_aligned;
} __rte_cache_aligned;

/* Global state */
extern struct nat_lcore_state g_nat_lcore[NAT_MAX_LCORES];
extern bool g_nat_fastpath_enabled;

/* Initialization */
int nat_fastpath_init(unsigned int lcore_id);
void nat_fastpath_cleanup(unsigned int lcore_id);

/* Fast path functions (MUST be inline for performance) */
static inline uint32_t
nat_hash_key(uint32_t ip, uint16_t port, uint8_t proto)
{
    struct nat_session_key key = {
        .ip = ip,
        .port = port,
        .proto = proto,
        ._pad = 0
    };
    return rte_jhash(&key, sizeof(key), 0);
}

/**
 * Prefetch session for upcoming lookup
 */
static inline void
nat_prefetch_session(struct nat_lcore_state *state, uint32_t ip, uint16_t port, uint8_t proto)
{
#ifdef HAVE_DPDK
    uint32_t hash = nat_hash_key(ip, port, proto);
    /* Prefetch hash bucket */
    rte_prefetch0(&state->in2out_hash);
    /* Prefetch based on hash - approximate bucket location */
    if (state->sessions) {
        uint32_t idx = hash & (state->max_sessions - 1);
        rte_prefetch0(&state->sessions[idx]);
    }
#else
    (void)state; (void)ip; (void)port; (void)proto;
#endif
}

/**
 * Batched NAT translation (VECTORIZED)
 * Process up to NAT_BATCH_SIZE packets at once
 */
int nat_translate_batch(struct rte_mbuf **pkts, uint16_t nb_pkts,
                        struct nat_lcore_state *state);

/**
 * Single packet fast path (inline)
 */
static inline int
nat_translate_fast(struct rte_mbuf *pkt, struct nat_lcore_state *state)
{
#ifdef HAVE_DPDK
    struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
                                                       sizeof(struct rte_ether_hdr));
    uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
    uint16_t src_port = 0;
    uint8_t proto = ip->next_proto_id;

    /* Extract port based on protocol */
    if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)ip +
                                   (ip->version_ihl & 0xf) * 4);
        src_port = rte_be_to_cpu_16(udp->src_port);
    } else if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip +
                                   (ip->version_ihl & 0xf) * 4);
        src_port = rte_be_to_cpu_16(tcp->src_port);
    }

    /* Hash lookup with precomputed hash */
    uint32_t hash = nat_hash_key(src_ip, src_port, proto);
    int ret = rte_hash_lookup_with_hash(state->in2out_hash,
                                        &(struct nat_session_key){src_ip, src_port, proto, 0},
                                        hash);

    if (likely(ret >= 0)) {
        /* Fast path: session found */
        struct nat_session_fast *sess = &state->sessions[ret];
        state->nat_hits++;

        /* Update IP and checksum */
        ip->src_addr = rte_cpu_to_be_32(sess->outside_ip);
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);

        /* Update L4 port */
        if (proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)ip +
                                       (ip->version_ihl & 0xf) * 4);
            udp->src_port = rte_cpu_to_be_16(sess->outside_port);
            udp->dgram_cksum = 0; /* Offload or recalc */
        } else if (proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip +
                                       (ip->version_ihl & 0xf) * 4);
            tcp->src_port = rte_cpu_to_be_16(sess->outside_port);
            tcp->cksum = 0; /* Offload or recalc */
        }

        sess->packets++;
        sess->bytes += rte_pktmbuf_pkt_len(pkt);
        sess->last_used = rte_get_tsc_cycles();

        return 0;
    }

    /* Slow path: create session */
    state->nat_misses++;
    return -1; /* Let slow path handle */
#else
    (void)pkt; (void)state;
    return -1;
#endif
}

/**
 * Allocate port from per-core block (LOCKLESS)
 */
static inline uint16_t
nat_alloc_port_fast(struct nat_lcore_state *state)
{
    /* Round-robin through port block */
    for (uint16_t i = 0; i < state->port_count; i++) {
        uint16_t port = state->port_base + ((state->next_port + i) % state->port_count);
        uint16_t word = (port - 1024) / 64;
        uint16_t bit = (port - 1024) % 64;

        if (!(state->port_bitmap[word] & (1ULL << bit))) {
            state->port_bitmap[word] |= (1ULL << bit);
            state->next_port = (state->next_port + i + 1) % state->port_count;
            return port;
        }
    }
    return 0; /* No ports available */
}

/**
 * Free port back to per-core block (LOCKLESS)
 */
static inline void
nat_free_port_fast(struct nat_lcore_state *state, uint16_t port)
{
    if (port >= 1024 && port < 65535) {
        uint16_t word = (port - 1024) / 64;
        uint16_t bit = (port - 1024) % 64;
        state->port_bitmap[word] &= ~(1ULL << bit);
    }
}

#endif /* NAT_FASTPATH_H */
