/**
 * @file nat_fastpath.c
 * @brief NAT44 Fast Path Implementation (V2)
 *
 * Zero-allocation, pipelined datapath.
 */

#include "nat_fastpath.h"
#include "nat.h"
#include "log.h"
#include "packet.h"
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>

/* Global config reference */
extern struct nat_config g_nat_config;
extern __thread int g_thread_worker_id;
extern struct nat_worker_data g_nat_workers[NAT_MAX_WORKERS];
extern struct nat_session *g_session_slab;

/* Forward declarations for lockless functions */
extern uint32_t nat_hash_inside(uint32_t ip, uint16_t port, uint8_t protocol);

/* Incremental Checksum Primitives (RFC 1624) */
static inline uint16_t fast_update_cksum16(uint16_t old_cksum, uint16_t old_val, uint16_t new_val)
{
    uint32_t sum = (~old_cksum & 0xFFFF);
    sum += (~old_val & 0xFFFF);
    sum += new_val;
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static inline uint16_t fast_update_cksum32(uint16_t old_cksum, uint32_t old_val, uint32_t new_val)
{
    uint32_t sum = (~old_cksum & 0xFFFF);
    sum += (~(old_val & 0xFFFF) & 0xFFFF);
    sum += (~(old_val >> 16) & 0xFFFF);
    sum += (new_val & 0xFFFF);
    sum += (new_val >> 16);
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/**
 * Stage 1: Parse & Hash
 * Fills scratchpad with parsed info and calculated hash
 */
struct pkt_ctx {
    struct rte_ipv4_hdr *ip;
    union {
        struct rte_tcp_hdr *tcp;
        struct rte_udp_hdr *udp;
        void *l4;
    };
    struct nat_session *session;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    bool is_valid;
};

/**
 * Main Fast Path Burst Processor
 */
uint16_t nat_fastpath_process_burst(struct rte_mbuf **pkts, uint16_t count, void *iface)
{
    struct pkt_ctx ctx[NAT_BATCH_SIZE];
    uint32_t i;

    (void)iface;

    /*
     * STAGE 0: Prefetch Loop
     * Prefetch first few packets to prime the L1 cache
     */
    for (i = 0; i < NAT_PREFETCH_OFFSET && i < count; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
    }

    /* Main Pipeline Loop */
    for (i = 0; i < count; i++) {
        struct rte_mbuf *m = pkts[i];

        /* Pipeline Stage 0: Prefetch next packet */
        if (likely(i + NAT_PREFETCH_OFFSET < count)) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts[i + NAT_PREFETCH_OFFSET], void *));
        }

        /* Pipeline Stage 1: Parse Headers */
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

        ctx[i].ip = ip;
        ctx[i].is_valid = true;
        ctx[i].proto = ip->next_proto_id;
        ctx[i].src_ip = rte_be_to_cpu_32(ip->src_addr);
        ctx[i].dst_ip = rte_be_to_cpu_32(ip->dst_addr);

        uint16_t l4_offset = sizeof(struct rte_ether_hdr) + (ip->version_ihl & 0xF) * 4;

        if (ctx[i].proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, l4_offset);
            ctx[i].udp = udp;
            ctx[i].src_port = rte_be_to_cpu_16(udp->src_port);
            ctx[i].dst_port = rte_be_to_cpu_16(udp->dst_port);
        } else if (ctx[i].proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, l4_offset);
            ctx[i].tcp = tcp;
            ctx[i].src_port = rte_be_to_cpu_16(tcp->src_port);
            ctx[i].dst_port = rte_be_to_cpu_16(tcp->dst_port);
        } else {
            ctx[i].is_valid = false; /* Skip non-TCP/UDP for now (handle in slow path?) */
        }

        /* Pipeline Stage 2: Lookup */
        /* Using lockless per-worker lookup and creation */
        if (likely(ctx[i].is_valid)) {
            /* Check worker ID is valid */
            int worker_id = g_thread_worker_id;
            if (unlikely(worker_id < 0 || worker_id >= NAT_MAX_WORKERS)) {
                worker_id = 0; /* Fallback to worker 0 */
            }

            struct nat_worker_data *worker = &g_nat_workers[worker_id];

            /* Fast path: Check per-worker session cache first (L1 resident) */
            uint32_t hash = nat_hash_inside(ctx[i].src_ip, ctx[i].src_port, ctx[i].proto);
            uint32_t cache_idx = hash & (NAT_SESSION_CACHE_SIZE - 1);

            if (likely(worker->session_cache[cache_idx].inside_ip == ctx[i].src_ip &&
                       worker->session_cache[cache_idx].inside_port == ctx[i].src_port)) {
                /* CACHE HIT - use cached session index */
                uint32_t session_idx = worker->session_cache[cache_idx].session_index;
                extern struct nat_session *g_session_slab;
                ctx[i].session = (session_idx > 0) ? &g_session_slab[session_idx] : NULL;
                worker->cache_hits++;
            } else {
                /* Cache miss - lookup in hash table */
                worker->cache_misses++;
                ctx[i].session = nat_session_lookup_inside(ctx[i].src_ip, ctx[i].src_port, ctx[i].proto);
            }

            if (unlikely(!ctx[i].session)) {
                /* Session not found - CREATE using lockless path */

                /* Allocate port from per-worker pool (lockless) */
                uint16_t nat_port = nat_worker_alloc_port_lockless(worker_id, ctx[i].src_port);
                if (likely(nat_port != 0)) {
                    /* Get NAT IP from worker's port pool */
                    uint32_t nat_ip = worker->port_pool.nat_ip;
                    if (nat_ip == 0) {
                        /* Fallback: use default pool IP */
                        nat_ip = 0xCB007101 + worker_id; /* 203.0.113.X */
                    }

                    /* Create session using lockless path */
                    ctx[i].session = nat_session_create_lockless(
                        worker_id,
                        ctx[i].src_ip, ctx[i].src_port,
                        nat_ip, nat_port,
                        ctx[i].proto,
                        ctx[i].dst_ip, ctx[i].dst_port
                    );

                    if (likely(ctx[i].session)) {
                        /* Update session cache */
                        worker->session_cache[cache_idx].inside_ip = ctx[i].src_ip;
                        worker->session_cache[cache_idx].inside_port = ctx[i].src_port;
                        worker->session_cache[cache_idx].session_index =
                            (uint32_t)(ctx[i].session - g_session_slab);
                        worker->sessions_created++;
                    } else {
                        /* Session creation failed, free the port */
                        nat_worker_free_port_lockless(worker_id, nat_port);
                        worker->sessions_failed++;
                    }
                } else {
                    /* Port allocation failed */
                    worker->port_alloc_failed++;
                }
            }
        }
    }

    /* Pipeline Stage 3: Translate & Writeback */
    for (i = 0; i < count; i++) {
        if (likely(ctx[i].is_valid && ctx[i].session)) {
            struct nat_session *s = ctx[i].session;
            struct rte_ipv4_hdr *ip = ctx[i].ip;

            /* Update TTL (Standard router behavior) */
            // ip->time_to_live--;

            /* 1. Update IP Addresses */
            uint32_t old_ip = ip->src_addr;
            uint32_t new_ip = rte_cpu_to_be_32(s->outside_ip);

            ip->src_addr = new_ip;

            /* 2. Update IP Checksum (Incremental) */
            ip->hdr_checksum = fast_update_cksum32(ip->hdr_checksum, old_ip, new_ip);

            /* 3. Update L4 Ports & Checksum */
            if (ctx[i].proto == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = ctx[i].udp;
                uint16_t old_port = udp->src_port;
                uint16_t new_port = rte_cpu_to_be_16(s->outside_port);

                udp->src_port = new_port;

                if (udp->dgram_cksum != 0) {
                    uint16_t cksum = udp->dgram_cksum;
                    cksum = fast_update_cksum32(cksum, old_ip, new_ip);
                    cksum = fast_update_cksum16(cksum, old_port, new_port);
                    udp->dgram_cksum = cksum;
                }
            } else if (ctx[i].proto == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = ctx[i].tcp;
                uint16_t old_port = tcp->src_port;
                uint16_t new_port = rte_cpu_to_be_16(s->outside_port);

                tcp->src_port = new_port;

                uint16_t cksum = tcp->cksum;
                cksum = fast_update_cksum32(cksum, old_ip, new_ip);
                cksum = fast_update_cksum16(cksum, old_port, new_port);
                tcp->cksum = cksum;
            }

            /* Update stats (Atomic is slow, ideally batch these but keeping functional) */
            /* In V2 we would use per-lcore non-atomic counters */
            // s->packets_in++;
            // Reuse nat_translate logic here? No, we are replacing it.
            // Just update per-worker stats
             if (g_thread_worker_id >= 0 && g_thread_worker_id < NAT_MAX_WORKERS) {
                g_nat_workers[g_thread_worker_id].packets_translated++;
            }
        }
    }

    return count;
}

int nat_fastpath_init(unsigned int lcore_id)
{
    (void)lcore_id;
    return 0;
}
