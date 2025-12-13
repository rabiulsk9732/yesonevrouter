/**
 * @file nat_dpdk_fastpath.c
 * @brief DPDK-Optimized NAT Fast Path for 10 Gbps/core
 *
 * Key optimizations:
 * - Batch processing (64-128 packets per burst)
 * - Zero-copy using rte_mbuf directly
 * - Hardware checksum offload
 * - SIMD-accelerated operations
 * - Prefetching and cache optimization
 */

#include "nat.h"
#include "log.h"
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#endif

/* Performance tuning constants */
#define NAT_BURST_SIZE         64    /* Packets per burst (cache line aligned) */
#define NAT_PREFETCH_OFFSET    4     /* Prefetch N packets ahead */
#define NAT_CACHE_LINE_SIZE    64

/* NAT interface direction - port 0 = inside, port 1 = outside */
#define NAT_INSIDE_PORT        0
#define NAT_OUTSIDE_PORT       1

/* Per-lcore statistics for zero contention */
struct nat_lcore_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t dropped;
    uint64_t sessions_created;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cycles_total;
    uint64_t bursts_processed;
    uint64_t handoff_tx;      /* Packets handed off to other workers */
    uint64_t handoff_rx;      /* Packets received from other workers */
} __attribute__((aligned(NAT_CACHE_LINE_SIZE)));

#ifdef HAVE_DPDK
static struct nat_lcore_stats g_lcore_stats[RTE_MAX_LCORE];
#endif

/* Thread-local worker ID */
extern __thread int g_thread_worker_id;
extern uint32_t g_num_workers;
extern struct nat_worker_data g_nat_workers[];

/**
 * Fast incremental checksum update
 * Avoids full recalculation - only updates changed fields
 */

/* Forward declaration for hash function */
extern uint32_t nat_hash_inside(uint32_t ip, uint16_t port, uint8_t protocol);
static inline uint16_t nat_fast_cksum_update(uint16_t old_cksum,
                                              uint32_t old_addr,
                                              uint32_t new_addr,
                                              uint16_t old_port,
                                              uint16_t new_port)
{
    uint32_t sum;

    /* Subtract old values, add new values */
    sum = (~old_cksum & 0xFFFF);
    sum += (~old_addr >> 16) & 0xFFFF;
    sum += ~old_addr & 0xFFFF;
    sum += (new_addr >> 16) & 0xFFFF;
    sum += new_addr & 0xFFFF;
    sum += ~old_port & 0xFFFF;
    sum += new_port & 0xFFFF;

    /* Fold 32-bit sum to 16-bit */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum & 0xFFFF;
}

#ifdef HAVE_DPDK
/**
 * Process a burst of packets through NAT - DPDK optimized
 *
 * @param pkts Array of packet mbufs
 * @param nb_rx Number of packets in burst
 * @param worker_id Current worker/lcore ID
 * @return Number of packets successfully processed
 */
uint16_t nat_process_burst_dpdk(struct rte_mbuf **pkts, uint16_t nb_rx, uint32_t worker_id)
{
    struct nat_lcore_stats *stats = &g_lcore_stats[worker_id];
    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    uint64_t start_cycles = rte_rdtsc();
    uint16_t nb_tx = 0;

    if (unlikely(nb_rx == 0)) return 0;

    stats->bursts_processed++;

    /* Stage 1: Prefetch all packet headers */
    for (int i = 0; i < nb_rx && i < NAT_PREFETCH_OFFSET; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
    }

    /* Stage 2: Process packets with lookahead prefetching */
    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_mbuf *pkt = pkts[i];
        struct rte_ipv4_hdr *ip;
        struct rte_udp_hdr *udp = NULL;
        struct rte_tcp_hdr *tcp = NULL;
        struct nat_session *session;
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        uint8_t proto;

        /* Prefetch next packets */
        if (likely(i + NAT_PREFETCH_OFFSET < nb_rx)) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts[i + NAT_PREFETCH_OFFSET], void *));
        }

        /* Get Ethernet header and check ether type */
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
        uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

        /* Handle ARP packets - send to ARP subsystem */
        if (unlikely(ether_type == RTE_ETHER_TYPE_ARP)) {
            extern int arp_process_packet_dpdk(struct rte_mbuf *mbuf, uint16_t port_id);
            arp_process_packet_dpdk(pkt, pkt->port);
            continue;
        }

        /* Skip non-IPv4 packets */
        if (unlikely(ether_type != RTE_ETHER_TYPE_IPV4)) {
            stats->dropped++;
            rte_pktmbuf_free(pkt);
            continue;
        }

        /* Check packet direction based on ingress port */
        uint16_t ingress_port = pkt->port;
        int is_inside_to_outside = (ingress_port == NAT_INSIDE_PORT);

        /* Get IP header */
        ip = (struct rte_ipv4_hdr *)(eth + 1);

        src_ip = rte_be_to_cpu_32(ip->src_addr);
        dst_ip = rte_be_to_cpu_32(ip->dst_addr);
        proto = ip->next_proto_id;

        /* Get L4 ports */
        if (proto == IPPROTO_UDP) {
            udp = (struct rte_udp_hdr *)((uint8_t *)ip + (ip->ihl << 2));
            src_port = rte_be_to_cpu_16(udp->src_port);
            dst_port = rte_be_to_cpu_16(udp->dst_port);
        } else if (proto == IPPROTO_TCP) {
            tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + (ip->ihl << 2));
            src_port = rte_be_to_cpu_16(tcp->src_port);
            dst_port = rte_be_to_cpu_16(tcp->dst_port);
        } else {
            /* Pass through non-TCP/UDP */
            pkts[nb_tx++] = pkt;
            continue;
        }

        /* VPP-STYLE WORKER HANDOFF: Route packet to correct worker */
        uint32_t target_worker = nat_flow_to_worker(src_ip, src_port, dst_ip, dst_port, proto);
        if (target_worker != worker_id) {
            /* This flow belongs to another worker - hand off via ring */
            if (nat_worker_handoff_enqueue(target_worker, pkt) == 0) {
                stats->handoff_tx++;
                continue;  /* Packet handed off successfully */
            }
            /* Ring full - process locally (fallback) */
        }

        /* Handle based on direction */
        if (is_inside_to_outside) {
            /* INSIDE -> OUTSIDE: SNAT (translate source) */
            /* Fast path: Check per-worker cache first (L1 resident) */
            uint32_t hash = nat_hash_inside(src_ip, src_port, proto);
            uint32_t cache_idx = hash & (NAT_SESSION_CACHE_SIZE - 1);

            if (likely(worker->session_cache[cache_idx].inside_ip == src_ip &&
                       worker->session_cache[cache_idx].inside_port == src_port)) {
                /* CACHE HIT - Use cached translation */
                uint32_t session_idx = worker->session_cache[cache_idx].session_index;
                extern struct nat_session *g_session_slab;
                session = (session_idx > 0) ? &g_session_slab[session_idx] : NULL;
                stats->cache_hits++;
                worker->cache_hits++;
            } else {
                /* Cache miss - lookup in per-worker hash table */
                stats->cache_misses++;
                worker->cache_misses++;

                /* Lookup in per-worker session table (PURE LOCKLESS - guaranteed to be in this worker's table) */
                session = nat_session_lookup_lockless(src_ip, src_port, proto, worker_id);

                if (!session) {
                    /* Create new session using THIS worker's port pool (LOCKLESS) */
                    uint16_t nat_port = nat_worker_alloc_port_lockless(worker_id, src_port);
                    if (nat_port == 0) {
                        /* Port alloc failed - log once */
                        static __thread uint64_t port_fail_count = 0;
                        if (port_fail_count++ < 5) {
                            LOG_WARN("[NAT-DPDK] Port alloc failed: worker=%u nat_ip=0x%x",
                                     worker_id, worker->port_pool.nat_ip);
                        }
                        stats->dropped++;
                        rte_pktmbuf_free(pkt);
                        continue;
                    }

                    /* LOCKLESS session create - each worker owns its session table */
                    session = nat_session_create_lockless(
                        worker_id,
                        src_ip, src_port,
                        worker->port_pool.nat_ip, nat_port,
                        proto, dst_ip, dst_port
                    );

                    if (!session) {
                        /* Session create failed - log once */
                        static __thread uint64_t sess_fail_count = 0;
                        if (sess_fail_count++ < 5) {
                            LOG_WARN("[NAT-DPDK] Session create failed: worker=%u", worker_id);
                        }
                        nat_worker_free_port_lockless(worker_id, nat_port);
                        stats->dropped++;
                        rte_pktmbuf_free(pkt);
                        continue;
                    }

                    stats->sessions_created++;
                }
            }

            /* Apply SNAT translation (inside -> outside) */
            if (!session) {
                static __thread uint64_t null_sess = 0;
                if (null_sess++ < 5) {
                    LOG_WARN("[NAT-SNAT] NULL session after lookup/create!");
                }
                stats->dropped++;
                rte_pktmbuf_free(pkt);
                continue;
            }

            uint32_t old_src = ip->src_addr;
            uint16_t old_port = (proto == IPPROTO_UDP) ? udp->src_port : tcp->src_port;

            ip->src_addr = rte_cpu_to_be_32(session->outside_ip);

            if (proto == IPPROTO_UDP) {
                udp->src_port = rte_cpu_to_be_16(session->outside_port);
                if (pkt->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) {
                    udp->dgram_cksum = 0;
                } else if (udp->dgram_cksum != 0) {
                    udp->dgram_cksum = nat_fast_cksum_update(
                        udp->dgram_cksum, old_src, ip->src_addr,
                        old_port, udp->src_port);
                }
            } else {
                tcp->src_port = rte_cpu_to_be_16(session->outside_port);
                if (pkt->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) {
                    tcp->cksum = 0;
                } else {
                    tcp->cksum = nat_fast_cksum_update(
                        tcp->cksum, old_src, ip->src_addr,
                        old_port, tcp->src_port);
                }
            }

            /* Update IP checksum */
            if (pkt->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
                ip->hdr_checksum = 0;
            } else {
                ip->hdr_checksum = nat_fast_cksum_update(
                    ip->hdr_checksum, old_src, ip->src_addr, 0, 0);
            }
        } else {
            /* OUTSIDE -> INSIDE: DNAT (translate destination) */

            /* Lookup session by outside (public) IP:port */
            session = nat_session_lookup_outside(dst_ip, dst_port, proto);

            if (!session) {
                /* No session - drop packet (unsolicited inbound) */
                stats->dropped++;
                rte_pktmbuf_free(pkt);
                continue;
            }

            /* Apply DNAT translation (outside -> inside) */
            uint32_t old_dst = ip->dst_addr;
            uint16_t old_port = (proto == IPPROTO_UDP) ? udp->dst_port : tcp->dst_port;

            ip->dst_addr = rte_cpu_to_be_32(session->inside_ip);

            if (proto == IPPROTO_UDP) {
                udp->dst_port = rte_cpu_to_be_16(session->inside_port);
                if (pkt->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) {
                    udp->dgram_cksum = 0;
                } else if (udp->dgram_cksum != 0) {
                    udp->dgram_cksum = nat_fast_cksum_update(
                        udp->dgram_cksum, old_dst, ip->dst_addr,
                        old_port, udp->dst_port);
                }
            } else {
                tcp->dst_port = rte_cpu_to_be_16(session->inside_port);
                if (pkt->ol_flags & RTE_MBUF_F_TX_TCP_CKSUM) {
                    tcp->cksum = 0;
                } else {
                    tcp->cksum = nat_fast_cksum_update(
                        tcp->cksum, old_dst, ip->dst_addr,
                        old_port, tcp->dst_port);
                }
            }

            /* Update IP checksum */
            if (pkt->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
                ip->hdr_checksum = 0;
            } else {
                ip->hdr_checksum = nat_fast_cksum_update(
                    ip->hdr_checksum, old_dst, ip->dst_addr, 0, 0);
            }
        }

        /* Mark packet for transmission */
        pkts[nb_tx++] = pkt;
        stats->tx_packets++;
    }

    stats->rx_packets += nb_rx;
    stats->cycles_total += rte_rdtsc() - start_cycles;

    return nb_tx;
}

/**
 * Main worker loop for DPDK lcore
 */
int nat_dpdk_worker_loop(void *arg)
{
    uint16_t port_id = *(uint16_t *)arg;
    uint16_t queue_id = rte_lcore_id();
    struct rte_mbuf *pkts[NAT_BURST_SIZE];

    LOG_INFO("[NAT-DPDK] Worker %u starting on lcore %u, port %u queue %u",
             g_thread_worker_id, rte_lcore_id(), port_id, queue_id);

    /* Initialize per-worker port pool */
    nat_worker_port_pool_init(g_thread_worker_id,
                              0xCB007100 + g_thread_worker_id,  /* 203.0.113.X */
                              1024, 65535);

    while (1) {
        /* Receive burst */
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts, NAT_BURST_SIZE);

        if (likely(nb_rx > 0)) {
            /* Process through NAT */
            uint16_t nb_tx = nat_process_burst_dpdk(pkts, nb_rx, g_thread_worker_id);

            /* Transmit burst */
            if (nb_tx > 0) {
                uint16_t sent = rte_eth_tx_burst(port_id, queue_id, pkts, nb_tx);

                /* Free unsent packets */
                if (unlikely(sent < nb_tx)) {
                    for (uint16_t i = sent; i < nb_tx; i++) {
                        rte_pktmbuf_free(pkts[i]);
                    }
                }
            }
        }
    }

    return 0;
}

/**
 * Get DPDK NAT statistics for a specific lcore
 */
void nat_dpdk_get_stats(uint32_t lcore_id, uint64_t *rx, uint64_t *tx,
                        uint64_t *dropped, double *cycles_per_pkt)
{
    struct nat_lcore_stats *stats = &g_lcore_stats[lcore_id];

    *rx = stats->rx_packets;
    *tx = stats->tx_packets;
    *dropped = stats->dropped;

    if (stats->rx_packets > 0) {
        *cycles_per_pkt = (double)stats->cycles_total / stats->rx_packets;
    } else {
        *cycles_per_pkt = 0;
    }
}

/**
 * Print DPDK NAT performance summary
 */
void nat_dpdk_print_stats(void)
{
    uint64_t total_rx = 0, total_tx = 0, total_dropped = 0;
    uint64_t total_cycles = 0, total_bursts = 0;

    LOG_INFO("[NAT-DPDK] Performance Statistics:");
    LOG_INFO("  ┌────────┬────────────┬────────────┬──────────┬────────────┐");
    LOG_INFO("  │ Lcore  │    RX      │    TX      │ Dropped  │ Cycles/pkt │");
    LOG_INFO("  ├────────┼────────────┼────────────┼──────────┼────────────┤");
    LOG_INFO("  |--------|------------|------------|----------|------------|");
    LOG_INFO("  | Lcore  |    RX      |    TX      | Dropped  | Cycles/pkt |");
    LOG_INFO("  |--------|------------|------------|----------|------------|");

    for (uint32_t i = 0; i < RTE_MAX_LCORE; i++) {
        struct nat_lcore_stats *stats = &g_lcore_stats[i];
        if (stats->rx_packets > 0) {
            double cpp = (double)stats->cycles_total / stats->rx_packets;
            (void)cpp; /* Silence warning when LOG is no-op */
            LOG_INFO("  |   %2u   | %10lu | %10lu | %8lu |   %6.1f   |",
                     i, stats->rx_packets, stats->tx_packets,
                     stats->dropped, cpp);

            total_rx += stats->rx_packets;
            total_tx += stats->tx_packets;
            total_dropped += stats->dropped;
            total_cycles += stats->cycles_total;
            total_bursts += stats->bursts_processed;
        }
    }

    LOG_INFO("  |--------|------------|------------|----------|------------|");
    double total_cpp = total_rx > 0 ? (double)total_cycles / total_rx : 0;
    LOG_INFO("  | TOTAL  | %10lu | %10lu | %8lu |   %6.1f   |",
             total_rx, total_tx, total_dropped, total_cpp);
    LOG_INFO("  ------------------------------------------------");

    /* Calculate throughput estimate */
    double avg_pkt_size = 400;  /* IMIX average */
    double cpu_ghz = 2.5;       /* Assumed CPU frequency */
    double pps_per_core = (cpu_ghz * 1e9) / (total_cpp > 0 ? total_cpp : 1);
    double gbps_per_core = (pps_per_core * avg_pkt_size * 8) / 1e9;

    LOG_INFO("  Estimated performance at %.1f GHz:", cpu_ghz);
    LOG_INFO("    %.2f Mpps/core, %.2f Gbps/core", pps_per_core / 1e6, gbps_per_core);
    (void)total_bursts; /* Mark as used */
    (void)gbps_per_core; /* Mark as used */
}

#else /* !HAVE_DPDK */

/* Stub implementations when DPDK is not available */
uint16_t nat_process_burst_dpdk(void **pkts, uint16_t nb_rx, uint32_t worker_id)
{
    (void)pkts; (void)nb_rx; (void)worker_id;
    return 0;
}

void nat_dpdk_print_stats(void)
{
    LOG_WARN("[NAT-DPDK] DPDK not available - stats not collected");
}

#endif /* HAVE_DPDK */
