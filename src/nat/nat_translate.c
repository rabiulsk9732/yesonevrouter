/**
 * @file nat_translate.c
 * @brief NAT Packet Translation Logic (DPDK Native)
 *
 * Implements SNAT44 and DNAT44 using DPDK native structures for maximum performance.
 * References: VPP NAT44 implementation, DPDK Programmer's Guide
 */

#include "acl.h"
#include "interface.h"
#include "log.h"
#include "nat.h"
#include "nat_log.h"
#include "nat_alg.h"
#include "packet.h"
#include <rte_byteorder.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <rte_ether.h>

/* External declarations */
extern struct nat_config g_nat_config;
extern __thread int g_thread_worker_id;
extern struct nat_worker_data g_nat_workers[NAT_MAX_WORKERS];

/**
 * Update IP checksum (DPDK optimized)
 */
static inline void nat_update_ip_checksum(struct rte_ipv4_hdr *ip)
{
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

/**
 * Update L4 checksum incrementally (RFC 1624)
 * Using DPDK optimized primitives
 */
static inline uint16_t nat_update_l4_checksum(uint16_t l4_cksum, uint32_t old_ip, uint32_t new_ip,
                                              uint16_t old_port, uint16_t new_port)
{
    /* We use a simplified approach for incremental update */
    /* This is a standard incremental update logic optimized for 16-bit math */

    uint32_t sum = (~l4_cksum & 0xFFFF);

    /* Subtract old IP (2 words) */
    sum += (~(old_ip & 0xFFFF) & 0xFFFF);
    sum += (~(old_ip >> 16) & 0xFFFF);

    /* Add new IP (2 words) */
    sum += (new_ip & 0xFFFF);
    sum += (new_ip >> 16);

    /* Subtract old Port */
    sum += (~old_port & 0xFFFF);

    /* Add new Port */
    sum += (new_port & 0xFFFF);

    /* Fold carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

/**
 * Process SNAT (Source NAT) - Inside to Outside translation
 * Translates private IP:port to public IP:port
 */
int nat_translate_snat(struct pkt_buf *pkt, struct interface *iface)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ipv4_hdr *ip;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    struct rte_icmp_hdr *icmp;
    struct nat_session *session;
    uint32_t inside_ip, outside_ip;
    uint16_t inside_port, outside_port;
    uint8_t protocol;

    (void)iface;

    /* Track SNAT function calls */
    __atomic_fetch_add(&g_nat_config.stats.snat_function_calls, 1, __ATOMIC_RELAXED);

    if (!m) {
        __atomic_fetch_add(&g_nat_config.stats.snat_early_returns, 1, __ATOMIC_RELAXED);
        return -1;
    }

    if (!g_nat_config.enabled) {
        /* NAT disabled - track this case */
        __atomic_fetch_add(&g_nat_config.stats.snat_early_returns, 1, __ATOMIC_RELAXED);
        return -1;
    }

    /* Fast path: Get IP header directly from mbuf */
    ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    protocol = ip->next_proto_id;
    inside_ip = rte_be_to_cpu_32(ip->src_addr);
    /* Capture destination IP from packet for NetFlow logging */
    uint32_t dest_ip = rte_be_to_cpu_32(ip->dst_addr);
    uint16_t dest_port = 0;

    /* Ensure L4 header is contiguous in first mbuf segment for safe casting */
    /* This handles cases where reassembly created chained mbufs with split headers */
    uint16_t l3_len = (ip->version_ihl & 0x0F) * 4;
    uint16_t min_contig_len = sizeof(struct rte_ether_hdr) + l3_len;

    switch (protocol) {
        case IPPROTO_TCP: min_contig_len += sizeof(struct rte_tcp_hdr); break;
        case IPPROTO_UDP: min_contig_len += sizeof(struct rte_udp_hdr); break;
        case IPPROTO_ICMP: min_contig_len += sizeof(struct rte_icmp_hdr); break;
    }

    if (unlikely(rte_pktmbuf_data_len(m) < min_contig_len)) {
        if (rte_pktmbuf_linearize(m) < 0) {
            /* Packet too big or fragmented weirdly, and we can't linearize headers */
            __atomic_fetch_add(&g_nat_config.stats.invalid_packet, 1, __ATOMIC_RELAXED);
            return -1;
        }
        /* Update pointers after linearization */
        ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    }

    /* Extract source port and destination port based on protocol */
    switch (protocol) {
    case IPPROTO_TCP:
        tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        inside_port = rte_be_to_cpu_16(tcp->src_port);
        dest_port = rte_be_to_cpu_16(tcp->dst_port);
        break;

    case IPPROTO_UDP:
        udp = (struct rte_udp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        inside_port = rte_be_to_cpu_16(udp->src_port);
        dest_port = rte_be_to_cpu_16(udp->dst_port);
        break;

    case IPPROTO_ICMP:
        icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        inside_port = rte_be_to_cpu_16(icmp->icmp_ident);
        /* For ICMP, destination port is the ICMP identifier (same as source) */
        dest_port = inside_port;
        /* Track ICMP echo requests */
        if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            __atomic_fetch_add(&g_nat_config.stats.icmp_echo_requests, 1, __ATOMIC_RELAXED);
        }
        break;

    default:
        /* Invalid protocol for NAT - increment counter but don't process */
        __atomic_fetch_add(&g_nat_config.stats.invalid_packet, 1, __ATOMIC_RELAXED);
        return -1;
    }

    /* Debug: Log ICMP lookup attempt */
    /* Disabled for load testing - too verbose
    static uint64_t snat_call_count = 0;
    snat_call_count++;
    if (protocol == IPPROTO_ICMP && (snat_call_count % 100) == 1) {
        printf("[SNAT] Call #%lu: Looking up inside_ip=%u.%u.%u.%u icmp_id=%u\n", snat_call_count,
               (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF, (inside_ip >> 8) & 0xFF,
               inside_ip & 0xFF, inside_port);
    }
    */

    /* Lookup existing session */
    session = nat_session_lookup_inside(inside_ip, inside_port, protocol);

    if (unlikely(!session)) {
        /* Slow path: Create new session */
        if (unlikely(g_nat_config.num_pools == 0)) {
            static uint64_t no_pool_warnings = 0;
            if (no_pool_warnings++ < 5) {
                YLOG_ERROR("[SNAT] No pools configured (enabled=%d, pools=%d)",
                       g_nat_config.enabled, g_nat_config.num_pools);
            }
            g_nat_config.stats.no_ip_available++;
            return -1;
        }

        /* Policy Based NAT: Select pool based on rules */
        struct nat_pool *selected_pool = NULL;

        if (g_nat_config.num_rules > 0) {
            /* Check rules in order */
            for (int i = 0; i < g_nat_config.num_rules; i++) {
                struct nat_rule *rule = &g_nat_config.rules[i];
                if (!rule->active)
                    continue;

                /* Check ACL */
                /* Protocol, SrcIP, DstIP, SrcPort, DstPort */
                /* For NAT ACLs we usually care about Source IP. Dst IP is 0=any */
                if (acl_check(rule->acl_name, protocol, inside_ip, 0, inside_port, 0) ==
                    ACL_PERMIT) {
                    /* Match found! Find the pool. */
                    for (int p = 0; p < g_nat_config.num_pools; p++) {
                        if (strcmp(g_nat_config.pools[p].name, rule->pool_name) == 0 &&
                            g_nat_config.pools[p].active) {
                            selected_pool = &g_nat_config.pools[p];
                            break;
                        }
                    }
                    if (selected_pool)
                        break;
                }
            }
        }

        /* Fallback: If no rule matched or no rules exist, use first pool (classic behavior) */
        /* BUT: If rules exist and none matched, typically we should NOT NAT? */
        /* For backward compatibility with previous steps, if num_rules==0 use pool[0] */
        if (!selected_pool) {
            if (g_nat_config.num_rules == 0) {
                selected_pool = &g_nat_config.pools[0];
            } else {
                /* Rules exist but none matched. */
                /* If user defined specific internal list with 'ip nat inside source list ...' */
                /* That command now creates a rule. So if no rule matches, traffic is not NATed. */
                return -1;
            }
        }

        /* Allocate public IP/Port from selected pool */
        outside_ip = nat_pool_allocate_ip(selected_pool);
        if (unlikely(!outside_ip)) {
            // YLOG_WARNING("[SNAT FAIL] Pool %s exhausted", selected_pool->name);
            g_nat_config.stats.no_ip_available++;

            /* Log quota exceeded */
            /* Log quota exceeded */
            extern void nat_logger_log_event(uint8_t event_type, uint32_t original_ip,
                                             uint16_t original_port, uint32_t translated_ip,
                                             uint16_t translated_port, uint32_t dest_ip,
                                             uint16_t dest_port, uint8_t protocol);
            /* 3=QUOTA_EXCEEDED */
            nat_logger_log_event(3, inside_ip, inside_port, 0, 0, 0, 0, protocol);

            return -1;
        }

        /* For ICMP, use EIM (Endpoint Independent Mapping) */
        if (protocol == IPPROTO_ICMP) {
            outside_port = inside_port;
        } else {
            outside_port = nat_allocate_port(selected_pool, outside_ip, protocol);
            if (unlikely(!outside_port)) {
                g_nat_config.stats.no_port_available++;
                nat_pool_release_ip(selected_pool, outside_ip);
                return -1;
            }
        }

        session = nat_session_create(inside_ip, inside_port, outside_ip, outside_port, protocol,
                                     dest_ip, dest_port);
        if (unlikely(!session)) {
            /* Cleanup allocated resources */
            if (protocol != IPPROTO_ICMP) {
                nat_release_port(selected_pool, outside_ip, outside_port, protocol);
            }
            nat_pool_release_ip(selected_pool, outside_ip);

            if (protocol == IPPROTO_ICMP) {
                __atomic_fetch_add(&g_nat_config.stats.icmp_session_race_failures, 1,
                                   __ATOMIC_RELAXED);
                YLOG_WARNING("[ICMP-IN2OUT] Session creation failed for in=%u.%u.%u.%u id=%u",
                             (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF,
                             (inside_ip >> 8) & 0xFF, inside_ip & 0xFF, inside_port);
            }
            return -1;
        }

        /* FAST PATH: No logging in hot path - stats only */
        g_nat_config.stats.in2out_misses++;
    } else {
        /* Session found - increment hit counter */
        __atomic_fetch_add(&g_nat_config.stats.in2out_hits, 1, __ATOMIC_RELAXED);
        outside_ip = session->outside_ip;
        outside_port = session->outside_port;

        /* Update destination IP/port for NetFlow logging */
        /* This ensures we capture the latest destination for EIM sessions */
        if (dest_ip != 0) {
            session->dest_ip = dest_ip;
            session->dest_port = dest_port;
        }
    }

    /* Perform translation */
    uint32_t old_ip_be = ip->src_addr;
    uint32_t new_ip_be = rte_cpu_to_be_32(outside_ip);

    /* Update IP header */
    ip->src_addr = new_ip_be;
    nat_update_ip_checksum(ip);

    /* ALG Processing (if active) */
    if (unlikely(session->alg_active)) {
        nat_alg_process(session, pkt, true);
    }

    /* Update transport layer */
    switch (protocol) {
    case IPPROTO_TCP:
        tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        tcp->cksum = nat_update_l4_checksum(tcp->cksum, old_ip_be, new_ip_be, tcp->src_port,
                                            rte_cpu_to_be_16(outside_port));
        tcp->src_port = rte_cpu_to_be_16(outside_port);
        break;

    case IPPROTO_UDP:
        udp = (struct rte_udp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        if (udp->dgram_cksum != 0) {
            udp->dgram_cksum =
                nat_update_l4_checksum(udp->dgram_cksum, old_ip_be, new_ip_be, udp->src_port,
                                       rte_cpu_to_be_16(outside_port));
        }
        udp->src_port = rte_cpu_to_be_16(outside_port);
        break;

    case IPPROTO_ICMP:
        icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        icmp->icmp_ident = rte_cpu_to_be_16(outside_port);
        /* ICMP checksum covers data, so we need to recalculate or update */
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum =
            ~rte_raw_cksum(icmp, rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip));
        break;
    }

    /* Update stats */
    session->packets_in++;
    session->bytes_in += rte_be_to_cpu_16(ip->total_length);

    /* Update per-worker stats */
    if (g_thread_worker_id >= 0 && g_thread_worker_id < NAT_MAX_WORKERS) {
        g_nat_workers[g_thread_worker_id].packets_translated++;
        g_nat_workers[g_thread_worker_id].snat_packets++;
    } else {
        /* Fallback for unknown threads */
        __atomic_fetch_add(&g_nat_config.stats.packets_translated, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&g_nat_config.stats.snat_packets, 1, __ATOMIC_RELAXED);
    }

    /* Flow cache behavior: packets are aggregated and exported on timeout
     * by the active timeout scanner thread in natexport.c
     * (inactive_timeout=15s, active_timeout=30min) */

    return 0;
}

/**
 * Process DNAT (Destination NAT) - Outside to Inside translation
 * Translates public IP:port back to private IP:port
 */
int nat_translate_dnat(struct pkt_buf *pkt, struct interface *iface)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ipv4_hdr *ip;
    struct rte_tcp_hdr *tcp;
    struct rte_udp_hdr *udp;
    struct rte_icmp_hdr *icmp;
    struct nat_session *session;
    uint32_t outside_ip, inside_ip;
    uint16_t outside_port, inside_port;
    uint8_t protocol;

    (void)iface;

    if (!m || !g_nat_config.enabled) {
        return -1;
    }

    ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    protocol = ip->next_proto_id;
    outside_ip = rte_be_to_cpu_32(ip->dst_addr);

    switch (protocol) {
    case IPPROTO_TCP:
        tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        outside_port = rte_be_to_cpu_16(tcp->dst_port);
        break;
    case IPPROTO_UDP:
        udp = (struct rte_udp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        outside_port = rte_be_to_cpu_16(udp->dst_port);
        break;
    case IPPROTO_ICMP:
        icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        outside_port = rte_be_to_cpu_16(icmp->icmp_ident);
        /* Track ICMP echo replies */
        if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
            __atomic_fetch_add(&g_nat_config.stats.icmp_echo_replies, 1, __ATOMIC_RELAXED);
        }
        break;
    default:
        return -1;
    }

    YLOG_DEBUG("DNAT lookup: dst_ip=%u.%u.%u.%u port=%u proto=%u", (outside_ip >> 24) & 0xFF,
               (outside_ip >> 16) & 0xFF, (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port,
               protocol);

    /* ICMP-specific debug */
    if (protocol == IPPROTO_ICMP) {
        YLOG_DEBUG("[ICMP-OUT2IN] Looking up: dst=%u.%u.%u.%u id=%u", (outside_ip >> 24) & 0xFF,
                   (outside_ip >> 16) & 0xFF, (outside_ip >> 8) & 0xFF, outside_ip & 0xFF,
                   outside_port);
    }

    session = nat_session_lookup_outside(outside_ip, outside_port, protocol);
    if (unlikely(!session)) {
        if (protocol == IPPROTO_ICMP) {
            /* Track ICMP identifier mismatches */
            __atomic_fetch_add(&g_nat_config.stats.icmp_identifier_mismatches, 1, __ATOMIC_RELAXED);
            YLOG_DEBUG("[ICMP-OUT2IN-MISS] No session for dst=%u.%u.%u.%u id=%u type=%u",
                       (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                       (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port,
                       icmp ? icmp->icmp_type : 0xFF);
        }
        static uint64_t out2in_miss_count = 0;
        if (unlikely((++out2in_miss_count % 100) == 0)) {
            YLOG_DEBUG("[NAT-OUT2IN-MISS #%lu] dst=%u.%u.%u.%u:%u proto=%u", out2in_miss_count,
                       (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                       (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port, protocol);
        }
        g_nat_config.stats.out2in_misses++;
        return -1;
    }
    if (protocol == IPPROTO_ICMP) {
        /* Validate session matches what we're looking for */
        if (session->outside_ip != outside_ip || session->outside_port != outside_port) {
            YLOG_WARNING("[ICMP-OUT2IN] Session mismatch: expected out=%u.%u.%u.%u id=%u, got "
                         "out=%u.%u.%u.%u id=%u",
                         (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                         (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port,
                         (session->outside_ip >> 24) & 0xFF, (session->outside_ip >> 16) & 0xFF,
                         (session->outside_ip >> 8) & 0xFF, session->outside_ip & 0xFF,
                         session->outside_port);
            __atomic_fetch_add(&g_nat_config.stats.icmp_identifier_mismatches, 1, __ATOMIC_RELAXED);
            g_nat_config.stats.out2in_misses++;
            return -1;
        }
        YLOG_DEBUG("[ICMP-OUT2IN-HIT] Session found! inside=%u.%u.%u.%u id=%u",
                   (session->inside_ip >> 24) & 0xFF, (session->inside_ip >> 16) & 0xFF,
                   (session->inside_ip >> 8) & 0xFF, session->inside_ip & 0xFF,
                   session->inside_port);
    }
    g_nat_config.stats.out2in_hits++;

    inside_ip = session->inside_ip;
    inside_port = session->inside_port;

    uint32_t old_ip_be = ip->dst_addr;
    uint32_t new_ip_be = rte_cpu_to_be_32(inside_ip);

    ip->dst_addr = new_ip_be;
    nat_update_ip_checksum(ip);

    /* ALG Processing (if active) */
    if (unlikely(session->alg_active)) {
        nat_alg_process(session, pkt, false);
    }

    switch (protocol) {
    case IPPROTO_TCP:
        tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        tcp->cksum = nat_update_l4_checksum(tcp->cksum, old_ip_be, new_ip_be, tcp->dst_port,
                                            rte_cpu_to_be_16(inside_port));
        tcp->dst_port = rte_cpu_to_be_16(inside_port);
        break;
    case IPPROTO_UDP:
        udp = (struct rte_udp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        if (udp->dgram_cksum != 0) {
            udp->dgram_cksum = nat_update_l4_checksum(udp->dgram_cksum, old_ip_be, new_ip_be,
                                                      udp->dst_port, rte_cpu_to_be_16(inside_port));
        }
        udp->dst_port = rte_cpu_to_be_16(inside_port);
        break;
    case IPPROTO_ICMP:
        icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        icmp->icmp_ident = rte_cpu_to_be_16(inside_port);
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum =
            ~rte_raw_cksum(icmp, rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip));
        break;
    }

    session->packets_out++;
    session->bytes_out += rte_be_to_cpu_16(ip->total_length);

    /* Update per-worker stats */
    if (g_thread_worker_id >= 0 && g_thread_worker_id < NAT_MAX_WORKERS) {
        g_nat_workers[g_thread_worker_id].packets_translated++;
        g_nat_workers[g_thread_worker_id].dnat_packets++;
    } else {
        __atomic_fetch_add(&g_nat_config.stats.packets_translated, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&g_nat_config.stats.dnat_packets, 1, __ATOMIC_RELAXED);
    }

    /* Flow cache behavior: packets are aggregated and exported on timeout
     * by the active timeout scanner thread in natexport.c
     * (inactive_timeout=15s, active_timeout=30min) */

    return 0;
}
