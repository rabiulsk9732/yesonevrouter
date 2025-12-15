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
#include "nat_alg.h"
#include "nat_log.h"
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

    /* FIXED: Check for IP fragments (RFC 3022 Section 4.1)
     * Fragments with non-zero offset have no L4 header
     */
    uint16_t frag_offset = rte_be_to_cpu_16(ip->fragment_offset);
    bool is_fragment = (frag_offset & 0x1FFF) != 0;       /* MF bit or non-zero offset */
    bool is_first_fragment = (frag_offset & 0x1FFF) == 0; /* offset=0, has L4 header */

    protocol = ip->next_proto_id;
    inside_ip = rte_be_to_cpu_32(ip->src_addr);
    /* Capture destination IP from packet for NetFlow logging */
    uint32_t dest_ip = rte_be_to_cpu_32(ip->dst_addr);
    uint16_t dest_port = 0;
    inside_port = 0; /* Default: no port for fragments */

    /* Only extract L4 info if not a fragment OR if it's the first fragment */
    if (!is_fragment || is_first_fragment) {
        /* Ensure L4 header is contiguous in first mbuf segment for safe casting */
        uint16_t l3_len = (ip->version_ihl & 0x0F) * 4;
        uint16_t min_contig_len = sizeof(struct rte_ether_hdr) + l3_len;

        switch (protocol) {
        case IPPROTO_TCP:
            min_contig_len += sizeof(struct rte_tcp_hdr);
            break;
        case IPPROTO_UDP:
            min_contig_len += sizeof(struct rte_udp_hdr);
            break;
        case IPPROTO_ICMP:
            min_contig_len += sizeof(struct rte_icmp_hdr);
            break;
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

        /* VPP-STYLE: Check worker ownership and handoff if needed
         * Owner is determined by INSIDE tuple ONLY (never changes after NAT)
         */
        extern uint32_t g_num_workers;
        if (g_num_workers > 1) {
            uint32_t owner_worker = nat_flow_to_worker(inside_ip, inside_port, protocol);
            if ((uint32_t)g_thread_worker_id != owner_worker) {
                /* Wrong worker - handoff packet to owner */
                if (nat_worker_handoff_enqueue(owner_worker, m) == 0) {
                    /* Successfully handed off - tell caller not to free mbuf */
                    pkt->mbuf = NULL;
                    return 1; /* Return >0 to indicate handoff (not drop) */
                }
                /* Handoff failed (ring full) - process locally as fallback */
            }
        }
    }

    /* Lookup existing session
     * For fragments without L4, we use flow-based lookup (src_ip, dst_ip, protocol)
     * This ensures subsequent fragments get the SAME NAT translation as the first fragment
     */
    session = NULL;
    if (!is_fragment || is_first_fragment) {
        /* Full session lookup with port for first fragment or non-fragmented packets */
        session = nat_session_lookup_inside(inside_ip, inside_port, protocol);
    } else {
        /* For subsequent fragments without L4 header, use flow-based lookup
         * This ensures the fragment gets the SAME NAT translation as the first fragment
         */
        session = nat_session_lookup_flow(inside_ip, dest_ip, protocol);
    }

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
        YLOG_INFO("[NAT-DEBUG] Pool '%s': allocated outside_ip = %u.%u.%u.%u", selected_pool->name,
                  (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF, (outside_ip >> 8) & 0xFF,
                  outside_ip & 0xFF);
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

        /* For ICMP, use EIM (Endpoint Independent Mapping) with identifier translation */
        if (protocol == IPPROTO_ICMP) {
            /* Allocate a different ICMP identifier for the outside */
            outside_port = nat_allocate_port(selected_pool, outside_ip, protocol);
            if (unlikely(!outside_port)) {
                g_nat_config.stats.no_port_available++;
                nat_pool_release_ip(selected_pool, outside_ip);
                return -1;
            }
        } else {
            outside_port = nat_allocate_port(selected_pool, outside_ip, protocol);
            if (unlikely(!outside_port)) {
                g_nat_config.stats.no_port_available++;
                nat_pool_release_ip(selected_pool, outside_ip);
                return -1;
            }
        }

        YLOG_INFO("[NAT-DEBUG] Creating session: inside=%u.%u.%u.%u:%u -> outside=%u.%u.%u.%u:%u",
                  (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF, (inside_ip >> 8) & 0xFF,
                  inside_ip & 0xFF, inside_port, (outside_ip >> 24) & 0xFF,
                  (outside_ip >> 16) & 0xFF, (outside_ip >> 8) & 0xFF, outside_ip & 0xFF,
                  outside_port);
        session = nat_session_create(inside_ip, inside_port, outside_ip, outside_port, protocol,
                                     dest_ip, dest_port);
        if (unlikely(!session)) {
            /* Cleanup allocated resources */
            nat_release_port(selected_pool, outside_ip, outside_port, protocol);
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

        /* Track ICMP session creation success */
        if (protocol == IPPROTO_ICMP) {
            __atomic_fetch_add(&g_nat_config.stats.icmp_sessions_created, 1, __ATOMIC_RELAXED);
            YLOG_INFO("[ICMP-IN2OUT] Session created: in=%u.%u.%u.%u:%u -> out=%u.%u.%u.%u:%u",
                      (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF,
                      (inside_ip >> 8) & 0xFF, inside_ip & 0xFF, inside_port,
                      (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                      (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port);
        }

        /* FAST PATH: No logging in hot path - stats only */
        g_nat_config.stats.in2out_misses++;
    } else {
        /* Session found - increment hit counter */
        __atomic_fetch_add(&g_nat_config.stats.in2out_hits, 1, __ATOMIC_RELAXED);
        outside_ip = session->outside_ip;
        outside_port = session->outside_port;

        /* Track ICMP session lookup hits */
        if (protocol == IPPROTO_ICMP) {
            __atomic_fetch_add(&g_nat_config.stats.icmp_sessions_lookup_hits, 1, __ATOMIC_RELAXED);
            YLOG_INFO("[ICMP-IN2OUT-HIT] Session cache hit: in=%u.%u.%u.%u:%u -> out=%u.%u.%u.%u:%u",
                      (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF,
                      (inside_ip >> 8) & 0xFF, inside_ip & 0xFF, inside_port,
                      (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                      (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port);
        }

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

    /* Update IP header (always, even for fragments) */
    ip->src_addr = new_ip_be;
    nat_update_ip_checksum(ip);

    /* FIXED: Clear hardware checksum offload flags to prevent conflicts
     * Software-calculated checksums must not be recalculated by NIC
     */
    m->ol_flags &= ~RTE_MBUF_F_TX_IPV4;
    m->ol_flags &= ~RTE_MBUF_F_TX_TCP_CKSUM;
    m->ol_flags &= ~RTE_MBUF_F_TX_UDP_CKSUM;
    m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM; /* Mark as software-calculated */

    /* ALG Processing (if active and session exists) */
    if (unlikely(session && session->alg_active)) {
        nat_alg_process(session, pkt, true);
    }

    /* Update transport layer (only if L4 header exists) */
    if (!is_fragment || is_first_fragment) {
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

            /* ICMP checksum calculation - recalculate entire checksum */
            /* Length = IP total length - IP header length = ICMP header + data */
            uint16_t icmp_len = rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip);
            icmp->icmp_cksum = 0;
            icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);

            /* ICMP Error Packet Support: Translate embedded IP packet in error messages */
            /* ICMP types 3 (Destination Unreachable), 4 (Source Quench), 5 (Redirect), */
            /* 11 (Time Exceeded), 12 (Parameter Problem) contain original IP packet */
            if (icmp->icmp_type >= 3 && icmp->icmp_type <= 5) {
                /* Check if there's enough space for embedded IP header */
                if (icmp_len >= sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr)) {
                    /* Skip ICMP header (8 bytes) to get to embedded IP packet */
                    struct rte_ipv4_hdr *emb_ip = (struct rte_ipv4_hdr *)((uint8_t *)icmp + 8);
                    uint32_t emb_src = rte_be_to_cpu_32(emb_ip->src_addr);

                    /* Check if embedded source IP matches NAT translation */
                    if (emb_src == outside_ip) {
                        /* Translate embedded IP source address */
                        emb_ip->src_addr = rte_cpu_to_be_32(inside_ip);
                        /* Recalculate embedded IP header checksum */
                        emb_ip->hdr_checksum = 0;
                        emb_ip->hdr_checksum = rte_ipv4_cksum(emb_ip);

                        /* Recalculate ICMP checksum after embedded packet modification */
                        icmp->icmp_cksum = 0;
                        icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);
                    }
                }
            }
            break;
        }
    }

    /* Update stats (only if session exists) */
    if (session) {
        session->packets_in++;
        session->bytes_in += rte_be_to_cpu_16(ip->total_length);
    }

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
    struct rte_icmp_hdr *icmp = NULL; /* Initialize to suppress warning */
    struct nat_session *session;
    uint32_t outside_ip, inside_ip;
    uint16_t outside_port, inside_port;
    uint8_t protocol;

    (void)iface;

    if (!m || !g_nat_config.enabled) {
        return -1;
    }

    ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    /* FIXED: Check for IP fragments (RFC 3022 Section 4.1) */
    uint16_t frag_offset = rte_be_to_cpu_16(ip->fragment_offset);
    bool is_fragment = (frag_offset & 0x1FFF) != 0;
    bool is_first_fragment = (frag_offset & 0x1FFF) == 0;

    protocol = ip->next_proto_id;
    outside_ip = rte_be_to_cpu_32(ip->dst_addr);
    outside_port = 0; /* Default: no port for fragments */

    /* Only extract L4 info if not a fragment OR if it's the first fragment */
    if (!is_fragment || is_first_fragment) {
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

        /* VPP-STYLE: For DNAT, compute owner from outside_port BEFORE session lookup
         * Each worker has a non-overlapping port range, so port tells us the owner
         * This avoids needing to search other workers' tables
         */
        extern uint32_t g_num_workers;
        if (g_num_workers > 1) {
            uint32_t owner_worker = nat_port_to_worker(outside_port);
            if ((uint32_t)g_thread_worker_id != owner_worker) {
                /* Wrong worker - handoff packet to owner */
                if (nat_worker_handoff_enqueue(owner_worker, m) == 0) {
                    /* Successfully handed off - tell caller not to free mbuf */
                    pkt->mbuf = NULL;
                    return 1; /* Return >0 to indicate handoff (not drop) */
                }
                /* Handoff failed (ring full) - drop packet */
                return -1;
            }
        }
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

    /* Lookup session
     * For fragments without L4, we use flow-based lookup
     * This ensures subsequent fragments get the SAME NAT translation as the first fragment
     */
    session = NULL;
    if (!is_fragment || is_first_fragment) {
        /* Full session lookup with port for first fragment or non-fragmented packets */
        /* FIXED: Use EIM lookup for ICMP (RFC 5508) */
        if (protocol == IPPROTO_ICMP) {
            session = nat_session_lookup_icmp_eim(outside_ip, outside_port);
        } else {
            /* VPP-STYLE: With handoff, we're guaranteed to be on the correct worker
             * Just do simple single-worker lookup in MY table only
             */
            session = nat_session_lookup_outside(outside_ip, outside_port, protocol);
        }
    } else {
        /* For subsequent fragments without L4 header, use flow-based lookup
         * This ensures the fragment gets the SAME NAT translation as the first fragment
         * For DNAT, we look up by (outside_ip, inside_ip, protocol)
         */
        inside_ip = rte_be_to_cpu_32(ip->src_addr); /* Get source IP from fragment */
        session = nat_session_lookup_flow(inside_ip, outside_ip, protocol);
    }
    if (unlikely(!session)) {
        if (protocol == IPPROTO_ICMP) {
            /* Track ICMP identifier mismatches and lookup misses */
            __atomic_fetch_add(&g_nat_config.stats.icmp_identifier_mismatches, 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&g_nat_config.stats.icmp_sessions_lookup_misses, 1, __ATOMIC_RELAXED);
            YLOG_WARNING("[ICMP-OUT2IN-MISS] No session for dst=%u.%u.%u.%u id=%u type=%u",
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
        __atomic_fetch_add(&g_nat_config.stats.icmp_sessions_lookup_hits, 1, __ATOMIC_RELAXED);
        YLOG_INFO("[ICMP-OUT2IN-HIT] Session found! in=%u.%u.%u.%u:%u -> out=%u.%u.%u.%u:%u",
                  (session->inside_ip >> 24) & 0xFF, (session->inside_ip >> 16) & 0xFF,
                  (session->inside_ip >> 8) & 0xFF, session->inside_ip & 0xFF, session->inside_port,
                  (session->outside_ip >> 24) & 0xFF, (session->outside_ip >> 16) & 0xFF,
                  (session->outside_ip >> 8) & 0xFF, session->outside_ip & 0xFF, session->outside_port);
    }
    g_nat_config.stats.out2in_hits++;

    /* VPP-STYLE: Check if we own this session, handoff if not
     * CRITICAL: Use stored session->owner_worker, NEVER recompute hash
     * The inside tuple that determined ownership never changes
     */
    extern uint32_t g_num_workers;
    if (g_num_workers > 1 && session->owner_worker != (uint8_t)g_thread_worker_id) {
        /* Wrong worker - handoff packet to owner */
        if (nat_worker_handoff_enqueue(session->owner_worker, m) == 0) {
            /* Successfully handed off - tell caller not to free mbuf */
            pkt->mbuf = NULL;
            return 1; /* Return >0 to indicate handoff (not drop) */
        }
        /* Handoff failed (ring full) - drop packet to preserve ownership invariant */
        return -1;
    }

    inside_ip = session->inside_ip;
    inside_port = session->inside_port;

    uint32_t old_ip_be = ip->dst_addr;
    uint32_t new_ip_be = rte_cpu_to_be_32(inside_ip);

    /* Update IP header (always, even for fragments) */
    ip->dst_addr = new_ip_be;
    nat_update_ip_checksum(ip);

    /* FIXED: Clear hardware checksum offload flags to prevent conflicts
     * Software-calculated checksums must not be recalculated by NIC
     */
    m->ol_flags &= ~RTE_MBUF_F_TX_IPV4;
    m->ol_flags &= ~RTE_MBUF_F_TX_TCP_CKSUM;
    m->ol_flags &= ~RTE_MBUF_F_TX_UDP_CKSUM;
    m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM; /* Mark as software-calculated */

    /* ALG Processing (if active and session exists) */
    if (unlikely(session && session->alg_active)) {
        nat_alg_process(session, pkt, false);
    }

    /* Update transport layer (only if L4 header exists) */
    if (!is_fragment || is_first_fragment) {
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
                udp->dgram_cksum =
                    nat_update_l4_checksum(udp->dgram_cksum, old_ip_be, new_ip_be, udp->dst_port,
                                           rte_cpu_to_be_16(inside_port));
            }
            udp->dst_port = rte_cpu_to_be_16(inside_port);
            break;
        case IPPROTO_ICMP:
            icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
            icmp->icmp_ident = rte_cpu_to_be_16(inside_port);

            /* ICMP checksum calculation - recalculate entire checksum */
            uint16_t icmp_len = rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip);
            icmp->icmp_cksum = 0;
            icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);

            /* ICMP Error Packet Support: Translate embedded IP packet in error messages */
            if (icmp->icmp_type >= 3 && icmp->icmp_type <= 5) {
                /* Check if there's enough space for embedded IP header */
                if (icmp_len >= sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr)) {
                    /* Skip ICMP header (8 bytes) to get to embedded IP packet */
                    struct rte_ipv4_hdr *emb_ip = (struct rte_ipv4_hdr *)((uint8_t *)icmp + 8);
                    uint32_t emb_src = rte_be_to_cpu_32(emb_ip->src_addr);

                    /* Check if embedded source IP matches NAT translation */
                    if (emb_src == inside_ip) {
                        /* Translate embedded IP source address back to outside IP */
                        emb_ip->src_addr = rte_cpu_to_be_32(outside_ip);
                        /* Recalculate embedded IP header checksum */
                        emb_ip->hdr_checksum = 0;
                        emb_ip->hdr_checksum = rte_ipv4_cksum(emb_ip);

                        /* Recalculate ICMP checksum after embedded packet modification */
                        icmp->icmp_cksum = 0;
                        icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);
                    }
                }
            }
            break;
        }
    }

    /* Update stats (only if session exists) */
    if (session) {
        session->packets_out++;
        session->bytes_out += rte_be_to_cpu_16(ip->total_length);
    }

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
