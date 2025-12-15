/**
 * @file packet_rx.c
 * @brief Packet Reception and Processing
 *
 * References:
 * - DPDK Programmer's Guide: https://doc.dpdk.org/guides/prog_guide/
 * - VPP Developer Guide: https://my-vpp-docs.readthedocs.io/en/latest/gettingstarted/developers/
 */

#include "packet_rx.h"
#include "arp.h"
#include "arp_queue.h"
#include "cpu_scheduler.h"
#include "dpdk_init.h"
#include "fragmentation.h"
#include "hqos.h"
#include "interface.h"
#include "ipv6/ipv6.h"
#include "log.h"
#include "nat.h"
#include "packet.h"
#include "pppoe.h"
#include "radius_lockless.h"
#include "reassembly.h"
#include "routing_table.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* Access to NAT worker count - needed for worker affinity check */
extern uint32_t g_num_workers;

/* Access NAT config for debugging */
extern struct nat_config g_nat_config;
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_DPDK
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#else
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include "env_config.h"

#ifdef HAVE_DPDK
#include <rte_ring.h>

/* VPP-STYLE WORKER HANDOFF INFRASTRUCTURE */
#define MAX_WORKERS 8
#define HANDOFF_RING_SIZE 4096

/* Inter-worker rings for packet handoff */
static struct rte_ring *g_worker_rings[MAX_WORKERS] = {NULL};
static uint32_t g_num_nat_workers = 1;

/* Deterministic hash for worker selection (VPP-style) */
static inline uint32_t nat_worker_hash(uint32_t src_ip, uint16_t src_port)
{
    /* Simple but effective hash - same flow always goes to same worker */
    uint32_t hash = src_ip ^ ((uint32_t)src_port << 16) ^ src_port;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    return hash;
}

static inline uint32_t get_nat_worker_id(uint32_t src_ip, uint16_t src_port)
{
    if (g_num_nat_workers <= 1)
        return 0;
    return nat_worker_hash(src_ip, src_port) % g_num_nat_workers;
}

/* Initialize worker handoff rings */
static int init_worker_handoff_rings(uint32_t num_workers)
{
    char ring_name[32];
    g_num_nat_workers = num_workers > MAX_WORKERS ? MAX_WORKERS : num_workers;

    for (uint32_t i = 0; i < g_num_nat_workers; i++) {
        snprintf(ring_name, sizeof(ring_name), "nat_worker_%u", i);
        g_worker_rings[i] =
            rte_ring_create(ring_name, HANDOFF_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
        if (!g_worker_rings[i]) {
            YLOG_ERROR("Failed to create worker ring %u", i);
            return -1;
        }
    }
    YLOG_INFO("[HANDOFF] Created %u worker rings (size=%u)", g_num_nat_workers, HANDOFF_RING_SIZE);
    return 0;
}

/* Per-thread TX buffer for batched transmission (CARRIER-GRADE) */
#define TX_BURST_MAX 32
static __thread struct {
    struct rte_mbuf *pkts[TX_BURST_MAX];
    uint16_t count;
    uint16_t port_id;
    uint16_t queue_id;
} tl_tx_buf = {0};

static inline void tx_flush(void)
{
    if (tl_tx_buf.count == 0)
        return;
    uint16_t sent =
        rte_eth_tx_burst(tl_tx_buf.port_id, tl_tx_buf.queue_id, tl_tx_buf.pkts, tl_tx_buf.count);
    /* Free unsent packets */
    for (uint16_t i = sent; i < tl_tx_buf.count; i++) {
        rte_pktmbuf_free(tl_tx_buf.pkts[i]);
    }
    tl_tx_buf.count = 0;
}

static inline void tx_enqueue(uint16_t port, uint16_t queue, struct rte_mbuf *m)
{
    tl_tx_buf.port_id = port;
    tl_tx_buf.queue_id = queue;
    tl_tx_buf.pkts[tl_tx_buf.count++] = m;
    if (tl_tx_buf.count >= TX_BURST_MAX) {
        tx_flush();
    }
}
#endif

static volatile bool g_rx_running = false;
/* static pthread_t g_rx_thread; - Removed, using multiple detached threads */

/* Forwarding statistics */
static struct {
    uint64_t packets_forwarded;
    uint64_t bytes_forwarded;
    uint64_t packets_dropped_no_route;
    uint64_t packets_dropped_ttl_exceeded;
    uint64_t packets_dropped_arp_failed;
    uint64_t icmp_time_exceeded_sent;
    uint64_t ipv6_packets_forwarded;
    uint64_t ipv6_packets_dropped_no_route;
    uint64_t ipv6_packets_dropped_hop_exceeded;
} g_fwd_stats = {0};

/* Process ARP packet */
static void process_arp(struct pkt_buf *pkt)
{
    /* Validate ARP header - l3_offset points to ARP header after Ethernet */
    if (pkt->len < pkt->meta.l3_offset + sizeof(struct arp_hdr)) {
        YLOG_WARNING("Truncated ARP packet");
        return;
    }

    /* ARP packet processing - fast path, no logging */

    /* Pass ARP data (starting at l3_offset, after Ethernet header) to ARP subsystem */
    uint8_t *arp_data = pkt->data + pkt->meta.l3_offset;
    uint16_t arp_len = pkt->len - pkt->meta.l3_offset;
    arp_process_packet(arp_data, arp_len, pkt->meta.ingress_ifindex);
}

/* Calculate checksum - used for IP/ICMP */
static uint16_t calc_checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/* Process ICMP echo request - send reply using DPDK structures
 * OPTIMIZED: Modifies packet in-place to avoid allocation overhead */
static void process_icmp_echo(struct pkt_buf *pkt, struct interface *iface)
{
#ifdef HAVE_DPDK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    struct rte_icmp_hdr *icmp =
        (struct rte_icmp_hdr *)(pkt->data + sizeof(struct rte_ether_hdr) + ihl);

    /* Only handle echo request (type 8) */
    if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        return;
    }

    /* FAST PATH: Modify packet in-place to create reply (no allocation!) */

    /* Swap Ethernet addresses - set dst to original src, src to our MAC */
    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    memcpy(&eth->src_addr, iface->mac_addr, RTE_ETHER_ADDR_LEN);

    /* Swap IP addresses */
    uint32_t tmp_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = tmp_ip;

    /* Recalculate IP checksum */
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Change ICMP type to echo reply (type 0) */
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

    /* Update ICMP checksum incrementally:
     * Old type was 8 (request), new type is 0 (reply)
     * Checksum difference: +8 (since we changed from 8 to 0) */
    /* Recalculate ICMP checksum using DPDK optimized function */
    icmp->icmp_cksum = 0;
    /* Calculate length of ICMP message (Total IP length - IP header length) */
    uint16_t icmp_len = rte_be_to_cpu_16(ip->total_length) - ihl;
    icmp->icmp_cksum = ~rte_raw_cksum(icmp, icmp_len);

    /* Reset TTL for the reply */
    ip->time_to_live = 64;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Send reply using the same packet buffer */
    if (interface_send(iface, pkt) != 0) {
        YLOG_ERROR("Failed to send ICMP echo reply");
    }
    /* Note: pkt will be freed by caller - we modified it in place */
#else
    (void)pkt;
    (void)iface;
#endif
}

#ifdef HAVE_DPDK
/**
 * @brief Send ICMP Time Exceeded message
 */
static void send_icmp_time_exceeded(struct pkt_buf *pkt, struct interface *ingress_iface)
{
    /* Allocate ICMP error packet */
    struct pkt_buf *icmp_pkt = pkt_alloc();
    if (!icmp_pkt) {
        YLOG_ERROR("Failed to allocate ICMP Time Exceeded packet");
        return;
    }

    struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *orig_ip =
        (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    /* Build ICMP Time Exceeded */
    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)icmp_pkt->data;
    struct rte_ipv4_hdr *new_ip =
        (struct rte_ipv4_hdr *)(icmp_pkt->data + sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmp =
        (struct rte_icmp_hdr *)(icmp_pkt->data + sizeof(struct rte_ether_hdr) +
                                sizeof(struct rte_ipv4_hdr));

    /* Ethernet header */
    rte_ether_addr_copy(&orig_eth->src_addr, &new_eth->dst_addr);
    memcpy(&new_eth->src_addr, ingress_iface->mac_addr, RTE_ETHER_ADDR_LEN);
    new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IP header */
    new_ip->version_ihl = 0x45; /* IPv4, 20 bytes */
    new_ip->type_of_service = 0;
    new_ip->total_length = rte_cpu_to_be_16(
        sizeof(struct rte_ipv4_hdr) + 8 + 28); /* IP + ICMP header + original IP header + 8 bytes */
    new_ip->packet_id = 0;
    new_ip->fragment_offset = 0;
    new_ip->time_to_live = 64;
    new_ip->next_proto_id = IPPROTO_ICMP;
    new_ip->src_addr = ingress_iface->config.ipv4_addr.s_addr;
    new_ip->dst_addr = orig_ip->src_addr;
    new_ip->hdr_checksum = 0;
    new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

    /* ICMP header */
    icmp->icmp_type = 11; /* Time Exceeded */
    icmp->icmp_code = 0;  /* TTL exceeded in transit */
    icmp->icmp_cksum = 0;
    icmp->icmp_ident = 0;
    icmp->icmp_seq_nb = 0;

    /* Copy original IP header + 8 bytes of data */
    memcpy(icmp + 1, orig_ip, 28);

    /* Calculate ICMP checksum */
    icmp->icmp_cksum = calc_checksum(icmp, 8 + 28);

    icmp_pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 8 + 28;

    /* Send back on ingress interface */
    if (interface_send(ingress_iface, icmp_pkt) == 0) {
        g_fwd_stats.icmp_time_exceeded_sent++;
    }

    pkt_free(icmp_pkt);
}

/**
 * @brief Send ICMP Destination Unreachable message
 * @param pkt Original packet that triggered the error
 * @param ingress_iface Interface where packet was received
 * @param code ICMP code (0=Network Unreachable, 1=Host Unreachable, etc.)
 */
static void send_icmp_destination_unreachable(struct pkt_buf *pkt, struct interface *ingress_iface,
                                              uint8_t code)
{
    /* Allocate ICMP error packet */
    struct pkt_buf *icmp_pkt = pkt_alloc();
    if (!icmp_pkt) {
        YLOG_ERROR("Failed to allocate ICMP Destination Unreachable packet");
        return;
    }

    struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *orig_ip =
        (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    /* Build ICMP Destination Unreachable */
    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)icmp_pkt->data;
    struct rte_ipv4_hdr *new_ip =
        (struct rte_ipv4_hdr *)(icmp_pkt->data + sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmp =
        (struct rte_icmp_hdr *)(icmp_pkt->data + sizeof(struct rte_ether_hdr) +
                                sizeof(struct rte_ipv4_hdr));

    /* Ethernet header */
    rte_ether_addr_copy(&orig_eth->src_addr, &new_eth->dst_addr);
    memcpy(&new_eth->src_addr, ingress_iface->mac_addr, RTE_ETHER_ADDR_LEN);
    new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IP header */
    new_ip->version_ihl = 0x45; /* IPv4, 20 bytes */
    new_ip->type_of_service = 0;
    new_ip->total_length = rte_cpu_to_be_16(
        sizeof(struct rte_ipv4_hdr) + 8 + 28); /* IP + ICMP header + original IP header + 8 bytes */
    new_ip->packet_id = 0;
    new_ip->fragment_offset = 0;
    new_ip->time_to_live = 64;
    new_ip->next_proto_id = IPPROTO_ICMP;
    new_ip->src_addr = ingress_iface->config.ipv4_addr.s_addr;
    new_ip->dst_addr = orig_ip->src_addr;
    new_ip->hdr_checksum = 0;
    new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

    /* ICMP header */
    icmp->icmp_type = 3;    /* Destination Unreachable */
    icmp->icmp_code = code; /* 0=Network Unreachable, 1=Host Unreachable */
    icmp->icmp_cksum = 0;
    icmp->icmp_ident = 0;
    icmp->icmp_seq_nb = 0;

    /* Copy original IP header + 8 bytes of data */
    memcpy(icmp + 1, orig_ip, 28);

    /* Calculate ICMP checksum */
    icmp->icmp_cksum = calc_checksum(icmp, 8 + 28);

    icmp_pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 8 + 28;

    /* Send back on ingress interface */
    if (interface_send(ingress_iface, icmp_pkt) == 0) {
        YLOG_DEBUG("ICMP Destination Unreachable (code %u) sent", code);
    }

    pkt_free(icmp_pkt);
}

/**
 * @brief Forward IPv4 packet to next hop
 */
static int forward_ipv4_packet(struct pkt_buf *pkt)
{
    struct routing_table *rt = routing_table_get_instance();
    if (!rt) {
        YLOG_ERROR("Routing table not initialized");
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    /* Check TTL */
    if (ip->time_to_live <= 1) {
        YLOG_DEBUG(
            "TTL exceeded for packet to %u.%u.%u.%u", (rte_be_to_cpu_32(ip->dst_addr) >> 24) & 0xFF,
            (rte_be_to_cpu_32(ip->dst_addr) >> 16) & 0xFF,
            (rte_be_to_cpu_32(ip->dst_addr) >> 8) & 0xFF, rte_be_to_cpu_32(ip->dst_addr) & 0xFF);

        struct interface *ingress_iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        if (ingress_iface) {
            send_icmp_time_exceeded(pkt, ingress_iface);
        }
        g_fwd_stats.packets_dropped_ttl_exceeded++;
        return -1;
    }

    /* Route lookup */
    struct in_addr dst_addr;
    dst_addr.s_addr = ip->dst_addr;

    /* Debug logging disabled for production */

    struct route_entry *route = routing_table_lookup(rt, &dst_addr);
    if (!route) {
        YLOG_WARNING("No route to %u.%u.%u.%u", (rte_be_to_cpu_32(ip->dst_addr) >> 24) & 0xFF,
                     (rte_be_to_cpu_32(ip->dst_addr) >> 16) & 0xFF,
                     (rte_be_to_cpu_32(ip->dst_addr) >> 8) & 0xFF,
                     rte_be_to_cpu_32(ip->dst_addr) & 0xFF);

        /* Send ICMP Destination Unreachable (Network Unreachable) */
        struct interface *ingress_iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        if (ingress_iface && ip->next_proto_id != IPPROTO_ICMP) {
            send_icmp_destination_unreachable(pkt, ingress_iface,
                                              0); /* Code 0 = Network Unreachable */
        }

        g_fwd_stats.packets_dropped_no_route++;
        return -1;
    }

    /* Get egress interface */
    struct interface *egress_iface = interface_find_by_index(route->egress_ifindex);
    if (!egress_iface || egress_iface->state != IF_STATE_UP) {
        YLOG_ERROR("Egress interface %u not available", route->egress_ifindex);
        return -1;
    }

    /* NAT processing - check if NAT is enabled and applies */
    struct interface *ingress_iface = interface_find_by_index(pkt->meta.ingress_ifindex);

    /* NAT debug logging disabled for production */

    if (nat_is_enabled() && ingress_iface && egress_iface) {
        /* Apply SNAT for traffic from inside (LAN) to outside (WAN) */
        /* Check: if ingress and egress are different interfaces, apply SNAT */
        /* Also check if source IP is in private range (RFC 1918) */
        uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
        bool is_private_ip = ((src_ip & 0xFF000000) == 0x0A000000) || /* 10.0.0.0/8 */
                             ((src_ip & 0xFFF00000) == 0xAC100000) || /* 172.16.0.0/12 */
                             ((src_ip & 0xFFFF0000) == 0xC0A80000);   /* 192.168.0.0/16 */

        /* Apply NAT if: different interfaces OR source is private IP going to WAN */
        if (ingress_iface->ifindex != egress_iface->ifindex || is_private_ip) {
            /* Removed verbose ICMP logging for performance */
            int nat_result = nat_translate_snat(pkt, egress_iface);
            if (nat_result < 0) {
                /* Removed verbose ICMP logging for performance */
                YLOG_WARNING(
                    "NAT SNAT failed for packet from %u.%u.%u.%u (ingress=%u, egress=%u, pools=%d)",
                    (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF,
                    src_ip & 0xFF, ingress_iface->ifindex, egress_iface->ifindex,
                    g_nat_config.num_pools);
                /* Don't continue - NAT is required for private IPs */
                if (is_private_ip) {
                    g_fwd_stats.packets_dropped_no_route++;
                    return -1;
                }
            } else {
                /* Removed verbose ICMP logging for performance */
                YLOG_DEBUG("NAT SNAT applied: %u.%u.%u.%u -> translated", (src_ip >> 24) & 0xFF,
                           (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF);
            }
        }
    } else if (ingress_iface && egress_iface) {
        /* Check if we should have NAT but it's not enabled */
        uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
        bool is_private_ip = ((src_ip & 0xFF000000) == 0x0A000000) ||
                             ((src_ip & 0xFFF00000) == 0xAC100000) ||
                             ((src_ip & 0xFFFF0000) == 0xC0A80000);

        if (is_private_ip && ingress_iface->ifindex != egress_iface->ifindex) {
            YLOG_WARNING(
                "Private IP %u.%u.%u.%u needs NAT but NAT is disabled (enabled=%d, pools=%d)",
                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                nat_is_enabled(), g_nat_config.num_pools);
        }
    }

    /* Determine next-hop IP (use route's next_hop if specified, otherwise use destination) */
    uint32_t next_hop_ip = (route->next_hop.s_addr != 0) ? ntohl(route->next_hop.s_addr)
                                                         : rte_be_to_cpu_32(ip->dst_addr);

    /* Check if destination is a PPPoE client */
    struct pppoe_session *pppoe_session = pppoe_find_session_by_ip(next_hop_ip);
    if (pppoe_session) {
        /* Encapsulate and send via PPPoE */
        /* Decrement TTL */
        ip->time_to_live--;
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);

        if (pppoe_send_session_packet(pppoe_session, pkt) == 0) {
            g_fwd_stats.packets_forwarded++;
            g_fwd_stats.bytes_forwarded += pkt->len;
            return 0;
        } else {
            return -1;
        }
    }

    /* ARP lookup for next-hop MAC */
    uint8_t next_hop_mac[6];
    if (arp_lookup(next_hop_ip, next_hop_mac) != 0) {
        /* ARP entry not found - send ARP request */
        YLOG_DEBUG("No ARP entry for next-hop %u.%u.%u.%u, sending ARP request",
                   (next_hop_ip >> 24) & 0xFF, (next_hop_ip >> 16) & 0xFF,
                   (next_hop_ip >> 8) & 0xFF, next_hop_ip & 0xFF);

        /* Send ARP request for the gateway */
        uint32_t src_ip = rte_be_to_cpu_32(egress_iface->config.ipv4_addr.s_addr);
        if (arp_send_request(next_hop_ip, src_ip, egress_iface->mac_addr, egress_iface->ifindex) !=
            0) {
            YLOG_WARNING("Failed to send ARP request for next-hop %u.%u.%u.%u",
                         (next_hop_ip >> 24) & 0xFF, (next_hop_ip >> 16) & 0xFF,
                         (next_hop_ip >> 8) & 0xFF, next_hop_ip & 0xFF);
            g_fwd_stats.packets_dropped_arp_failed++;
            return -1;
        }

        /* Try lookup again after sending request (might have been cached) */
        if (arp_lookup(next_hop_ip, next_hop_mac) != 0) {
            /* Still no entry - queue packet for later, ARP reply will come later */
            YLOG_DEBUG("ARP entry still not available for %u.%u.%u.%u, queuing packet",
                       (next_hop_ip >> 24) & 0xFF, (next_hop_ip >> 16) & 0xFF,
                       (next_hop_ip >> 8) & 0xFF, next_hop_ip & 0xFF);

            /* Queue packet for ARP resolution */
            if (arp_queue_packet(next_hop_ip, pkt, egress_iface, ingress_iface) == 0) {
                /* Packet queued successfully - don't free it */
                return 0;
            } else {
                /* Queue full - drop packet */
                g_fwd_stats.packets_dropped_arp_failed++;
                return -1;
            }
        }
    }

    /* Decrement TTL */
    ip->time_to_live--;

    /* Recalculate IP checksum */
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Update Ethernet header */
    memcpy(&eth->dst_addr, next_hop_mac, RTE_ETHER_ADDR_LEN);
    memcpy(&eth->src_addr, egress_iface->mac_addr, RTE_ETHER_ADDR_LEN);

    /* Set egress interface */
    pkt->meta.egress_ifindex = route->egress_ifindex;

    /* Check if we need to fragment */
    if (pkt->len > egress_iface->config.mtu) {
        YLOG_INFO("Packet size %u exceeds MTU %u, attempting fragmentation", pkt->len,
                  egress_iface->config.mtu);

        /* Check DF bit */
        uint16_t frag_off = rte_be_to_cpu_16(ip->fragment_offset);
        if (frag_off & (RTE_IPV4_HDR_DF_FLAG << 13)) {
            /* DF bit set - send ICMP Fragmentation Needed */
            struct interface *ingress_iface = interface_find_by_index(pkt->meta.ingress_ifindex);
            if (ingress_iface) {
                send_icmp_fragmentation_needed(pkt, egress_iface->config.mtu, ingress_iface);
            }
            return -1;
        }

        /* Fragment and send */
        return ip_fragment_packet(pkt, egress_iface->config.mtu, egress_iface);
    }

    /* Forward packet */
    /* Removed verbose logging - use YLOG_DEBUG if needed for troubleshooting */

    if (interface_send(egress_iface, pkt) == 0) {
        g_fwd_stats.packets_forwarded++;
        g_fwd_stats.bytes_forwarded += pkt->len;
        return 0;
    }

    return -1;
}

/**
 * @brief Forward IPv6 packet to next hop
 */
static int forward_ipv6_packet(struct pkt_buf *pkt)
{
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    /* Check Hop Limit */
    if (ip6->hop_limits <= 1) {
        YLOG_DEBUG("IPv6 Hop Limit exceeded");
        /* TODO: Send ICMPv6 Time Exceeded */
        g_fwd_stats.ipv6_packets_dropped_hop_exceeded++;
        return -1;
    }

    /* Route lookup using our IPv6 LPM */
    struct ipv6_addr dst_addr;
    memcpy(dst_addr.addr, ip6->dst_addr, 16);

    struct ipv6_route *route = ipv6_route_lookup(&dst_addr);
    if (!route) {
        char dst_str[64];
        inet_ntop(AF_INET6, ip6->dst_addr, dst_str, sizeof(dst_str));
        YLOG_DEBUG("No IPv6 route to %s", dst_str);
        g_fwd_stats.ipv6_packets_dropped_no_route++;
        return -1;
    }

    /* Get egress interface by name */
    struct interface *egress_iface = interface_find_by_name(route->interface);
    if (!egress_iface || egress_iface->state != IF_STATE_UP) {
        YLOG_WARNING("IPv6 egress interface %s not available", route->interface);
        return -1;
    }

    /* Decrement Hop Limit */
    ip6->hop_limits--;

    /* For now, use a simple approach: set destination MAC to gateway MAC */
    /* In production, would do NDP lookup for next-hop MAC */
    /* For tap interface testing, kernel handles L2 */

    /* Update Ethernet header */
    memcpy(&eth->src_addr, egress_iface->mac_addr, RTE_ETHER_ADDR_LEN);
    /* For testing via tap, broadcast or let kernel handle */
    memset(&eth->dst_addr, 0xff, RTE_ETHER_ADDR_LEN); /* Broadcast for now */
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

    /* Set egress interface */
    pkt->meta.egress_ifindex = egress_iface->ifindex;

    /* Forward packet */
    if (interface_send(egress_iface, pkt) == 0) {
        g_fwd_stats.ipv6_packets_forwarded++;
        char dst_str[64];
        inet_ntop(AF_INET6, ip6->dst_addr, dst_str, sizeof(dst_str));
        YLOG_DEBUG("IPv6 packet forwarded to %s via %s", dst_str, egress_iface->name);
        return 0;
    }

    return -1;
}
#endif /* HAVE_DPDK */

/* Process IPv6 packet */
static void process_ipv6(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return;
    }

    struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
    if (!iface) {
        return;
    }

    /* Check if IPv6 is enabled */
    if (!ipv6_is_enabled()) {
        YLOG_DEBUG("IPv6 packet received but IPv6 is disabled");
        return;
    }

#ifdef HAVE_DPDK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv6_hdr *ip6 = (struct rte_ipv6_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    uint8_t next_header = ip6->proto;

    /* Handle ICMPv6 */
    if (next_header == IPPROTO_ICMPV6) {
        uint8_t *icmp_data = pkt->data + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr);
        uint8_t icmp_type = icmp_data[0];

        if (icmp_type == ICMPV6_ECHO_REQUEST) {
            /* Echo Request - send Echo Reply */
            YLOG_DEBUG("ICMPv6 Echo Request received");

            /* Swap src/dst addresses */
            uint8_t tmp_addr[16];
            memcpy(tmp_addr, ip6->src_addr, 16);
            memcpy(ip6->src_addr, ip6->dst_addr, 16);
            memcpy(ip6->dst_addr, tmp_addr, 16);

            /* Swap MAC addresses */
            struct rte_ether_addr tmp_mac;
            rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
            rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
            rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);

            /* Change type to Echo Reply */
            icmp_data[0] = ICMPV6_ECHO_REPLY;

            /* Recalculate ICMPv6 checksum (simple fix: adjust by type difference) */
            /* Type changed from 128 to 129, difference = 1 */
            uint16_t *cksum_ptr = (uint16_t *)(icmp_data + 2);
            uint32_t cksum = ntohs(*cksum_ptr);
            cksum += (ICMPV6_ECHO_REQUEST - ICMPV6_ECHO_REPLY);
            if (cksum > 0xFFFF)
                cksum -= 0xFFFF;
            *cksum_ptr = htons((uint16_t)cksum);

            /* Send back on same interface */
            interface_send(iface, pkt);
            YLOG_DEBUG("ICMPv6 Echo Reply sent");
            return;
        } else if (icmp_type == ICMPV6_NEIGHBOR_SOLICIT) {
            /* Neighbor Solicitation - extract source MAC for NDP cache */
            YLOG_DEBUG("ICMPv6 Neighbor Solicitation received");
            /* TODO: Send Neighbor Advertisement */
        } else if (icmp_type == ICMPV6_NEIGHBOR_ADVERT) {
            /* Neighbor Advertisement - update NDP cache */
            YLOG_DEBUG("ICMPv6 Neighbor Advertisement received");
            struct ipv6_addr src;
            memcpy(src.addr, ip6->src_addr, 16);
            ndp_update(&src, eth->src_addr.addr_bytes);
        }
        return;
    }

    /* Forward packet */
    forward_ipv6_packet(pkt);
#else
    YLOG_DEBUG("IPv6 forwarding requires DPDK");
    (void)pkt;
#endif
}

/* Process IPv4 packet */
static void process_ipv4(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return;
    }

    struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
    if (!iface) {
        return;
    }

    /* FIXED: Apply NAT BEFORE reassembly to handle fragments
     * RFC 3022 Section 4.1: NAT must translate fragments
     * Lock-free: Each fragment goes to same worker via RSS
     */
#ifdef HAVE_DPDK
    if (nat_is_enabled() && (iface->config.nat_inside || iface->config.nat_outside)) {
        struct rte_mbuf *m = pkt->mbuf;
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
        uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
        uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);

        /* FIXED: Check both directions for asymmetric routing
         * Determine translation direction based on IP addresses, not just interface
         */
        bool src_is_private = ((src_ip & 0xFF000000) == 0x0A000000) || /* 10.0.0.0/8 */
                              ((src_ip & 0xFFF00000) == 0xAC100000) || /* 172.16.0.0/12 */
                              ((src_ip & 0xFFFF0000) == 0xC0A80000);   /* 192.168.0.0/16 */

        bool dst_is_private = ((dst_ip & 0xFF000000) == 0x0A000000) ||
                              ((dst_ip & 0xFFF00000) == 0xAC100000) ||
                              ((dst_ip & 0xFFFF0000) == 0xC0A80000);

        /* Check if this is a fragment */
        uint16_t frag_offset = rte_be_to_cpu_16(ip->fragment_offset);
        bool is_fragment = (frag_offset & 0x1FFF) != 0; /* MF bit or non-zero offset */

        /* Apply NAT based on translation direction (not just interface) */
        if (src_is_private && !dst_is_private) {
            /* SNAT: Private → Public (inside to outside) */
            int nat_result = nat_translate_snat(pkt, iface);
            if (nat_result < 0 && !is_fragment) {
                /* Drop non-fragment if NAT fails */
                return;
            }
        } else if (!src_is_private && dst_is_private) {
            /* DNAT: Public → Private (outside to inside) */
            int nat_result = nat_translate_dnat(pkt, iface);
            if (nat_result < 0 && !is_fragment) {
                return;
            }
        } else if (iface->config.nat_inside && src_is_private) {
            /* Fallback: Interface-based NAT for inside interface */
            int nat_result = nat_translate_snat(pkt, iface);
            if (nat_result < 0 && !is_fragment) {
                return;
            }
        } else if (iface->config.nat_outside && dst_is_private) {
            /* Fallback: Interface-based NAT for outside interface */
            int nat_result = nat_translate_dnat(pkt, iface);
            if (nat_result < 0 && !is_fragment) {
                return;
            }
        }

        /* FIXED: Worker Affinity Check for RSS Consistency
         * RSS may send forward/reverse packets to different workers
         * Ensure packets go to the worker that owns the NAT session
         */
        struct nat_session *session = NULL;
        uint16_t l4_port = 0;
        uint8_t proto = ip->next_proto_id;

        /* Extract ports if not a fragment */
        if (!is_fragment || (rte_be_to_cpu_16(ip->fragment_offset) & 0x1FFF) == 0) {
            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
                struct rte_tcp_hdr *tcp_hdr =
                    (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
                l4_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
            } else if (proto == IPPROTO_ICMP) {
                struct rte_icmp_hdr *icmp_hdr =
                    (struct rte_icmp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
                l4_port = rte_be_to_cpu_16(icmp_hdr->icmp_ident);
            }
        }

        /* Lookup session to get worker affinity */
        if (!is_fragment) {
            if (src_is_private && !dst_is_private) {
                /* SNAT - lookup by outside (translated) */
                session = nat_session_lookup_outside(dst_ip, l4_port, proto);
            } else if (!src_is_private && dst_is_private) {
                /* DNAT - lookup by outside (translated) */
                session = nat_session_lookup_outside(src_ip, l4_port, proto);
            }
        }

        /* Check worker affinity and handoff if needed */
        if (session && g_num_nat_workers > 1) {
            /* VPP-STYLE: Use stored owner_worker, NEVER recompute hash
             * The owner was determined at session creation using inside tuple
             */
            uint32_t expected_worker = session->owner_worker;
            extern __thread int g_thread_worker_id;
            int current_worker = g_thread_worker_id;

            if (current_worker >= 0 && current_worker != (int)expected_worker) {
                /* Wrong worker! Handoff to correct worker */
                int ret = nat_worker_handoff_enqueue(expected_worker, pkt->mbuf);
                if (ret == 0) {
                    /* Successfully enqueued - don't process this packet */
                    return;
                }
                /* If handoff fails (ring full), continue processing on this worker */
                /* This is acceptable - packet will be processed, just not ideal */
            }
        }
    }
#endif

    /* Try reassembly after NAT (handles both translated and non-translated) */
    struct pkt_buf *reassembled = NULL;
    int result = ip_reassembly_process(pkt, &reassembled);

    if (result < 0) {
        /* Reassembly error */
        YLOG_ERROR("IP reassembly failed");
        return;
    } else if (result == 0) {
        /* Waiting for more fragments - don't free pkt, it's stored */
        return;
    }

    /* result == 1: Complete packet (possibly reassembled) */
    pkt = reassembled;

#ifdef HAVE_DPDK
    /* Apply post-reassembly NAT if needed (for fragments that arrived after session creation) */
    if (nat_is_enabled() && (iface->config.nat_inside || iface->config.nat_outside)) {
        /* Fragment already translated? Check and skip if so */
        struct rte_mbuf *m = pkt->mbuf;
        if (m && !(m->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)) {
            /* Not translated yet - do it now */
            if (iface->config.nat_inside) {
                nat_translate_snat(pkt, iface);
            } else if (iface->config.nat_outside) {
                nat_translate_dnat(pkt, iface);
            }
        }
    }

    /* NAT44 HAIRPIN: Private IP -> NAT -> Same port back (for testing) */
    if (nat_is_enabled()) {
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
        uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);

        /* Check if source is private IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) */
        bool is_private = ((src_ip & 0xFF000000) == 0x0A000000) ||
                          ((src_ip & 0xFFF00000) == 0xAC100000) ||
                          ((src_ip & 0xFFFF0000) == 0xC0A80000);

        if (is_private) {
            /* NAT already applied above - just forward */
            /* Decrement TTL */
            ip->time_to_live--;
            ip->hdr_checksum = 0;
            ip->hdr_checksum = rte_ipv4_cksum(ip);

            /* BATCHED HAIRPIN: Enqueue to per-thread TX buffer (CARRIER-GRADE) */
            struct rte_mbuf *m = pkt->mbuf;
            if (m) {
                uint16_t tx_port = m->port; /* Use ingress port for egress */
                uint16_t tx_queue = g_thread_queue_id % env_get_tx_queues();
                tx_enqueue(tx_port, tx_queue, m);
                g_fwd_stats.packets_forwarded++;
                g_fwd_stats.bytes_forwarded += pkt->len;
                pkt->mbuf = NULL; /* Mbuf ownership transferred to TX buffer */
                return;
            }
            /* No mbuf, fall through to drop */
        }
    }
#endif

    /* Intercept RADIUS responses (UDP from port 1812/1813) BEFORE for_us check */
    /* RADIUS responses go to NAS IP which may not be on any interface */
    if (pkt->meta.protocol == IPPROTO_UDP) {
        struct rte_ether_hdr *eth_r = (struct rte_ether_hdr *)pkt->data;
        struct rte_ipv4_hdr *ip_r = (struct rte_ipv4_hdr *)(eth_r + 1);
        struct rte_udp_hdr *udp_r =
            (struct rte_udp_hdr *)((uint8_t *)ip_r + (ip_r->version_ihl & 0x0F) * 4);
        uint16_t src_port = rte_be_to_cpu_16(udp_r->src_port);

        if (src_port == 1812 || src_port == 1813) {
            /* RADIUS response - pass to lockless RADIUS handler */
            uint8_t *radius_data = (uint8_t *)(udp_r + 1);
            uint16_t radius_len = rte_be_to_cpu_16(udp_r->dgram_len) - sizeof(struct rte_udp_hdr);

            extern void radius_lockless_process_dpdk_response(uint8_t *data, uint16_t len);
            YLOG_INFO("RADIUS response intercepted from %u.%u.%u.%u:%d len=%d",
                      (pkt->meta.src_ip >> 24) & 0xFF, (pkt->meta.src_ip >> 16) & 0xFF,
                      (pkt->meta.src_ip >> 8) & 0xFF, pkt->meta.src_ip & 0xFF, src_port,
                      radius_len);
            radius_lockless_process_dpdk_response(radius_data, radius_len);
            return;
        }
    }

    /* Check if destined for us (check all interfaces) */
    bool for_us = false;

    /* Check if it matches any of our interface IPs */
    for (uint32_t i = 1; i <= interface_count(); i++) {
        struct interface *check_iface = interface_find_by_index(i);
        if (check_iface && check_iface->config.ipv4_addr.s_addr != 0 &&
            pkt->meta.dst_ip == ntohl(check_iface->config.ipv4_addr.s_addr)) {
            for_us = true;
            break;
        }
    }

    /* NAT DNAT processing for return traffic coming in on WAN (port 1) */
    if (nat_is_enabled() && iface->ifindex == 1) {
        /* Check if this is return traffic that needs DNAT */
        int dnat_result = nat_translate_dnat(pkt, iface);
        if (dnat_result == 0) {
            /* Packet was translated - forward directly to inside network */
            /* Don't use forward_ipv4_packet() as it might re-apply NAT */
#ifdef HAVE_DPDK
            struct rte_ipv4_hdr *ip =
                (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));
            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;

            uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);
            pkt->meta.dst_ip = dst_ip;

            /* Find the LAN interface (egress for return traffic) */
            /* Look for interface that has the destination IP in its subnet */
            struct interface *egress_iface = NULL;
            for (uint32_t i = 1; i <= interface_count(); i++) {
                struct interface *check_iface = interface_find_by_index(i);
                if (check_iface && check_iface->ifindex != 1 && check_iface->state == IF_STATE_UP) {
                    /* Check if destination is in this interface's subnet */
                    uint32_t if_ip = ntohl(check_iface->config.ipv4_addr.s_addr);
                    uint32_t if_mask = ntohl(check_iface->config.ipv4_mask.s_addr);
                    if ((dst_ip & if_mask) == (if_ip & if_mask)) {
                        egress_iface = check_iface;
                        break;
                    }
                }
            }

            /* Fallback: use interface 2 (LAN) if subnet check fails */
            if (!egress_iface) {
                egress_iface = interface_find_by_index(2);
            }

            if (!egress_iface) {
                YLOG_WARNING("DNAT: No egress interface found for return traffic to %u.%u.%u.%u",
                             (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF,
                             dst_ip & 0xFF);
                return;
            }

            /* Decrement TTL and update checksum */
            ip->time_to_live--;
            ip->hdr_checksum = 0;
            ip->hdr_checksum = rte_ipv4_cksum(ip);

            /* ARP lookup for destination (client) */
            uint8_t dst_mac[6];
            if (arp_lookup(dst_ip, dst_mac) != 0) {
                /* Send ARP request for client */
                uint32_t src_ip = ntohl(egress_iface->config.ipv4_addr.s_addr);
                arp_send_request(dst_ip, src_ip, egress_iface->mac_addr, egress_iface->ifindex);
                YLOG_DEBUG("DNAT: ARP request sent for client %u.%u.%u.%u", (dst_ip >> 24) & 0xFF,
                           (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
                /* Try lookup again */
                if (arp_lookup(dst_ip, dst_mac) != 0) {
                    /* Queue packet for ARP resolution */
                    YLOG_DEBUG("DNAT: ARP not available, queuing packet for %u.%u.%u.%u",
                               (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF,
                               dst_ip & 0xFF);
                    if (arp_queue_packet(dst_ip, pkt, egress_iface, iface) == 0) {
                        /* Packet queued successfully */
                        return;
                    } else {
                        /* Queue full - drop packet */
                        YLOG_DEBUG("DNAT: ARP queue full, dropping packet");
                        return;
                    }
                }
            }

            /* Update Ethernet header */
            memcpy(&eth->dst_addr, dst_mac, RTE_ETHER_ADDR_LEN);
            memcpy(&eth->src_addr, egress_iface->mac_addr, RTE_ETHER_ADDR_LEN);

            /* Set egress interface */
            pkt->meta.egress_ifindex = egress_iface->ifindex;

            /* Send directly to LAN interface */
            if (interface_send(egress_iface, pkt) == 0) {
                g_fwd_stats.packets_forwarded++;
                g_fwd_stats.bytes_forwarded += pkt->len;
                YLOG_DEBUG("DNAT: Return packet forwarded to %u.%u.%u.%u via %s",
                           (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF,
                           dst_ip & 0xFF, egress_iface->name);
            } else {
                YLOG_WARNING("DNAT: Failed to send return packet to %s", egress_iface->name);
            }
#endif
            return; /* Packet handled by DNAT - don't process further */
        }
        /* If dnat_result < 0, no session found - proceed normally */
    }

    if (for_us) {
        /* Packet is for us - process locally */
        if (pkt->meta.protocol == IPPROTO_ICMP) {
            /* Removed verbose logging for performance - caused 35% ICMP drop */
            process_icmp_echo(pkt, iface);
        } else if (pkt->meta.protocol == IPPROTO_UDP) {
            /* Check for RADIUS response (from port 1812) */
            struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
            struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
            struct rte_udp_hdr *udp =
                (struct rte_udp_hdr *)((uint8_t *)ip + (ip->version_ihl & 0x0F) * 4);
            uint16_t src_port = rte_be_to_cpu_16(udp->src_port);

            if (src_port == 1812 || src_port == 1813) {
                /* RADIUS response - pass to lockless RADIUS handler */
                uint8_t *radius_data = (uint8_t *)(udp + 1);
                uint16_t radius_len = rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct rte_udp_hdr);

                extern void radius_lockless_process_dpdk_response(uint8_t *data, uint16_t len);
                radius_lockless_process_dpdk_response(radius_data, radius_len);
                YLOG_INFO("RADIUS response intercepted from port %d, len=%d", src_port, radius_len);
                return;
            }
        }
    } else {
        /* Packet is not for us - forward it */
        /* Removed verbose ICMP logging for performance */
#ifdef HAVE_DPDK
        forward_ipv4_packet(pkt);
#else
        YLOG_DEBUG("Packet forwarding not supported without DPDK");
#endif
    }
}

/* Main packet processing function */
void packet_rx_process_packet(struct pkt_buf *pkt)
{
    /* TRACE LOG - CONFIRM PACKET ARRIVAL */
    struct rte_ether_hdr *eth_trace = (struct rte_ether_hdr *)pkt->data;
    uint16_t eth_type_trace = rte_be_to_cpu_16(eth_trace->ether_type);
    /* PERFORMANCE: Changed from YLOG_INFO to avoid latency */
    /* YLOG_DEBUG("RX ENTRY: iface=%u len=%u eth_type=0x%04x",
              pkt->meta.ingress_ifindex, pkt->len, eth_type_trace); */

    /* Extract metadata (parse headers) */
    if (pkt_extract_metadata(pkt) != 0) {
        YLOG_WARNING("Failed to extract packet metadata");
        return;
    }

    /* Handle PPPoE - check for VLAN tagged packets */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);

    /* Strip VLAN tag if present to get inner ethertype */
    if (eth_type == RTE_ETHER_TYPE_VLAN && pkt->len >= sizeof(struct rte_ether_hdr) + 4) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        eth_type = rte_be_to_cpu_16(vlan->eth_proto);
    }

    if (eth_type == 0x8863) { /* PPPoE DISC */
        /* YLOG_DEBUG("RX PPPoE DISC"); */
        struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        pppoe_process_discovery(pkt, iface);
        return;
    }

    if (eth_type == 0x8864) { /* PPPoE SESS */
        struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        pppoe_process_session(pkt, iface);
        return;
    }

    /* Early intercept for RADIUS responses before other processing */
    if (pkt->meta.l3_type == PKT_L3_IPV4 && pkt->meta.protocol == IPPROTO_UDP) {
        struct rte_ether_hdr *eth_chk = (struct rte_ether_hdr *)pkt->data;
        struct rte_ipv4_hdr *ip_chk = (struct rte_ipv4_hdr *)(eth_chk + 1);
        struct rte_udp_hdr *udp_chk =
            (struct rte_udp_hdr *)((uint8_t *)ip_chk + (ip_chk->version_ihl & 0x0F) * 4);
        uint16_t src_port = rte_be_to_cpu_16(udp_chk->src_port);

        if (src_port == 1812 || src_port == 1813) {
            uint8_t *radius_data = (uint8_t *)(udp_chk + 1);
            uint16_t radius_len = rte_be_to_cpu_16(udp_chk->dgram_len) - sizeof(struct rte_udp_hdr);

            extern void radius_lockless_process_dpdk_response(uint8_t *data, uint16_t len);
            YLOG_INFO("RADIUS RX: src=%u.%u.%u.%u:%d dst=%u.%u.%u.%u len=%d",
                      (pkt->meta.src_ip >> 24) & 0xFF, (pkt->meta.src_ip >> 16) & 0xFF,
                      (pkt->meta.src_ip >> 8) & 0xFF, pkt->meta.src_ip & 0xFF, src_port,
                      (pkt->meta.dst_ip >> 24) & 0xFF, (pkt->meta.dst_ip >> 16) & 0xFF,
                      (pkt->meta.dst_ip >> 8) & 0xFF, pkt->meta.dst_ip & 0xFF, radius_len);
            radius_lockless_process_dpdk_response(radius_data, radius_len);
            return;
        }
    }

    /* Dispatch based on L3 type */
    switch (pkt->meta.l3_type) {
    case PKT_L3_ARP:
        /* YLOG_DEBUG("RX L3 ARP matched"); */
        process_arp(pkt);
        break;
    case PKT_L3_IPV4:
        process_ipv4(pkt);
        break;
    case PKT_L3_IPV6:
        process_ipv6(pkt);
        break;
    default:
        /* YLOG_DEBUG("RX UNKNOWN L3 TYPE: %d (eth_type=0x%04x)", pkt->meta.l3_type, eth_type); */
        /* Debug: print first bytes */
        /* YLOG_HEX("Packet Dump", pkt->data, 32); */
    }
}

/* RX thread function */
/* Worker thread arguments */
struct rx_thread_args {
    int worker_id;
    int core_id;
    int queue_id;
};

static void *rx_thread_func(void *arg)
{
    struct rx_thread_args *args = (struct rx_thread_args *)arg;
    int worker_id = args->worker_id;
    int core_id = args->core_id;
    int queue_id = args->queue_id;

    /* Silence unused warnings if logging is disabled */
    (void)worker_id;
    (void)queue_id;

    /* Pin to specific core */
    if (cpu_scheduler_set_affinity(core_id) != 0) {
        YLOG_ERROR("Failed to pin RX thread %d to core %d", worker_id, core_id);
    } else {
        YLOG_INFO("RX thread %d pinned to core %d (polling queue %d)", worker_id, core_id,
                  queue_id);
    }

    /* Initialize flow cache for this core/thread */
    extern int flow_cache_init(unsigned int lcore_id);
    if (flow_cache_init(core_id) != 0) {
        YLOG_WARNING("Failed to initialize flow cache for RX thread %d (core %d)", worker_id,
                     core_id);
    } else {
        YLOG_DEBUG("Flow cache initialized for RX thread %d (core %d)", worker_id, core_id);
    }

    free(args);

    /* Lockless RADIUS - no per-worker init needed */

#ifdef HAVE_DPDK
    /* Initialize per-worker NAT port pool for LOCKLESS allocation */
    /* Use actual NAT pool IP from config (first active pool) */
    extern void nat_worker_port_pool_init(uint32_t worker_id, uint32_t nat_ip, uint16_t port_min,
                                          uint16_t port_max);
    extern struct nat_config g_nat_config;
    uint32_t nat_ip = 0;
    /* Get IP from first active NAT pool */
    for (int i = 0; i < g_nat_config.num_pools && nat_ip == 0; i++) {
        if (g_nat_config.pools[i].active) {
            nat_ip = g_nat_config.pools[i].start_ip;
        }
    }
    if (nat_ip == 0) {
        /* Fallback: get WAN interface IP */
        struct interface *wan = interface_find_by_name("Gi0/1");
        if (wan && wan->config.ipv4_addr.s_addr != 0) {
            nat_ip = ntohl(wan->config.ipv4_addr.s_addr);
        }
    }

    /* VPP-STYLE: Allocate NON-OVERLAPPING port blocks per worker
     * This allows DNAT to determine session owner from outside_port alone
     * Total usable ports: 65535 - 1024 = 64511
     * With 8 workers, each gets ~8000 ports
     */
    extern uint32_t g_num_workers;
    uint16_t total_ports = 65535 - 1024;
    uint16_t ports_per_worker = total_ports / (g_num_workers > 0 ? g_num_workers : 1);
    uint16_t port_min = 1024 + (worker_id * ports_per_worker);
    uint16_t port_max = port_min + ports_per_worker - 1;
    if (worker_id == (int)(g_num_workers - 1)) {
        port_max = 65535; /* Last worker gets remainder */
    }

    nat_worker_port_pool_init(worker_id, nat_ip, port_min, port_max);
    YLOG_INFO("[NAT] Worker %d: NAT port range %u-%u (IP=%u.%u.%u.%u)", worker_id, port_min,
              port_max, (nat_ip >> 24) & 0xFF, (nat_ip >> 16) & 0xFF, (nat_ip >> 8) & 0xFF,
              nat_ip & 0xFF);
#endif

    /* Main loop - DPDK DIRECT FAST PATH */
    printf("[FAST-PATH-DEBUG] Worker %d entering loop, queue=%d, HAVE_DPDK=%d\n", worker_id,
           queue_id, 1);
    fflush(stdout);

    while (g_rx_running) {
        int packets_processed = 0;

#ifdef HAVE_DPDK
        /* Log first iteration */
        static __thread int first_iter = 1;
        if (first_iter) {
            printf("[FAST-PATH-DEBUG] Worker %d INSIDE DPDK block!\n", worker_id);
            fflush(stdout);
            first_iter = 0;
        }
        /* ============================================================
         * DEBUG: Comprehensive logging to find where packets are lost
         * ============================================================ */
        {
#define FAST_BURST_SIZE 128 /* Increased for higher throughput */
            static __thread struct rte_mbuf *rx_pkts[FAST_BURST_SIZE];
            static __thread uint64_t total_rx = 0, total_tx = 0, total_drops = 0;
            static __thread uint64_t total_rx_bytes = 0, total_tx_bytes = 0;
            static __thread uint64_t last_rx = 0, last_tx = 0, last_rx_bytes = 0, last_tx_bytes = 0;
            static __thread uint64_t poll_count = 0, empty_polls = 0;
            static __thread uint64_t last_log = 0;
            static __thread uint64_t last_stats_time = 0;
            static __thread int logged_start = 0;

            /* Log once at start */
            if (!logged_start) {
                YLOG_INFO("[DPDK-DEBUG] Worker started: queue=%d worker=%d (polling both ports)",
                          queue_id, worker_id);
                logged_start = 1;
            }

            poll_count++;

            /* Poll lockless RADIUS responses - distribute across workers using modulo */
            /* Each worker polls at offset intervals to spread the load */
            if ((poll_count & 0x3F) ==
                (uint64_t)worker_id) { /* Each worker polls every 64 iterations, staggered */
                extern unsigned int radius_lockless_poll_responses(
                    struct radius_auth_response * *responses, unsigned int max);
                extern void radius_lockless_free_response(struct radius_auth_response * resp);
                extern void pppoe_handle_radius_response(struct radius_auth_response * resp);

                struct radius_auth_response *resps[8];
                unsigned int n = radius_lockless_poll_responses(resps, 8);
                for (unsigned int r = 0; r < n; r++) {
                    pppoe_handle_radius_response(resps[r]);
                    radius_lockless_free_response(resps[r]);
                }
            }

            /* VPP-STYLE: Process packets handed off from other workers FIRST
             * This is critical - without this, handoff rings fill up and packets are lost!
             */
            {
                extern uint16_t nat_worker_handoff_dequeue(
                    uint32_t worker_id, struct rte_mbuf **pkts, uint16_t max_pkts);
                extern uint16_t nat_process_burst_dpdk(struct rte_mbuf * *pkts, uint16_t nb_rx,
                                                       uint32_t worker_id);
                struct rte_mbuf *handoff_pkts[32];
                uint16_t nb_handoff = nat_worker_handoff_dequeue(worker_id, handoff_pkts, 32);
                if (nb_handoff > 0) {
                    /* Process through NAT (we are now the correct owner) */
                    uint16_t nb_tx = nat_process_burst_dpdk(handoff_pkts, nb_handoff, worker_id);

                    /* TX the processed packets */
                    uint16_t num_tx_ports = rte_eth_dev_count_avail();
                    for (uint16_t tx_port = 0; tx_port < num_tx_ports; tx_port++) {
                        struct rte_mbuf *port_pkts[32];
                        uint16_t port_count = 0;
                        for (uint16_t j = 0; j < nb_tx; j++) {
                            if (handoff_pkts[j]->port == tx_port) {
                                port_pkts[port_count++] = handoff_pkts[j];
                            }
                        }
                        if (port_count > 0) {
                            uint16_t sent =
                                rte_eth_tx_burst(tx_port, queue_id, port_pkts, port_count);
                            /* Free unsent packets */
                            for (uint16_t k = sent; k < port_count; k++) {
                                rte_pktmbuf_free(port_pkts[k]);
                            }
                        }
                    }
                }
            }

            /* Poll ALL available DPDK ports (dynamic from env) */
            uint16_t nb_rx = 0;
            uint16_t num_ports = rte_eth_dev_count_avail();
            for (uint16_t port_id = 0; port_id < num_ports; port_id++) {
                uint16_t rx_count =
                    rte_eth_rx_burst(port_id, queue_id, rx_pkts + nb_rx, FAST_BURST_SIZE - nb_rx);
                nb_rx += rx_count;
                if (nb_rx >= FAST_BURST_SIZE)
                    break;
            }

            if (nb_rx > 0) {
                total_rx += nb_rx;
                /* Count RX bytes */
                for (uint16_t b = 0; b < nb_rx; b++) {
                    total_rx_bytes += rx_pkts[b]->pkt_len;
                }

                /* VPP-STYLE WORKER HANDOFF:
                 * 1. Hash each packet to determine owning worker
                 * 2. If packet belongs to this worker, process locally
                 * 3. If packet belongs to another worker, enqueue to their ring
                 * 4. Also dequeue and process packets from our own ring
                 */
                extern uint16_t nat_process_burst_dpdk(struct rte_mbuf * *pkts, uint16_t nb_rx,
                                                       uint32_t worker_id);

                /* Separate packets by destination worker */
                struct rte_mbuf *local_pkts[FAST_BURST_SIZE];
                uint16_t local_count = 0;

                for (uint16_t i = 0; i < nb_rx; i++) {
                    struct rte_mbuf *pkt = rx_pkts[i];
                    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
                    uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);

                    /* Check for VLAN tag and get inner ethertype */
                    uint16_t vlan_id = 0;
                    if (eth_type == RTE_ETHER_TYPE_VLAN) {
                        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
                        vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xFFF;
                        eth_type = rte_be_to_cpu_16(vlan->eth_proto);
                    }

                    /* PPPoE Discovery (PADI/PADO/PADR/PADS/PADT) - route to PPPoE handler */
                    if (eth_type == 0x8863) { /* ETH_P_PPPOE_DISC */
                        struct pkt_buf *pbuf = pkt_alloc();
                        if (pbuf) {
                            pbuf->mbuf = pkt;
                            pbuf->data = rte_pktmbuf_mtod(pkt, uint8_t *);
                            pbuf->len = rte_pktmbuf_pkt_len(pkt);
                            pbuf->meta.ingress_ifindex = (pkt->port == 0) ? 1 : 2;
                            pbuf->meta.vlan_id = vlan_id;
                            struct interface *iface =
                                interface_find_by_index(pbuf->meta.ingress_ifindex);
                            YLOG_INFO("PPPoE: Discovery on port %u vlan %u (iface %s)", pkt->port,
                                      vlan_id, iface ? iface->name : "?");
                            pppoe_process_discovery(pbuf, iface);
                            pkt_free(pbuf);
                        } else {
                            rte_pktmbuf_free(pkt);
                        }
                        continue; /* Skip NAT for this packet */
                    }

                    /* PPPoE Session (LCP/IPCP/Data) - route to PPPoE session handler */
                    if (eth_type == 0x8864) { /* ETH_P_PPPOE_SESS */
                        struct pkt_buf *pbuf = pkt_alloc();
                        if (pbuf) {
                            pbuf->mbuf = pkt;
                            pbuf->data = rte_pktmbuf_mtod(pkt, uint8_t *);
                            pbuf->len = rte_pktmbuf_pkt_len(pkt);
                            pbuf->meta.ingress_ifindex = (pkt->port == 0) ? 1 : 2;
                            pbuf->meta.vlan_id = vlan_id;
                            struct interface *iface =
                                interface_find_by_index(pbuf->meta.ingress_ifindex);
                            pppoe_process_session(pbuf, iface);
                            pkt_free(pbuf);
                        } else {
                            rte_pktmbuf_free(pkt);
                        }
                        continue; /* Skip NAT for this packet */
                    }

                    /* Handle ARP */
                    if (eth_type == RTE_ETHER_TYPE_ARP) {
                        struct pkt_buf *pbuf = pkt_alloc();
                        if (pbuf) {
                            pbuf->mbuf = pkt;
                            pbuf->data = rte_pktmbuf_mtod(pkt, uint8_t *);
                            pbuf->len = rte_pktmbuf_pkt_len(pkt);
                            /* Map port 0->1 (WAN), 1->2 (LAN) approximately? Or use env/config? */
                            /* Existing code assumes port 0=WAN(1), port 1=LAN(2) */
                            pbuf->meta.ingress_ifindex = (pkt->port == 0) ? 1 : 2;
                            pbuf->meta.vlan_id = vlan_id;

                            /* Call generic handler (which has trace logs) */
                            packet_rx_process_packet(pbuf);

                            /* mbuf ownership is tricky.
                               If packet_rx_process_packet -> process_arp -> consumes data, it
                               doesn't free mbuf. We need to ensure mbuf is freed if not forwarded.
                               process_arp doesn't forward mbuf, it replies with NEW packet.
                               So we should free mbuf?
                               pkt_free(pbuf) doesn't free mbuf usually.
                            */
                            rte_pktmbuf_free(
                                pkt);       /* Free original ARP request mbuf after processing */
                            pkt_free(pbuf); /* Free wrapper */
                        } else {
                            rte_pktmbuf_free(pkt);
                        }
                        continue;
                    }

                    /* IPv4 - process locally (each worker owns its sessions) */
                    if (eth_type == RTE_ETHER_TYPE_IPV4) {
                        /* NO HANDOFF: Each worker processes packets it receives
                         * and creates sessions in its own table. This is the
                         * original lockless approach that achieved 1.65M PPS.
                         */
                        local_pkts[local_count++] = pkt;
                    } else {
                        /* Non-IPv4/Non-PPPoE - drop */
                        rte_pktmbuf_free(pkt);
                    }
                }

                /* Process local packets through NAT */
                uint16_t nb_tx = 0;
                if (local_count > 0) {
                    nb_tx = nat_process_burst_dpdk(local_pkts, local_count, worker_id);
                }

                /* NAT fastpath now handles MAC rewriting and sets pkt->port for egress */
                /* TX burst - route based on pkt->port set by NAT */
                uint16_t sent = 0;
                uint16_t num_tx_ports = rte_eth_dev_count_avail();

                if (num_tx_ports == 1) {
                    /* Single port mode */
                    sent = rte_eth_tx_burst(0, queue_id, local_pkts, nb_tx);
                } else {
                    /* Multi-port mode: use pkt->port set by NAT for egress routing */
                    for (uint16_t tx_port = 0; tx_port < num_tx_ports; tx_port++) {
                        struct rte_mbuf *port_pkts[FAST_BURST_SIZE];
                        uint16_t port_count = 0;
                        for (uint16_t j = 0; j < nb_tx; j++) {
                            /* NAT sets pkt->port to correct egress port */
                            if (local_pkts[j]->port == tx_port) {
                                port_pkts[port_count++] = local_pkts[j];
                            }
                        }
                        if (port_count > 0) {
                            uint16_t tx_sent =
                                rte_eth_tx_burst(tx_port, queue_id, port_pkts, port_count);
                            sent += tx_sent;
                        }
                    }
                }
                total_tx += sent;
                /* Count TX bytes */
                for (uint16_t b = 0; b < sent; b++) {
                    total_tx_bytes += local_pkts[b]->pkt_len;
                }

                if (sent < nb_tx) {
                    total_drops += (nb_tx - sent);
                    for (uint16_t i = sent; i < nb_tx; i++) {
                        rte_pktmbuf_free(local_pkts[i]);
                    }
                }
                packets_processed = nb_rx;
            }

            /* Print stats every 2 seconds */
            uint64_t now = rte_rdtsc();
            uint64_t hz = rte_get_tsc_hz();
            if (now - last_stats_time > hz * 2) {
                uint64_t delta_rx = total_rx - last_rx;
                uint64_t delta_tx = total_tx - last_tx;
                uint64_t delta_rx_bytes = total_rx_bytes - last_rx_bytes;
                uint64_t delta_tx_bytes = total_tx_bytes - last_tx_bytes;
                double rx_pps = delta_rx / 2.0;
                double tx_pps = delta_tx / 2.0;
                double rx_gbps = (delta_rx_bytes * 8.0) / (2.0 * 1000000000.0);
                double tx_gbps = (delta_tx_bytes * 8.0) / (2.0 * 1000000000.0);

                if (delta_rx > 0 || delta_tx > 0) {
                    YLOG_INFO("[STATS] W%d: RX %.0f pps (%.2f Gbps) | TX %.0f pps (%.2f Gbps) | "
                              "Drops %lu",
                              worker_id, rx_pps, rx_gbps, tx_pps, tx_gbps, total_drops);
                }
                last_rx = total_rx;
                last_tx = total_tx;
                last_rx_bytes = total_rx_bytes;
                last_tx_bytes = total_tx_bytes;
                last_stats_time = now;
            }

            /* VPP-STYLE: Also process packets from our handoff ring */
            if (g_worker_rings[worker_id]) {
                struct rte_mbuf *ring_pkts[FAST_BURST_SIZE];
                unsigned int ring_count = rte_ring_dequeue_burst(
                    g_worker_rings[worker_id], (void **)ring_pkts, FAST_BURST_SIZE, NULL);
                if (ring_count > 0) {
                    static __thread uint64_t ring_debug = 0;
                    if (ring_debug++ < 10) {
                        YLOG_INFO("[RING-RX] worker=%d dequeued %u pkts from ring", worker_id,
                                  ring_count);
                    }
                    extern uint16_t nat_process_burst_dpdk(struct rte_mbuf * *pkts, uint16_t nb_rx,
                                                           uint32_t worker_id);
                    uint16_t nb_tx = nat_process_burst_dpdk(ring_pkts, ring_count, worker_id);
                    if (ring_debug < 15) {
                        YLOG_INFO("[RING-TX] worker=%d nb_tx=%u from NAT", worker_id, nb_tx);
                    }

                    /* NAT fastpath handles MAC rewriting - no swap needed */

                    /* TX burst - use pkt->port set by NAT for egress routing */
                    uint16_t sent = 0;
                    uint16_t num_ring_tx_ports = rte_eth_dev_count_avail();

                    if (num_ring_tx_ports == 1) {
                        sent = rte_eth_tx_burst(0, queue_id, ring_pkts, nb_tx);
                    } else {
                        for (uint16_t tx_port = 0; tx_port < num_ring_tx_ports; tx_port++) {
                            struct rte_mbuf *port_pkts[FAST_BURST_SIZE];
                            uint16_t port_count = 0;
                            for (uint16_t j = 0; j < nb_tx; j++) {
                                if (ring_pkts[j]->port == tx_port) {
                                    port_pkts[port_count++] = ring_pkts[j];
                                }
                            }
                            if (port_count > 0) {
                                sent += rte_eth_tx_burst(tx_port, queue_id, port_pkts, port_count);
                            }
                        }
                    }
                    total_tx += sent;

                    if (sent < nb_tx) {
                        total_drops += (nb_tx - sent);
                        for (uint16_t i = sent; i < nb_tx; i++) {
                            rte_pktmbuf_free(ring_pkts[i]);
                        }
                    }
                }
            }

            if (nb_rx == 0) {
                empty_polls++;
            }

            /* Log stats every 5 seconds - write to file for guaranteed visibility */
            uint64_t now_log = rte_rdtsc();
            if (now_log - last_log > rte_get_tsc_hz() * 5) {
                struct rte_eth_stats eth_stats;
                rte_eth_stats_get(0, &eth_stats); /* Stats from port 0 */

                FILE *f = fopen("/tmp/dpdk_debug.log", "a");
                if (f) {
                    fprintf(f, "[DPDK] Q%d polls=%lu empty=%lu rx=%lu tx=%lu drops=%lu\n", queue_id,
                            poll_count, empty_polls, total_rx, total_tx, total_drops);
                    fprintf(f,
                            "[NIC] ipkts=%lu opkts=%lu ierr=%lu oerr=%lu missed=%lu nombuf=%lu\n",
                            eth_stats.ipackets, eth_stats.opackets, eth_stats.ierrors,
                            eth_stats.oerrors, eth_stats.imissed, eth_stats.rx_nombuf);
                    fclose(f);
                }
                last_log = now;
            }

            /* HQoS Scheduler - Must run on Worker 0 to avoid race on Queue 0 */
            if (worker_id == 0) {
                hqos_run();
            }

            continue;
        }
#endif

        /* Flow Cache Expiration Check */
        extern void flow_cache_expire(uint64_t now_ms);
        static uint64_t last_tsc = 0;
        uint64_t now_tsc = rte_get_timer_cycles();
        if (last_tsc == 0)
            last_tsc = now_tsc;

        /* 100ms interval approx */
        if (now_tsc - last_tsc > (rte_get_timer_hz() / 10)) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            uint64_t now_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
            flow_cache_expire(now_ms);
            last_tsc = now_tsc;
        }

        /* Poll all interfaces - simplified for PoC */

        /*
         * Packet RX/TX implementation
         */
        /* In a real implementation, we would only poll DPDK ports assigned to this queue */
        /* For now, we iterate all interfaces. If it's a DPDK interface, we should ideally
           pass the queue_id. But our interface API doesn't support it yet.
           However, since we configured the hardware with N queues, and we are running N threads,
           we need to ensure each thread polls a different queue.

           CRITICAL: The current interface_recv() implementation calls physical_recv() which
           uses queue 0 hardcoded or a shared burst buffer.
           We need to modify physical_recv to use the queue_id.

           Since we can't easily change the API right now, we will use a thread-local variable
           to pass the queue_id to physical_recv.
        */

        extern __thread int g_thread_queue_id;
        extern __thread int g_thread_worker_id;
        g_thread_queue_id = queue_id;
        g_thread_worker_id = worker_id;

        /* Poll lockless RADIUS responses ONCE per loop iteration (worker 0 only) */
        if (worker_id == 0) {
            extern unsigned int radius_lockless_poll_responses(
                struct radius_auth_response * *responses, unsigned int max);
            extern void radius_lockless_free_response(struct radius_auth_response * resp);
            extern void pppoe_handle_radius_response(struct radius_auth_response * resp);

            struct radius_auth_response *resps[32];
            unsigned int n = radius_lockless_poll_responses(resps, 32);
            for (unsigned int r = 0; r < n; r++) {
                YLOG_INFO("RADIUS: Dispatching response to pppoe_handle session=%u",
                          resps[r]->session_id);
                pppoe_handle_radius_response(resps[r]);
                radius_lockless_free_response(resps[r]);
            }
        }

        /* Poll interfaces 1..32 (max) */
        static int iface_debug_done = 0;
        for (int i = 1; i <= 32; i++) {
            struct interface *iface = interface_find_by_index(i);
            if (!iface || iface->state != IF_STATE_UP)
                continue;

            /* Debug: Log which interfaces we're polling (once) */
            if (!iface_debug_done && worker_id == 0) {
                YLOG_INFO("RX polling interface %d: %s (state=%d)", i, iface->name, iface->state);
                iface_debug_done = 1;
            }

            struct pkt_buf *pkt = NULL;

            /* Process burst of packets from this interface */
            int quota = 64; /* Increased burst for better throughput */
            while (quota > 0) {
                int ret = interface_recv(iface, &pkt);

                if (ret > 0 && pkt) {
                    pkt->meta.ingress_ifindex = iface->ifindex;

                    /* Flow Cache Update - Note: For DPDK packets, this is done in physical_recv()
                     */
                    /* For kernel packets (non-DPDK), we need to track them separately if needed */
                    /* Currently, DPDK packets are tracked in physical_recv() before mbuf is freed
                     */

                    packet_rx_process_packet(pkt);
                    pkt_free(pkt);
                    packets_processed++;
                    quota--;
                } else {
                    break; /* No more packets on this interface */
                }
            }
        }

        /* CARRIER-GRADE: Flush TX buffer after processing burst */
#ifdef HAVE_DPDK
        tx_flush();
#endif

        if (packets_processed == 0) {
            /* Busy wait - DPDK poll mode */
        }

        /* HQoS Scheduler Logic */

        /* HQoS Scheduler - Must run on Worker 0 to avoid race on Queue 0 */
        if (worker_id == 0) {
            hqos_run();
        }
    }

    return NULL;
}

/* Thread-local queue ID definition */
/* Thread-local queue ID definition moved to cpu_scheduler.c/h */

int packet_rx_start(void)
{
    YLOG_INFO("packet_rx_start() called");

    if (g_rx_running) {
        YLOG_INFO("packet_rx_start: already running");
        return 0;
    }

    g_rx_running = true;

    /* Get worker lcores from .env config (Bison-style) */
    extern struct env_config g_env_config;
    int num_cores = g_env_config.dpdk.num_workers;
    int cores[32];

    if (num_cores > 0 && num_cores <= 32) {
        for (int i = 0; i < num_cores; i++) {
            cores[i] = g_env_config.dpdk.worker_lcores[i];
        }
        YLOG_INFO("[ENV] packet_rx_start: %d worker lcores from .env", num_cores);
    } else {
        /* Fallback to core 1 if not specified */
        cores[0] = 1;
        num_cores = 1;
        YLOG_INFO("packet_rx_start: using default core 1");
    }

    YLOG_INFO("Starting %d RX threads", num_cores);

    /* VPP-STYLE: Initialize worker handoff rings for multi-worker NAT
     * Each worker owns its session table - handoff ensures flow affinity
     */
#ifdef HAVE_DPDK
    if (init_worker_handoff_rings(num_cores) != 0) {
        YLOG_ERROR("Failed to initialize worker handoff rings");
        return -1;
    }
#endif
    nat_set_num_workers(num_cores);
    YLOG_INFO("NAT: VPP-style worker handoff enabled (%d workers)", num_cores);

    for (int i = 0; i < num_cores; i++) {
        struct rx_thread_args *args = malloc(sizeof(*args));
        if (!args)
            return -1;

        args->worker_id = i;
        args->core_id = cores[i];
        args->queue_id = i; /* Queue ID matches worker index */

        pthread_t tid;
        if (pthread_create(&tid, NULL, rx_thread_func, args) != 0) {
            YLOG_ERROR("Failed to create RX thread %d", i);
            free(args);
            return -1;
        }
        pthread_detach(tid);
    }

    return 0;
}

void packet_rx_stop(void)
{
    if (!g_rx_running) {
        return;
    }

    g_rx_running = false;
    /* We detached threads, so we can't join them easily.
       They will exit when they see g_rx_running == false. */
    sleep(1); /* Give them time to stop */
}

/**
 * @brief Dump forwarding statistics
 */
void packet_rx_dump_stats(void)
{
    printf("\nForwarding Statistics:\n");
    printf("========================================\n");
    printf("Packets Forwarded:           %lu\n", g_fwd_stats.packets_forwarded);
    printf("Bytes Forwarded:             %lu\n", g_fwd_stats.bytes_forwarded);
    printf("Packets Dropped (No Route):  %lu\n", g_fwd_stats.packets_dropped_no_route);
    printf("Packets Dropped (TTL):       %lu\n", g_fwd_stats.packets_dropped_ttl_exceeded);
    printf("Packets Dropped (ARP Fail):  %lu\n", g_fwd_stats.packets_dropped_arp_failed);
    printf("ICMP Time Exceeded Sent:     %lu\n", g_fwd_stats.icmp_time_exceeded_sent);
    printf("\n");
    printf("IPv6 Packets Forwarded:      %lu\n", g_fwd_stats.ipv6_packets_forwarded);
    printf("IPv6 Dropped (No Route):     %lu\n", g_fwd_stats.ipv6_packets_dropped_no_route);
    printf("========================================\n");
}
