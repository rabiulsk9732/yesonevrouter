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
#include "fragmentation.h"
#include "interface.h"
#include "log.h"
#include "nat.h"
#include "packet.h"
#include "pppoe.h"
#include "reassembly.h"
#include "routing_table.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

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

#include "yesrouter_config.h"

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
} g_fwd_stats = {0};

/* Process ARP packet */
static void process_arp(struct pkt_buf *pkt)
{
    /* Validate ARP header - l3_offset points to ARP header after Ethernet */
    if (pkt->len < pkt->meta.l3_offset + sizeof(struct arp_hdr)) {
        YLOG_WARNING("Truncated ARP packet");
        return;
    }

    /* ARP packet processing - removed verbose logging for performance */

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
#endif /* HAVE_DPDK */

/* Process IPv4 packet */
static void process_ipv4(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return;
    }

    /* Try reassembly first */
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
    struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
    if (!iface) {
        return;
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
    /* Debug logging disabled for production */

    /* Extract metadata (parse headers) */
    if (pkt_extract_metadata(pkt) != 0) {
        YLOG_WARNING("Failed to extract packet metadata");
        return;
    }

    /* Handle PPPoE */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    uint16_t eth_type = rte_be_to_cpu_16(eth->ether_type);

    if (eth_type == ETH_P_PPPOE_DISC) {
        struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        pppoe_process_discovery(pkt, iface);
        return;
    }

    if (eth_type == ETH_P_PPPOE_SESS) {
        struct interface *iface = interface_find_by_index(pkt->meta.ingress_ifindex);
        pppoe_process_session(pkt, iface);
        return;
    }

    /* Dispatch based on L3 type */
    switch (pkt->meta.l3_type) {
    case PKT_L3_ARP:
        process_arp(pkt);
        break;
    case PKT_L3_IPV4:
        process_ipv4(pkt);
        break;
    default:
        YLOG_DEBUG("Unknown L3 packet type: %d", pkt->meta.l3_type);
        break;
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

    free(args);

    /* Main loop */
    while (g_rx_running) {
        int packets_processed = 0;

        /* Debug logging disabled for production */

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

        /* Poll interfaces 1..32 (max) */
        for (int i = 1; i <= 32; i++) {
            struct interface *iface = interface_find_by_index(i);
            if (!iface || iface->state != IF_STATE_UP)
                continue;

            struct pkt_buf *pkt = NULL;
            /* This will eventually call physical_recv which reads g_thread_queue_id */

            /* Process burst of packets from this interface */
            int quota = 32;
            while (quota > 0) {
                int ret = interface_recv(iface, &pkt);

                if (ret > 0 && pkt) {
                    pkt->meta.ingress_ifindex = iface->ifindex;

                    /* Flow Cache Update */
                    extern void flow_cache_update(struct rte_mbuf * m, int direction);
                    if (pkt->mbuf) {
                        /* 0 = Ingress for now, simplified */
                        flow_cache_update(pkt->mbuf, 0);
                    }

                    packet_rx_process_packet(pkt);
                    pkt_free(pkt);
                    packets_processed++;
                    quota--;
                } else {
                    break; /* No more packets on this interface */
                }
            }
        }

        if (packets_processed == 0) {
            /* Busy wait or small sleep? DPDK usually busy waits. */
            /* usleep(1); */
        }
    }

    return NULL;
}

/* Thread-local queue ID definition */
/* Thread-local queue ID definition moved to cpu_scheduler.c/h */

int packet_rx_start(void)
{
    if (g_rx_running) {
        return 0;
    }

    g_rx_running = true;

    /* Parse corelist-workers */
    extern struct yesrouter_hw_config g_yesrouter_hw_config;
    char *corelist = g_yesrouter_hw_config.cpu_config.corelist_workers;

    int cores[32];
    int num_cores = 0;

    if (strlen(corelist) > 0) {
        /* Parse range or list */
        char *dash = strchr(corelist, '-');
        if (dash) {
            int start = atoi(corelist);
            int end = atoi(dash + 1);
            for (int i = start; i <= end && num_cores < 32; i++) {
                cores[num_cores++] = i;
            }
        } else {
            /* Assume single number for now */
            cores[num_cores++] = atoi(corelist);
        }
    } else {
        /* Default to core 1 if not specified */
        cores[num_cores++] = 1;
    }

    YLOG_INFO("Starting %d RX threads", num_cores);

    /* Update NAT worker count to match RX threads */
    /* This enables per-worker session tables for lockless operation */
    if (num_cores > 0 && num_cores <= 16) {
        nat_set_num_workers(num_cores);
        YLOG_INFO("NAT: Configured for %d workers (per-worker tables enabled)", num_cores);
    }

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
