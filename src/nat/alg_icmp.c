/**
 * @file alg_icmp.c
 * @brief ICMP Application Level Gateway (DPDK Native)
 *
 * Handles ICMP error message translation for NAT
 * Translates embedded IP headers in ICMP error messages
 */

#include "nat.h"
#include "alg.h"
#include "packet.h"
#include "log.h"
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>
#include <stdbool.h>

/**
 * Process ICMP error message for NAT ALG
 *
 * ICMP error messages (Destination Unreachable, Time Exceeded, etc.)
 * contain the original IP header + 8 bytes of payload that caused the error.
 * We need to translate the embedded IP header to match the NAT translation.
 */
int alg_icmp_process_error(struct pkt_buf *pkt, bool outbound)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ipv4_hdr *outer_ip;
    struct rte_ipv4_hdr *inner_ip;
    struct rte_icmp_hdr *icmp;

    if (!m) return -1;

    outer_ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    if (outer_ip->next_proto_id != IPPROTO_ICMP) {
        return -1;
    }

    icmp = (struct rte_icmp_hdr *)((uint8_t *)outer_ip + rte_ipv4_hdr_len(outer_ip));

    /* Only process error messages */
    /* DPDK defines RTE_IP_ICMP_ECHO_REPLY (0) and RTE_IP_ICMP_ECHO_REQUEST (8) */
    /* We need to check for error types: 3, 4, 11, 12 */
    if (icmp->icmp_type != 3 &&  /* Destination Unreachable */
        icmp->icmp_type != 4 &&  /* Source Quench */
        icmp->icmp_type != 11 && /* Time Exceeded */
        icmp->icmp_type != 12) { /* Parameter Problem */
        return 0;  /* Not an error message - no ALG needed */
    }

    /* Get pointer to embedded IP header (in ICMP data) */
    /* ICMP header is 8 bytes */
    inner_ip = (struct rte_ipv4_hdr *)(icmp + 1);

    /* Verify it's a valid IP header */
    if ((inner_ip->version_ihl >> 4) != 4) {
        return -1;
    }

    /* Translate embedded IP header based on direction */
    if (outbound) {
        /* Outbound: inside -> outside */
        uint32_t inside_ip = rte_be_to_cpu_32(inner_ip->src_addr);
        uint16_t inside_port = 0;

        if (inner_ip->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
            inside_port = rte_be_to_cpu_16(tcp->src_port);
        } else if (inner_ip->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
            inside_port = rte_be_to_cpu_16(udp->src_port);
        }

        struct nat_session *session = nat_session_lookup_inside(inside_ip, inside_port, inner_ip->next_proto_id);
        if (!session) {
            YLOG_DEBUG("No NAT session for embedded IP %u.%u.%u.%u:%u",
                       (inside_ip >> 24) & 0xFF, (inside_ip >> 16) & 0xFF,
                       (inside_ip >> 8) & 0xFF, inside_ip & 0xFF, inside_port);
            return -1;
        }

        inner_ip->src_addr = rte_cpu_to_be_32(session->outside_ip);

        if (inside_port != 0) {
            if (inner_ip->next_proto_id == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
                tcp->src_port = rte_cpu_to_be_16(session->outside_port);
            } else if (inner_ip->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
                udp->src_port = rte_cpu_to_be_16(session->outside_port);
            }
        }
    } else {
        /* Inbound: outside -> inside */
        uint32_t outside_ip = rte_be_to_cpu_32(inner_ip->dst_addr);
        uint16_t outside_port = 0;

        if (inner_ip->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
            outside_port = rte_be_to_cpu_16(tcp->dst_port);
        } else if (inner_ip->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
            outside_port = rte_be_to_cpu_16(udp->dst_port);
        }

        struct nat_session *session = nat_session_lookup_outside(outside_ip, outside_port, inner_ip->next_proto_id);
        if (!session) {
            return -1;
        }

        inner_ip->dst_addr = rte_cpu_to_be_32(session->inside_ip);

        if (outside_port != 0) {
            if (inner_ip->next_proto_id == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
                tcp->dst_port = rte_cpu_to_be_16(session->inside_port);
            } else if (inner_ip->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)inner_ip + rte_ipv4_hdr_len(inner_ip));
                udp->dst_port = rte_cpu_to_be_16(session->inside_port);
            }
        }
    }

    /* Recalculate inner IP checksum */
    inner_ip->hdr_checksum = 0;
    inner_ip->hdr_checksum = rte_ipv4_cksum(inner_ip);

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ~rte_raw_cksum(icmp, rte_be_to_cpu_16(outer_ip->total_length) - rte_ipv4_hdr_len(outer_ip));

    YLOG_DEBUG("ICMP ALG: Processed %s ICMP error message",
               outbound ? "outbound" : "inbound");

    return 0;
}

/**
 * Check if ICMP ALG is needed for this packet
 */
bool alg_icmp_is_needed(struct pkt_buf *pkt)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ipv4_hdr *outer_ip;
    struct rte_icmp_hdr *icmp;

    if (!pkt || !m) return false;

    /* Parse outer IP header */
    outer_ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

    if (outer_ip->next_proto_id != IPPROTO_ICMP) {
        return false;
    }

    icmp = (struct rte_icmp_hdr *)((uint8_t *)outer_ip + rte_ipv4_hdr_len(outer_ip));

    /* Only error messages need ALG processing */
    /* Check for Destination Unreachable (3), Source Quench (4), Time Exceeded (11), Parameter Problem (12) */
    return (icmp->icmp_type == 3 ||
            icmp->icmp_type == 4 ||
            icmp->icmp_type == 11 ||
            icmp->icmp_type == 12);
}
