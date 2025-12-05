/**
 * @file nat_hairpin.c
 * @brief NAT Hairpinning (DPDK Native)
 */

#include "nat.h"
#include "packet.h"
#include "log.h"
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

/* External NAT config */
extern struct nat_config g_nat_config;

/**
 * Detect if packet requires hairpinning
 */
bool nat_hairpin_detect(struct pkt_buf *pkt, uint32_t *inside_src, uint32_t *inside_dst)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ipv4_hdr *ip;
    uint32_t src_ip, dst_ip;

    if (!m || !g_nat_config.hairpinning_enabled) {
        return false;
    }

    ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    src_ip = rte_be_to_cpu_32(ip->src_addr);
    dst_ip = rte_be_to_cpu_32(ip->dst_addr);

    /* Check if destination is a public IP in our NAT pools */
    bool dst_is_nat_ip = false;
    for (int i = 0; i < g_nat_config.num_pools; i++) {
        struct nat_pool *pool = &g_nat_config.pools[i];
        if (pool->active && dst_ip >= pool->start_ip && dst_ip <= pool->end_ip) {
            dst_is_nat_ip = true;
            break;
        }
    }

    if (!dst_is_nat_ip) {
        return false;
    }

    /* Check if there's a NAT session for this destination */
    uint16_t dst_port;
    switch (ip->next_proto_id) {
    case IPPROTO_TCP: {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        dst_port = rte_be_to_cpu_16(tcp->dst_port);
        break;
    }
    case IPPROTO_UDP: {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((uint8_t *)ip + rte_ipv4_hdr_len(ip));
        dst_port = rte_be_to_cpu_16(udp->dst_port);
        break;
    }
    default:
        return false;
    }

    /* Lookup existing NAT session by outside tuple */
    struct nat_session *session = nat_session_lookup_outside(dst_ip, dst_port, ip->next_proto_id);
    if (!session) {
        return false;
    }

    /* Hairpinning detected */
    if (inside_src) *inside_src = src_ip;
    if (inside_dst) *inside_dst = session->inside_ip;

    return true;
}

/**
 * Process hairpin packet
 * Performs double NAT: SNAT (src → public) + DNAT (dst → private)
 */
int nat_hairpin_process(struct pkt_buf *pkt)
{
    if (!pkt || !g_nat_config.hairpinning_enabled) {
        return -1;
    }

    /* First, perform DNAT (outside → inside for destination) */
    if (nat_translate_dnat(pkt, NULL) != 0) {
        return -1;
    }

    /* Then, perform SNAT (inside → outside for source) */
    if (nat_translate_snat(pkt, NULL) != 0) {
        return -1;
    }

    return 0;
}
