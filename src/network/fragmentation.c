/**
 * @file fragmentation.c
 * @brief IP Fragmentation Implementation (RFC 791)
 */

#include "fragmentation.h"
#include "packet.h"
#include "interface.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#endif

/* Global statistics */
static struct fragmentation_stats g_frag_stats = {0};

/* Fragment ID counter (should be per source IP in production) */
static uint16_t g_fragment_id = 1;

/**
 * @brief Initialize fragmentation subsystem
 */
int ip_fragmentation_init(void)
{
    memset(&g_frag_stats, 0, sizeof(g_frag_stats));
    g_fragment_id = 1;
    printf("IP Fragmentation subsystem initialized\n");
    return 0;
}

/**
 * @brief Check if packet needs fragmentation
 */
bool ip_needs_fragmentation(struct pkt_buf *pkt, uint16_t mtu)
{
    if (!pkt || pkt->len <= mtu) {
        return false;
    }
    return true;
}

#ifdef HAVE_DPDK
/**
 * @brief Create a fragment from original packet
 */
static struct pkt_buf *create_fragment(struct rte_ipv4_hdr *orig_ip,
                                      struct rte_ether_hdr *orig_eth,
                                      struct rte_mbuf *src_mbuf,
                                      uint16_t src_offset,
                                      uint16_t data_len,
                                      uint16_t frag_offset_val,
                                      bool more_fragments,
                                      struct interface *egress_iface)
{
    struct pkt_buf *fragment = pkt_alloc();
    if (!fragment) {
        YLOG_ERROR("Failed to allocate fragment packet");
        return NULL;
    }

    (void)egress_iface;  /* Reserved for future use */
    uint8_t ip_hdr_len = (orig_ip->version_ihl & 0x0F) * 4;

    /* Build Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)fragment->data;
    memcpy(eth, orig_eth, sizeof(struct rte_ether_hdr));

    /* Build IP header */
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(fragment->data + sizeof(struct rte_ether_hdr));
    memcpy(ip, orig_ip, ip_hdr_len);

    /* Update IP fields */
    ip->total_length = rte_cpu_to_be_16(ip_hdr_len + data_len);

    /* Set fragment offset and MF flag */
    uint16_t frag_offset_field = frag_offset_val / 8;  /* Offset is in 8-byte units */
    uint16_t flags = more_fragments ? RTE_IPV4_HDR_MF_FLAG : 0;
    ip->fragment_offset = rte_cpu_to_be_16((flags << 13) | frag_offset_field);

    /* Recalculate IP checksum */
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Copy fragment data safely from chained mbuf */
    uint8_t *dest_ptr = fragment->data + sizeof(struct rte_ether_hdr) + ip_hdr_len;
    if (rte_pktmbuf_read(src_mbuf, src_offset, data_len, dest_ptr) == NULL) {
        YLOG_ERROR("Failed to read fragment data from source mbuf");
        pkt_free(fragment);
        return NULL;
    }

    fragment->len = sizeof(struct rte_ether_hdr) + ip_hdr_len + data_len;

    return fragment;
}

/**
 * @brief Fragment a packet that exceeds MTU
 */
int ip_fragment_packet(struct pkt_buf *pkt, uint16_t mtu,
                       struct interface *egress_iface)
{
    if (!pkt || !egress_iface) {
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    uint16_t ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    uint16_t total_len = rte_be_to_cpu_16(ip->total_length);
    uint16_t data_len = total_len - ip_hdr_len;

    /* Check DF (Don't Fragment) bit */
    uint16_t frag_off = rte_be_to_cpu_16(ip->fragment_offset);
    if (frag_off & (RTE_IPV4_HDR_DF_FLAG << 13)) {
        YLOG_INFO("Packet has DF bit set, cannot fragment");
        /* Will send ICMP Fragmentation Needed from calling function */
        return -1;
    }

    /* Calculate max data per fragment (must be multiple of 8) */
    uint16_t max_frag_data = (mtu - sizeof(struct rte_ether_hdr) - ip_hdr_len) & ~7;

    if (max_frag_data < 8) {
        YLOG_ERROR("MTU too small for fragmentation");
        g_frag_stats.packets_too_large++;
        return -1;
    }

    YLOG_INFO("Fragmenting %u byte packet into %u byte fragments",
              total_len, max_frag_data);

    /* Start of IP payload in the SOURCE mbuf */
    /* Note: pkt->meta.l3_offset might be safer, but assuming eth+ip is correct for now */
    uint16_t src_payload_offset = sizeof(struct rte_ether_hdr) + ip_hdr_len;

    uint16_t offset = 0;
    uint32_t frag_count = 0;

    /* Create fragments */
    while (offset < data_len) {
        uint16_t fragment_data_len = (offset + max_frag_data > data_len) ?
                                     (data_len - offset) : max_frag_data;
        bool more_fragments = (offset + fragment_data_len < data_len);

        struct pkt_buf *fragment = create_fragment(ip, eth,
                                                   pkt->mbuf,
                                                   src_payload_offset + offset,
                                                   fragment_data_len,
                                                   offset, more_fragments,
                                                   egress_iface);
        if (!fragment) {
            YLOG_ERROR("Failed to create fragment");
            return -1;
        }

        /* Send fragment */
        if (interface_send(egress_iface, fragment) != 0) {
            YLOG_ERROR("Failed to send fragment");
            pkt_free(fragment);
            return -1;
        }

        pkt_free(fragment);
        frag_count++;
        offset += fragment_data_len;
    }

    YLOG_INFO("Sent %u fragments", frag_count);
    g_frag_stats.packets_fragmented++;
    g_frag_stats.fragments_created += frag_count;

    return 0;
}

/**
 * @brief Send ICMP Fragmentation Needed (Type 3, Code 4)
 */
int send_icmp_fragmentation_needed(struct pkt_buf *pkt, uint16_t mtu,
                                   struct interface *ingress_iface)
{
    if (!pkt || !ingress_iface) {
        return -1;
    }

    struct pkt_buf *icmp_pkt = pkt_alloc();
    if (!icmp_pkt) {
        YLOG_ERROR("Failed to allocate ICMP Fragmentation Needed packet");
        return -1;
    }

    struct rte_ether_hdr *orig_eth = (struct rte_ether_hdr *)pkt->data;
    struct rte_ipv4_hdr *orig_ip = (struct rte_ipv4_hdr *)(pkt->data + sizeof(struct rte_ether_hdr));

    /* Build ICMP Destination Unreachable - Fragmentation Needed */
    struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)icmp_pkt->data;
    struct rte_ipv4_hdr *new_ip = (struct rte_ipv4_hdr *)(icmp_pkt->data + sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(icmp_pkt->data +
                                sizeof(struct rte_ether_hdr) +
                                sizeof(struct rte_ipv4_hdr));

    /* Ethernet header */
    rte_ether_addr_copy(&orig_eth->src_addr, &new_eth->dst_addr);
    memcpy(&new_eth->src_addr, ingress_iface->mac_addr, RTE_ETHER_ADDR_LEN);
    new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IP header */
    new_ip->version_ihl = 0x45; /* IPv4, 20 bytes */
    new_ip->type_of_service = 0;
    new_ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 8 + 28);
    new_ip->packet_id = 0;
    new_ip->fragment_offset = 0;
    new_ip->time_to_live = 64;
    new_ip->next_proto_id = IPPROTO_ICMP;
    new_ip->src_addr = ingress_iface->config.ipv4_addr.s_addr;
    new_ip->dst_addr = orig_ip->src_addr;
    new_ip->hdr_checksum = 0;
    new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

    /* ICMP header */
    icmp->icmp_type = 3;   /* Destination Unreachable */
    icmp->icmp_code = 4;   /* Fragmentation Needed and DF set */
    icmp->icmp_cksum = 0;
    icmp->icmp_ident = 0;
    icmp->icmp_seq_nb = rte_cpu_to_be_16(mtu);  /* Next-hop MTU in seq field */

    /* Copy original IP header + 8 bytes of data */
    memcpy(icmp + 1, orig_ip, 28);

    /* Calculate ICMP checksum */
    icmp->icmp_cksum = rte_ipv4_cksum((const struct rte_ipv4_hdr *)icmp);

    icmp_pkt->len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 8 + 28;

    /* Send */
    if (interface_send(ingress_iface, icmp_pkt) == 0) {
        YLOG_INFO("ICMP Fragmentation Needed sent (MTU=%u)", mtu);
        g_frag_stats.fragmentation_needed_sent++;
    }

    pkt_free(icmp_pkt);
    return 0;
}

#else /* !HAVE_DPDK */

int ip_fragment_packet(struct pkt_buf *pkt, uint16_t mtu,
                       struct interface *egress_iface)
{
    (void)pkt;
    (void)mtu;
    (void)egress_iface;
    YLOG_ERROR("Fragmentation not supported without DPDK");
    return -1;
}

int send_icmp_fragmentation_needed(struct pkt_buf *pkt, uint16_t mtu,
                                   struct interface *ingress_iface)
{
    (void)pkt;
    (void)mtu;
    (void)ingress_iface;
    YLOG_ERROR("ICMP Fragmentation Needed not supported without DPDK");
    return -1;
}

#endif /* HAVE_DPDK */

/**
 * @brief Get fragmentation statistics
 */
void ip_fragmentation_get_stats(struct fragmentation_stats *stats)
{
    if (stats) {
        memcpy(stats, &g_frag_stats, sizeof(g_frag_stats));
    }
}

/**
 * @brief Cleanup fragmentation subsystem
 */
void ip_fragmentation_cleanup(void)
{
    printf("IP Fragmentation subsystem cleaned up\n");
}
