/**
 * @file packet.c
 * @brief Packet Buffer Management Implementation
 *
 * References:
 * - DPDK Programmer's Guide: https://doc.dpdk.org/guides/prog_guide/
 * - DPDK Packet (Mbuf) Library
 */

#define _DEFAULT_SOURCE
#include "packet.h"
#include "interface.h"
#include "log.h"
#include "dpdk_init.h"
#include <rte_mbuf.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef HAVE_DPDK
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#endif

/* Fallback definitions for non-DPDK builds */
#ifndef HAVE_DPDK
#include <net/ethernet.h>
#include <linux/if_ether.h>
#endif

/* Packet statistics */
static struct {
    uint64_t allocated;
    uint64_t freed;
    uint64_t alloc_failed;
} pkt_stats;

int pkt_buf_init(void)
{
    memset(&pkt_stats, 0, sizeof(pkt_stats));
    printf("Packet buffer subsystem initialized\n");
    return 0;
}

struct pkt_buf *pkt_alloc(void)
{
    struct pkt_buf *pkt;

    pkt = calloc(1, sizeof(*pkt));
    if (!pkt) {
        __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_RELAXED);
        return NULL;
    }

#ifdef HAVE_DPDK
    if (dpdk_is_enabled() && g_dpdk_config.pkt_mempool) {
        pkt->mbuf = rte_pktmbuf_alloc((struct rte_mempool *)g_dpdk_config.pkt_mempool->pool);
        if (!pkt->mbuf) {
            free(pkt);
            __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_RELAXED);
            return NULL;
        }
        pkt->data = rte_pktmbuf_mtod(pkt->mbuf, uint8_t *);
        pkt->len = 0;
        pkt->headroom = rte_pktmbuf_headroom(pkt->mbuf);
        pkt->buf_size = rte_pktmbuf_tailroom(pkt->mbuf) + pkt->headroom;
        pkt->buf = NULL;  /* Not used with DPDK */
    } else
#endif
    {
        /* Software fallback */
        pkt->buf_size = PKT_MAX_SIZE;
        pkt->buf = malloc(pkt->buf_size);
        if (!pkt->buf) {
            free(pkt);
            __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_RELAXED);
            return NULL;
        }
        pkt->data = pkt->buf + PKT_DEFAULT_HEADROOM;
        pkt->len = 0;
        pkt->headroom = PKT_DEFAULT_HEADROOM;
    }

    pkt->refcnt = 1;
    pkt->timestamp = 0;  /* Avoid time() syscall in fast path - caller sets if needed */

    __atomic_add_fetch(&pkt_stats.allocated, 1, __ATOMIC_RELAXED);

    return pkt;
}

void pkt_free(struct pkt_buf *pkt)
{
    if (!pkt) {
        return;
    }

    /* Decrement reference count */
    uint32_t refs = __atomic_sub_fetch(&pkt->refcnt, 1, __ATOMIC_RELAXED);
    if (refs > 0) {
        return;
    }

#ifdef HAVE_DPDK
    if (pkt->mbuf) {
        rte_pktmbuf_free(pkt->mbuf);
    } else
#endif
    {
        if (pkt->buf) {
            free(pkt->buf);
        }
    }

    free(pkt);
    __atomic_add_fetch(&pkt_stats.freed, 1, __ATOMIC_RELAXED);
}

struct pkt_buf *pkt_clone(struct pkt_buf *pkt)
{
    if (!pkt) {
        return NULL;
    }

    /* Increment reference count for shared data */
    pkt_ref(pkt);

    return pkt;
}

struct pkt_buf *pkt_copy(struct pkt_buf *pkt)
{
    struct pkt_buf *copy;

    if (!pkt) {
        return NULL;
    }

    copy = pkt_alloc();
    if (!copy) {
        return NULL;
    }

    /* Copy packet data */
    if (pkt->len > 0) {
        memcpy(copy->data, pkt->data, pkt->len);
        copy->len = pkt->len;
    }

    /* Copy metadata */
    copy->flags = pkt->flags;
    copy->meta = pkt->meta;

    return copy;
}

uint8_t *pkt_push(struct pkt_buf *pkt, uint16_t len)
{
    if (!pkt || len > pkt->headroom) {
        return NULL;
    }

    pkt->data -= len;
    pkt->len += len;
    pkt->headroom -= len;

    return pkt->data;
}

uint8_t *pkt_pull(struct pkt_buf *pkt, uint16_t len)
{
    if (!pkt || len > pkt->len) {
        return NULL;
    }

    pkt->data += len;
    pkt->len -= len;
    pkt->headroom += len;

    return pkt->data;
}

int pkt_extract_metadata(struct pkt_buf *pkt)
{
    uint16_t eth_type;
    uint8_t *l4_hdr;

#ifdef HAVE_DPDK
    /* Use DPDK structures for proper parsing - DPDK Programmer's Guide */
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ip;

    if (!pkt || pkt->len < sizeof(struct rte_ether_hdr)) {
        return -1;
    }

    /* Save ingress interface index before clearing meta - set by RX thread */
    uint32_t saved_ifindex = pkt->meta.ingress_ifindex;
    memset(&pkt->meta, 0, sizeof(pkt->meta));
    pkt->meta.ingress_ifindex = saved_ifindex;

    /* Parse Ethernet header using DPDK rte_ether_hdr */
    eth = (struct rte_ether_hdr *)pkt->data;
    pkt->meta.l2_offset = 0;
    pkt->meta.l2_type = PKT_L2_ETHERNET;
    pkt->flags |= PKT_FLAG_L2_VALID;

    eth_type = rte_be_to_cpu_16(eth->ether_type);

    /* Check for VLAN (802.1Q) */
    if (eth_type == RTE_ETHER_TYPE_VLAN) {
        pkt->meta.l2_type = PKT_L2_VLAN;
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        pkt->meta.vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0x0FFF;
        pkt->meta.l3_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr);
        eth_type = rte_be_to_cpu_16(vlan->eth_proto);
    } else {
        pkt->meta.l3_offset = sizeof(struct rte_ether_hdr);
    }

    /* Parse IPv4 header */
    if (eth_type == RTE_ETHER_TYPE_IPV4 &&
        pkt->len >= pkt->meta.l3_offset + sizeof(struct rte_ipv4_hdr)) {

        ip = (struct rte_ipv4_hdr *)(pkt->data + pkt->meta.l3_offset);
        pkt->meta.l3_type = PKT_L3_IPV4;
        pkt->meta.src_ip = rte_be_to_cpu_32(ip->src_addr);
        pkt->meta.dst_ip = rte_be_to_cpu_32(ip->dst_addr);
        pkt->meta.protocol = ip->next_proto_id;
        pkt->flags |= PKT_FLAG_L3_VALID;

        uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
        pkt->meta.l4_offset = pkt->meta.l3_offset + ihl;
        l4_hdr = pkt->data + pkt->meta.l4_offset;

        /* Parse Layer 4 */
        if (ip->next_proto_id == IPPROTO_TCP &&
            pkt->len >= pkt->meta.l4_offset + 20) {
            pkt->meta.l4_type = PKT_L4_TCP;
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            pkt->meta.src_port = rte_be_to_cpu_16(tcp->src_port);
            pkt->meta.dst_port = rte_be_to_cpu_16(tcp->dst_port);
            pkt->flags |= PKT_FLAG_L4_VALID;
            pkt->meta.payload_offset = pkt->meta.l4_offset + ((tcp->data_off >> 4) * 4);

        } else if (ip->next_proto_id == IPPROTO_UDP &&
                   pkt->len >= pkt->meta.l4_offset + 8) {
            pkt->meta.l4_type = PKT_L4_UDP;
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            pkt->meta.src_port = rte_be_to_cpu_16(udp->src_port);
            pkt->meta.dst_port = rte_be_to_cpu_16(udp->dst_port);
            pkt->flags |= PKT_FLAG_L4_VALID;
            pkt->meta.payload_offset = pkt->meta.l4_offset + sizeof(struct rte_udp_hdr);
        } else if (ip->next_proto_id == IPPROTO_ICMP) {
            pkt->meta.l4_type = PKT_L4_ICMP;
            pkt->flags |= PKT_FLAG_L4_VALID;
            pkt->meta.payload_offset = pkt->meta.l4_offset + 8;
        }
    }

    /* Handle ARP */
    if (eth_type == RTE_ETHER_TYPE_ARP) {
        pkt->meta.l3_type = PKT_L3_ARP;
        pkt->meta.l3_offset = sizeof(struct rte_ether_hdr);
        pkt->flags |= PKT_FLAG_L3_VALID;
    }

#else
    /* Non-DPDK fallback using Linux headers */
    struct iphdr *ip;
    uint16_t *ports;

    if (!pkt || pkt->len < 14) {
        return -1;
    }

    /* Save ingress interface index before clearing meta */
    uint32_t saved_ifindex_nondpdk = pkt->meta.ingress_ifindex;
    memset(&pkt->meta, 0, sizeof(pkt->meta));
    pkt->meta.ingress_ifindex = saved_ifindex_nondpdk;
    pkt->meta.l2_offset = 0;
    pkt->meta.l2_type = PKT_L2_ETHERNET;
    pkt->flags |= PKT_FLAG_L2_VALID;

    eth_type = ntohs(*(uint16_t *)(pkt->data + 12));

    if (eth_type == 0x8100) {  /* VLAN */
        pkt->meta.l2_type = PKT_L2_VLAN;
        pkt->meta.vlan_id = ntohs(*(uint16_t *)(pkt->data + 14)) & 0x0FFF;
        pkt->meta.l3_offset = 18;
        eth_type = ntohs(*(uint16_t *)(pkt->data + 16));
    } else {
        pkt->meta.l3_offset = 14;
    }

    if (eth_type == 0x0800 && pkt->len >= pkt->meta.l3_offset + 20) {  /* IPv4 */
        ip = (struct iphdr *)(pkt->data + pkt->meta.l3_offset);
        pkt->meta.l3_type = PKT_L3_IPV4;
        pkt->meta.src_ip = ntohl(ip->saddr);
        pkt->meta.dst_ip = ntohl(ip->daddr);
        pkt->meta.protocol = ip->protocol;
        pkt->flags |= PKT_FLAG_L3_VALID;
        pkt->meta.l4_offset = pkt->meta.l3_offset + (ip->ihl * 4);
        l4_hdr = pkt->data + pkt->meta.l4_offset;

        if (ip->protocol == IPPROTO_TCP && pkt->len >= pkt->meta.l4_offset + 20) {
            pkt->meta.l4_type = PKT_L4_TCP;
            ports = (uint16_t *)l4_hdr;
            pkt->meta.src_port = ntohs(ports[0]);
            pkt->meta.dst_port = ntohs(ports[1]);
            pkt->flags |= PKT_FLAG_L4_VALID;
        } else if (ip->protocol == IPPROTO_UDP && pkt->len >= pkt->meta.l4_offset + 8) {
            pkt->meta.l4_type = PKT_L4_UDP;
            ports = (uint16_t *)l4_hdr;
            pkt->meta.src_port = ntohs(ports[0]);
            pkt->meta.dst_port = ntohs(ports[1]);
            pkt->flags |= PKT_FLAG_L4_VALID;
        } else if (ip->protocol == IPPROTO_ICMP) {
            pkt->meta.l4_type = PKT_L4_ICMP;
            pkt->flags |= PKT_FLAG_L4_VALID;
        }
    } else if (eth_type == 0x0806) {  /* ARP */
        pkt->meta.l3_type = PKT_L3_ARP;
        pkt->meta.l3_offset = 14;
        pkt->flags |= PKT_FLAG_L3_VALID;
    }
#endif

    /* Calculate flow hash */
    pkt->meta.flow_hash = pkt_calc_flow_hash(pkt);

    return 0;
}

uint32_t pkt_calc_flow_hash(struct pkt_buf *pkt)
{
    uint32_t hash = 0;

    if (!pkt || !(pkt->flags & PKT_FLAG_L3_VALID)) {
        return 0;
    }

    /* Simple hash based on 5-tuple */
    hash = pkt->meta.src_ip ^ pkt->meta.dst_ip;
    hash ^= (pkt->meta.src_port << 16) | pkt->meta.dst_port;
    hash ^= pkt->meta.protocol;

    return hash;
}

void pkt_get_stats(uint64_t *allocated, uint64_t *freed)
{
    if (allocated) {
        *allocated = __atomic_load_n(&pkt_stats.allocated, __ATOMIC_SEQ_CST);
    }
    if (freed) {
        *freed = __atomic_load_n(&pkt_stats.freed, __ATOMIC_SEQ_CST);
    }
}

void pkt_buf_cleanup(void)
{
    uint64_t allocated, freed;

    pkt_get_stats(&allocated, &freed);

    printf("Packet buffer statistics:\n");
    printf("  Allocated: %lu\n", allocated);
    printf("  Freed: %lu\n", freed);
    printf("  Leaked: %lu\n", allocated - freed);
    printf("  Alloc failures: %lu\n", pkt_stats.alloc_failed);

    if (allocated != freed) {
        fprintf(stderr, "WARNING: %lu packet buffers leaked!\n",
                allocated - freed);
    }
}
