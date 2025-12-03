/**
 * @file packet.c
 * @brief Packet Buffer Management Implementation
 */

#define _DEFAULT_SOURCE
#include "packet.h"
#include "dpdk_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

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
        __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_SEQ_CST);
        return NULL;
    }

#ifdef HAVE_DPDK
    if (dpdk_is_enabled() && g_dpdk_config.pkt_mempool) {
        pkt->mbuf = rte_pktmbuf_alloc((struct rte_mempool *)g_dpdk_config.pkt_mempool->pool);
        if (!pkt->mbuf) {
            free(pkt);
            __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_SEQ_CST);
            return NULL;
        }
        pkt->data = rte_pktmbuf_mtod(pkt->mbuf, uint8_t *);
        pkt->len = 0;
        pkt->headroom = rte_pktmbuf_headroom(pkt->mbuf);
    } else
#endif
    {
        /* Software fallback */
        pkt->buf_size = PKT_MAX_SIZE;
        pkt->buf = malloc(pkt->buf_size);
        if (!pkt->buf) {
            free(pkt);
            __atomic_add_fetch(&pkt_stats.alloc_failed, 1, __ATOMIC_SEQ_CST);
            return NULL;
        }
        pkt->data = pkt->buf + PKT_DEFAULT_HEADROOM;
        pkt->len = 0;
        pkt->headroom = PKT_DEFAULT_HEADROOM;
    }
    
    pkt->refcnt = 1;
    pkt->timestamp = time(NULL);
    
    __atomic_add_fetch(&pkt_stats.allocated, 1, __ATOMIC_SEQ_CST);
    
    return pkt;
}

void pkt_free(struct pkt_buf *pkt)
{
    if (!pkt) {
        return;
    }
    
    /* Decrement reference count */
    uint32_t refs = __atomic_sub_fetch(&pkt->refcnt, 1, __ATOMIC_SEQ_CST);
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
    __atomic_add_fetch(&pkt_stats.freed, 1, __ATOMIC_SEQ_CST);
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
    struct ethhdr *eth;
    struct iphdr *ip;
    uint16_t *ports;
    uint16_t eth_type;
    uint8_t *l4_hdr;
    
    if (!pkt || pkt->len < sizeof(struct ethhdr)) {
        return -1;
    }
    
    memset(&pkt->meta, 0, sizeof(pkt->meta));
    
    /* Parse Ethernet header */
    eth = (struct ethhdr *)pkt->data;
    pkt->meta.l2_offset = 0;
    pkt->meta.l2_type = PKT_L2_ETHERNET;
    pkt->flags |= PKT_FLAG_L2_VALID;
    
    eth_type = ntohs(eth->h_proto);
    
    /* Check for VLAN */
    if (eth_type == ETH_P_8021Q) {
        pkt->meta.l2_type = PKT_L2_VLAN;
        /* VLAN header is 4 bytes */
        pkt->meta.vlan_id = ntohs(*(uint16_t *)(pkt->data + 14)) & 0x0FFF;
        pkt->meta.l3_offset = sizeof(struct ethhdr) + 4;
        eth_type = ntohs(*(uint16_t *)(pkt->data + 16));
    } else {
        pkt->meta.l3_offset = sizeof(struct ethhdr);
    }
    
    /* Parse IP header */
    if (eth_type == ETH_P_IP && 
        pkt->len >= pkt->meta.l3_offset + sizeof(struct iphdr)) {
        
        ip = (struct iphdr *)(pkt->data + pkt->meta.l3_offset);
        pkt->meta.l3_type = PKT_L3_IPV4;
        pkt->meta.src_ip = ntohl(ip->saddr);
        pkt->meta.dst_ip = ntohl(ip->daddr);
        pkt->meta.protocol = ip->protocol;
        pkt->flags |= PKT_FLAG_L3_VALID;
        
        pkt->meta.l4_offset = pkt->meta.l3_offset + (ip->ihl * 4);
        l4_hdr = pkt->data + pkt->meta.l4_offset;
        
        /* Parse Layer 4 - use raw pointers for compatibility */
        if (ip->protocol == IPPROTO_TCP && 
            pkt->len >= pkt->meta.l4_offset + 20) {
            
            pkt->meta.l4_type = PKT_L4_TCP;
            ports = (uint16_t *)l4_hdr;
            pkt->meta.src_port = ntohs(ports[0]);
            pkt->meta.dst_port = ntohs(ports[1]);
            pkt->flags |= PKT_FLAG_L4_VALID;
            /* TCP header length is in nibbles at offset 12 */
            pkt->meta.payload_offset = pkt->meta.l4_offset + ((l4_hdr[12] >> 4) * 4);
            
        } else if (ip->protocol == IPPROTO_UDP && 
                   pkt->len >= pkt->meta.l4_offset + 8) {
            
            pkt->meta.l4_type = PKT_L4_UDP;
            ports = (uint16_t *)l4_hdr;
            pkt->meta.src_port = ntohs(ports[0]);
            pkt->meta.dst_port = ntohs(ports[1]);
            pkt->flags |= PKT_FLAG_L4_VALID;
            pkt->meta.payload_offset = pkt->meta.l4_offset + 8;
            
        } else if (ip->protocol == IPPROTO_ICMP) {
            pkt->meta.l4_type = PKT_L4_ICMP;
            pkt->flags |= PKT_FLAG_L4_VALID;
            pkt->meta.payload_offset = pkt->meta.l4_offset + 8;
        }
    } else if (eth_type == ETH_P_ARP) {
        pkt->meta.l3_type = PKT_L3_ARP;
        pkt->flags |= PKT_FLAG_L3_VALID;
    }
    
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
