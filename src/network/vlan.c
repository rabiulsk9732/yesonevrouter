/**
 * @file vlan.c
 * @brief VLAN (802.1Q) Protocol Implementation
 */

#include "vlan.h"
#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#endif

/**
 * @brief Check if a packet has a VLAN tag
 */
bool vlan_is_tagged(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return false;
    }

#ifdef HAVE_DPDK
    /* Get Ethernet header from packet data */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    uint16_t ether_type = ntohs(eth->ether_type);
    return (ether_type == ETHERTYPE_VLAN);
#else
    return false;
#endif
}

/**
 * @brief Get VLAN ID from a tagged packet
 */
uint16_t vlan_get_id(struct pkt_buf *pkt)
{
    if (!vlan_is_tagged(pkt)) {
        return 0;
    }

#ifdef HAVE_DPDK
    /* VLAN header is right after Ethernet header */
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *vlan = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
    uint16_t tci = ntohs(vlan->tci);
    return VLAN_TCI_GET_VID(tci);
#else
    return 0;
#endif
}

/**
 * @brief Get VLAN priority from a tagged packet
 */
uint8_t vlan_get_priority(struct pkt_buf *pkt)
{
    if (!vlan_is_tagged(pkt)) {
        return 0;
    }

#ifdef HAVE_DPDK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *vlan = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
    uint16_t tci = ntohs(vlan->tci);
    return VLAN_TCI_GET_PCP(tci);
#else
    return 0;
#endif
}

/**
 * @brief Add VLAN tag to a packet
 */
int vlan_tag_packet(struct pkt_buf *pkt, uint16_t vlan_id, uint8_t pcp)
{
    if (!pkt || !pkt->mbuf) {
        return -1;
    }

    if (!vlan_id_is_valid(vlan_id)) {
        fprintf(stderr, "Invalid VLAN ID: %u\n", vlan_id);
        return -1;
    }

    if (pcp > 7) {
        fprintf(stderr, "Invalid VLAN priority: %u\n", pcp);
        return -1;
    }

#ifdef HAVE_DPDK
    /* For DPDK, use hardware VLAN insertion */
    struct rte_mbuf *m = pkt->mbuf;

    /* Set VLAN TCI in mbuf */
    m->vlan_tci = VLAN_TCI(pcp, 0, vlan_id);

    /*  Request hardware VLAN insertion */
    m->ol_flags |= RTE_MBUF_F_TX_VLAN;

    return 0;
#else
    fprintf(stderr, "VLAN tagging not supported without DPDK\n");
    return -1;
#endif
}

/**
 * @brief Remove VLAN tag from a packet
 */
int vlan_untag_packet(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->mbuf) {
        return -1;
    }

    if (!vlan_is_tagged(pkt)) {
        /* Not tagged, nothing to do */
        return 0;
    }

#ifdef HAVE_DPDK
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *vlan = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));

    /* Save the encapsulated EtherType */
    uint16_t inner_ethertype = vlan->ethertype;

    /* Remove VLAN header by copying MAC addresses forward */
    uint8_t *new_eth = (uint8_t *)eth + sizeof(struct vlan_hdr);
    memmove(new_eth, eth, 12);  /* Copy src + dst MAC */

    /* Set the EtherType to the encapsulated protocol */
    ((struct rte_ether_hdr *)new_eth)->ether_type = inner_ethertype;

    /* Adjust mbuf data pointer */
    rte_pktmbuf_adj(m, sizeof(struct vlan_hdr));

    /* Update packet data pointer */
    pkt->data = rte_pktmbuf_mtod(m, uint8_t *);
    pkt->len = rte_pktmbuf_pkt_len(m);

    return 0;
#else
    fprintf(stderr, "VLAN untagging not supported without DPDK\n");
    return -1;
#endif
}

/* ========== IEEE 802.1QinQ (Double VLAN Tagging) Implementation ========== */

#ifdef HAVE_DPDK

/**
 * @brief Check if packet is double-tagged (QinQ)
 */
bool vlan_is_double_tagged(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return false;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    uint16_t ether_type = ntohs(eth->ether_type);

    /* Check if outer tag is QinQ EtherType */
    if (ether_type == ETHERTYPE_QINQ ||
        ether_type == ETHERTYPE_QINQ_ALT ||
        ether_type == ETHERTYPE_QINQ_ALT2) {
        /* Check if inner tag is 802.1Q */
        struct vlan_hdr *outer = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
        uint16_t inner_type = ntohs(outer->ethertype);
        return (inner_type == ETHERTYPE_VLAN);
    }

    return false;
}

/**
 * @brief Get both outer and inner VLAN tags from QinQ packet
 */
int vlan_get_qinq_tags(struct pkt_buf *pkt, struct qinq_tags *tags)
{
    if (!vlan_is_double_tagged(pkt) || !tags) {
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);

    /* Parse outer tag (S-TAG) */
    struct vlan_hdr *outer = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
    uint16_t outer_tci = ntohs(outer->tci);
    tags->outer_vlan_id = VLAN_TCI_GET_VID(outer_tci);
    tags->outer_pcp = VLAN_TCI_GET_PCP(outer_tci);
    tags->outer_dei = VLAN_TCI_GET_DEI(outer_tci);

    /* Parse inner tag (C-TAG) */
    struct vlan_hdr *inner = outer + 1;
    uint16_t inner_tci = ntohs(inner->tci);
    tags->inner_vlan_id = VLAN_TCI_GET_VID(inner_tci);
    tags->inner_pcp = VLAN_TCI_GET_PCP(inner_tci);
    tags->inner_dei = VLAN_TCI_GET_DEI(inner_tci);

    return 0;
}

/**
 * @brief Get outer VLAN ID (S-VID) from double-tagged packet
 */
uint16_t vlan_get_outer_id(struct pkt_buf *pkt)
{
    if (!vlan_is_double_tagged(pkt)) {
        return 0;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *outer = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
    uint16_t outer_tci = ntohs(outer->tci);
    return VLAN_TCI_GET_VID(outer_tci);
}

/**
 * @brief Get inner VLAN ID (C-VID) from double-tagged packet
 */
uint16_t vlan_get_inner_id(struct pkt_buf *pkt)
{
    if (!vlan_is_double_tagged(pkt)) {
        return 0;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *outer = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));
    struct vlan_hdr *inner = outer + 1;
    uint16_t inner_tci = ntohs(inner->tci);
    return VLAN_TCI_GET_VID(inner_tci);
}

/**
 * @brief Push outer VLAN tag (S-TAG) onto packet
 * Converts single-tagged packet to double-tagged (QinQ)
 */
int vlan_push_tag(struct pkt_buf *pkt, uint16_t svid, uint8_t pcp)
{
    if (!pkt || !pkt->mbuf) {
        return -1;
    }

    if (!vlan_id_is_valid(svid)) {
        fprintf(stderr, "Invalid S-VID: %u\n", svid);
        return -1;
    }

    if (pcp > 7) {
        fprintf(stderr, "Invalid PCP: %u\n", pcp);
        return -1;
    }

    /* Packet must already be single-tagged */
    if (!vlan_is_tagged(pkt)) {
        fprintf(stderr, "Packet must be VLAN-tagged before pushing S-TAG\n");
        return -1;
    }

    if (vlan_is_double_tagged(pkt)) {
        fprintf(stderr, "Packet is already double-tagged\n");
        return -1;
    }

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Prepend 4 bytes for outer VLAN tag */
    char *new_data = rte_pktmbuf_prepend(m, sizeof(struct vlan_hdr));
    if (!new_data) {
        fprintf(stderr, "Failed to prepend S-TAG\n");
        return -1;
    }

    /* Move Ethernet header forward */
    memmove(new_data, new_data + sizeof(struct vlan_hdr), sizeof(struct rte_ether_hdr));

    eth = (struct rte_ether_hdr *)new_data;
    struct vlan_hdr *outer = (struct vlan_hdr *)(eth + 1);

    /* Build outer tag (S-TAG) */
    uint16_t existing_ethertype = eth->ether_type;  /* Should be 0x8100 */
    eth->ether_type = htons(ETHERTYPE_QINQ);

    outer->tci = htons(VLAN_TCI(pcp, 0, svid));
    outer->ethertype = existing_ethertype;  /* Point to C-TAG (0x8100) */

    /* Update packet pointers */
    pkt->data = rte_pktmbuf_mtod(m, uint8_t *);
    pkt->len = rte_pktmbuf_pkt_len(m);

    return 0;
}

/**
 * @brief Pop outer VLAN tag (S-TAG) from packet
 * Converts double-tagged packet to single-tagged
 */
int vlan_pop_tag(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->mbuf) {
        return -1;
    }

    if (!vlan_is_double_tagged(pkt)) {
        fprintf(stderr, "Packet is not double-tagged\n");
        return -1;
    }

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Move Ethernet header backward to remove outer tag */
    uint8_t *new_eth = (uint8_t *)eth + sizeof(struct vlan_hdr);
    memmove(new_eth, eth, sizeof(struct rte_ether_hdr));

    /* Update Ethernet header to point to C-TAG */
    eth = (struct rte_ether_hdr *)new_eth;
    /* Inner tag already has correct EtherType (0x8100) from outer->ethertype */

    /* Adjust mbuf */
    rte_pktmbuf_adj(m, sizeof(struct vlan_hdr));

    /* Update packet pointers */
    pkt->data = rte_pktmbuf_mtod(m, uint8_t *);
    pkt->len = rte_pktmbuf_pkt_len(m);

    return 0;
}

/**
 * @brief Swap outer VLAN tag while preserving inner tag
 * Used in provider networks to change S-VID
 */
int vlan_swap_outer_tag(struct pkt_buf *pkt, uint16_t new_svid, uint8_t new_pcp)
{
    if (!pkt || !pkt->data) {
        return -1;
    }

    if (!vlan_id_is_valid(new_svid)) {
        fprintf(stderr, "Invalid S-VID: %u\n", new_svid);
        return -1;
    }

    if (new_pcp > 7) {
        fprintf(stderr, "Invalid PCP: %u\n", new_pcp);
        return -1;
    }

    if (!vlan_is_double_tagged(pkt)) {
        fprintf(stderr, "Packet is not double-tagged\n");
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    struct vlan_hdr *outer = (struct vlan_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));

    /* Update outer tag TCI (S-VID and PCP) */
    outer->tci = htons(VLAN_TCI(new_pcp, 0, new_svid));

    return 0;
}

#else /* !HAVE_DPDK */

/* Stub implementations for non-DPDK builds */

bool vlan_is_double_tagged(struct pkt_buf *pkt)
{
    (void)pkt;
    return false;
}

int vlan_get_qinq_tags(struct pkt_buf *pkt, struct qinq_tags *tags)
{
    (void)pkt;
    (void)tags;
    return -1;
}

uint16_t vlan_get_outer_id(struct pkt_buf *pkt)
{
    (void)pkt;
    return 0;
}

uint16_t vlan_get_inner_id(struct pkt_buf *pkt)
{
    (void)pkt;
    return 0;
}

int vlan_push_tag(struct pkt_buf *pkt, uint16_t svid, uint8_t pcp)
{
    (void)pkt;
    (void)svid;
    (void)pcp;
    fprintf(stderr, "QinQ not supported without DPDK\n");
    return -1;
}

int vlan_pop_tag(struct pkt_buf *pkt)
{
    (void)pkt;
    fprintf(stderr, "QinQ not supported without DPDK\n");
    return -1;
}

int vlan_swap_outer_tag(struct pkt_buf *pkt, uint16_t new_svid, uint8_t new_pcp)
{
    (void)pkt;
    (void)new_svid;
    (void)new_pcp;
    fprintf(stderr, "QinQ not supported without DPDK\n");
    return -1;
}

#endif /* HAVE_DPDK */
