/**
 * @file vlan.h
 * @brief VLAN (802.1Q) Protocol Support
 */

#ifndef VLAN_H
#define VLAN_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"

/* VLAN EtherType */
#define ETHERTYPE_VLAN      0x8100  /* IEEE 802.1Q */

/* QinQ EtherTypes (IEEE 802.1ad) */
#define ETHERTYPE_QINQ      0x88a8  /* IEEE 802.1ad (preferred) */
#define ETHERTYPE_QINQ_ALT  0x9100  /* Alternative QinQ */
#define ETHERTYPE_QINQ_ALT2 0x9200  /* Another alternative */

/* VLAN ID limits */
#define VLAN_ID_MIN     1
#define VLAN_ID_MAX     4094
#define VLAN_N_VID      4096

/* VLAN priority (PCP) values */
#define VLAN_PCP_BE     0  /* Best Effort */
#define VLAN_PCP_BK     1  /* Background */
#define VLAN_PCP_EE     2  /* Excellent Effort */
#define VLAN_PCP_CA     3  /* Critical Applications */
#define VLAN_PCP_VI     4  /* Video */
#define VLAN_PCP_VO     5  /* Voice */
#define VLAN_PCP_IC     6  /* Internetwork Control */
#define VLAN_PCP_NC     7  /* Network Control */

/**
 * @brief 802.1Q VLAN header structure
 *
 * Format:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  PCP  |D|        VLAN ID (VID)         |       EtherType       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * PCP: Priority Code Point (3 bits)
 * D:   Drop Eligible Indicator (1 bit)
 * VID: VLAN Identifier (12 bits)
 */
struct vlan_hdr {
    uint16_t tci;        /* Tag Control Information (PCP + DEI + VID) */
    uint16_t ethertype;  /* Encapsulated protocol */
} __attribute__((packed));

/**
 * @brief QinQ (double-tagged) packet tags structure
 */
struct qinq_tags {
    uint16_t outer_vlan_id;  /* S-VID (Service VLAN ID) */
    uint8_t  outer_pcp;      /* Outer priority */
    uint8_t  outer_dei;      /* Outer DEI */
    uint16_t inner_vlan_id;  /* C-VID (Customer VLAN ID) */
    uint8_t  inner_pcp;      /* Inner priority */
    uint8_t  inner_dei;      /* Inner DEI */
};

/* TCI field manipulation macros */
#define VLAN_TCI_PCP_SHIFT  13
#define VLAN_TCI_DEI_SHIFT  12
#define VLAN_TCI_VID_MASK   0x0FFF

#define VLAN_TCI(pcp, dei, vid) \
    (((pcp) << VLAN_TCI_PCP_SHIFT) | ((dei) << VLAN_TCI_DEI_SHIFT) | ((vid) & VLAN_TCI_VID_MASK))

#define VLAN_TCI_GET_PCP(tci)   (((tci) >> VLAN_TCI_PCP_SHIFT) & 0x07)
#define VLAN_TCI_GET_DEI(tci)   (((tci) >> VLAN_TCI_DEI_SHIFT) & 0x01)
#define VLAN_TCI_GET_VID(tci)   ((tci) & VLAN_TCI_VID_MASK)

/**
 * @brief Check if a packet has a VLAN tag
 * @param pkt Packet buffer
 * @return true if packet is VLAN-tagged, false otherwise
 */
bool vlan_is_tagged(struct pkt_buf *pkt);

/**
 * @brief Get VLAN ID from a tagged packet
 * @param pkt Packet buffer
 * @return VLAN ID (1-4094) or 0 if not tagged
 */
uint16_t vlan_get_id(struct pkt_buf *pkt);

/**
 * @brief Get VLAN priority from a tagged packet
 * @param pkt Packet buffer
 * @return VLAN priority (0-7) or 0 if not tagged
 */
uint8_t vlan_get_priority(struct pkt_buf *pkt);

/**
 * @brief Add VLAN tag to a packet
 * @param pkt Packet buffer
 * @param vlan_id VLAN ID (1-4094)
 * @param pcp Priority Code Point (0-7)
 * @return 0 on success, -1 on failure
 */
int vlan_tag_packet(struct pkt_buf *pkt, uint16_t vlan_id, uint8_t pcp);

/**
 * @brief Remove VLAN tag from a packet
 * @param pkt Packet buffer
 * @return 0 on success, -1 on failure
 */
int vlan_untag_packet(struct pkt_buf *pkt);

/**
 * @brief Validate VLAN ID
 * @param vlan_id VLAN ID to validate
 * @return true if valid, false otherwise
 */
static inline bool vlan_id_is_valid(uint16_t vlan_id)
{
    return (vlan_id >= VLAN_ID_MIN && vlan_id <= VLAN_ID_MAX);
}

/* ========== IEEE 802.1QinQ (Double VLAN Tagging) Functions ========== */

/**
 * @brief Check if packet is double-tagged (QinQ)
 * @param pkt Packet buffer
 * @return true if double-tagged, false otherwise
 */
bool vlan_is_double_tagged(struct pkt_buf *pkt);

/**
 * @brief Get both outer and inner VLAN tags from QinQ packet
 * @param pkt Packet buffer
 * @param tags Output structure for tag information
 * @return 0 on success, -1 on failure
 */
int vlan_get_qinq_tags(struct pkt_buf *pkt, struct qinq_tags *tags);

/**
 * @brief Get outer VLAN ID (S-VID) from double-tagged packet
 * @param pkt Packet buffer
 * @return Outer VLAN ID or 0 if not double-tagged
 */
uint16_t vlan_get_outer_id(struct pkt_buf *pkt);

/**
 * @brief Get inner VLAN ID (C-VID) from double-tagged packet
 * @param pkt Packet buffer
 * @return Inner VLAN ID or 0 if not double-tagged
 */
uint16_t vlan_get_inner_id(struct pkt_buf *pkt);

/**
 * @brief Push outer VLAN tag (S-TAG) onto packet
 * @param pkt Packet buffer (must already have C-TAG)
 * @param svid Service VLAN ID
 * @param pcp Priority Code Point
 * @return 0 on success, -1 on failure
 */
int vlan_push_tag(struct pkt_buf *pkt, uint16_t svid, uint8_t pcp);

/**
 * @brief Pop outer VLAN tag (S-TAG) from packet
 * @param pkt Packet buffer (must be double-tagged)
 * @return 0 on success, -1 on failure
 */
int vlan_pop_tag(struct pkt_buf *pkt);

/**
 * @brief Swap outer VLAN tag while preserving inner tag
 * @param pkt Packet buffer (must be double-tagged)
 * @param new_svid New service VLAN ID
 * @param new_pcp New priority
 * @return 0 on success, -1 on failure
 */
int vlan_swap_outer_tag(struct pkt_buf *pkt, uint16_t new_svid, uint8_t new_pcp);

#endif /* VLAN_H */
