/**
 * @file lacp.c
 * @brief Link Aggregation Control Protocol (802.3ad) Implementation
 */

#include "lacp.h"
#include "packet.h"
#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#endif

/* Global bond list */
static struct bond_interface *g_bonds[16];
static uint32_t g_num_bonds = 0;

/**
 * @brief Initialize LACP subsystem
 */
int lacp_init(void)
{
    memset(g_bonds, 0, sizeof(g_bonds));
    g_num_bonds = 0;
    printf("LACP subsystem initialized\n");
    return 0;
}

/**
 * @brief Create a bonded interface
 */
struct bond_interface *bond_create(const char *name, enum bond_mode mode)
{
    if (g_num_bonds >= 16) {
        fprintf(stderr, "Maximum number of bond interfaces reached\n");
        return NULL;
    }

    struct bond_interface *bond = calloc(1, sizeof(struct bond_interface));
    if (!bond) {
        fprintf(stderr, "Failed to allocate bond interface\n");
        return NULL;
    }

    bond->mode = mode;
    bond->xmit_hash_policy = BOND_XMIT_POLICY_LAYER34;
    bond->num_ports = 0;
    bond->active_member = 0;
    bond->lacp_active = true;
    bond->lacp_fast = false;
    bond->system_priority = 32768;  /* Default priority */
    bond->key = g_num_bonds + 1;

    /* Generate system MAC (use first available interface's MAC) */
    /* For now, use a default MAC */
    memset(bond->system_mac, 0, 6);
    bond->system_mac[0] = 0x02;  /* Locally administered */

    g_bonds[g_num_bonds++] = bond;

    printf("Bond interface '%s' created (mode: %d)\n", name, mode);
    return bond;
}

/**
 * @brief Add a member port to a bond
 */
int bond_add_member(struct bond_interface *bond, struct interface *iface)
{
    if (!bond || !iface) {
        return -1;
    }

    if (bond->num_ports >= IF_MAX_VLAN_MEMBERS) {
        fprintf(stderr, "Maximum number of bond members reached\n");
        return -1;
    }

    /* Create LACP port structure */
    struct lacp_port *port = calloc(1, sizeof(struct lacp_port));
    if (!port) {
        fprintf(stderr, "Failed to allocate LACP port\n");
        return -1;
    }

    port->iface = iface;
    port->port_number = bond->num_ports + 1;
    port->port_priority = 32768;  /* Default priority */
    port->state = LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION;
    port->sm_state = LACP_SM_DETACHED;

    /* Initialize actor information */
    port->actor_info.system_priority = htons(bond->system_priority);
    memcpy(port->actor_info.system, bond->system_mac, 6);
    port->actor_info.key = htons(bond->key);
    port->actor_info.port_priority = htons(port->port_priority);
    port->actor_info.port = htons(port->port_number);
    port->actor_info.state = port->state;

    bond->ports[bond->num_ports++] = port;

    printf("Added member %s to bond (member %u/%u)\n",
           iface->name, bond->num_ports, IF_MAX_VLAN_MEMBERS);

    return 0;
}

/**
 * @brief Remove a member port from a bond
 */
int bond_remove_member(struct bond_interface *bond, struct interface *iface)
{
    if (!bond || !iface) {
        return -1;
    }

    for (uint32_t i = 0; i < bond->num_ports; i++) {
        if (bond->ports[i] && bond->ports[i]->iface == iface) {
            free(bond->ports[i]);

            /* Shift remaining ports */
            for (uint32_t j = i; j < bond->num_ports - 1; j++) {
                bond->ports[j] = bond->ports[j + 1];
            }

            bond->ports[bond->num_ports - 1] = NULL;
            bond->num_ports--;

            printf("Removed member %s from bond\n", iface->name);
            return 0;
        }
    }

    fprintf(stderr, "Member %s not found in bond\n", iface->name);
    return -1;
}

/**
 * @brief Hash packet for load balancing (Layer 2)
 */
static uint32_t bond_hash_l2(struct pkt_buf *pkt)
{
    if (!pkt || !pkt->data) {
        return 0;
    }

#ifdef HAVE_DPDK
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)(pkt->data + pkt->meta.l2_offset);
    uint32_t hash = 0;

    /* XOR source and destination MAC addresses */
    for (int i = 0; i < 6; i++) {
        hash ^= eth->src_addr.addr_bytes[i] ^ eth->dst_addr.addr_bytes[i];
    }

    return hash;
#else
    return 0;
#endif
}

/**
 * @brief Hash packet for load balancing (Layer 3+4)
 */
static uint32_t bond_hash_l34(struct pkt_buf *pkt)
{
    if (!pkt) {
        return 0;
    }

#ifdef HAVE_DPDK
    uint32_t hash = 0;

    /* Use existing flow hash if available */
    if (pkt->meta.flow_hash != 0) {
        return pkt->meta.flow_hash;
    }

    /* Hash IP addresses */
    if (pkt->meta.l3_type == PKT_L3_IPV4 && pkt->meta.l3_offset > 0) {
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt->data + pkt->meta.l3_offset);
        hash = rte_hash_crc_4byte(ip->src_addr, 0);
        hash = rte_hash_crc_4byte(ip->dst_addr, hash);

        /* Hash L4 ports if available */
        if (ip->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)
                                      ((uint8_t *)ip + sizeof(struct rte_ipv4_hdr));
            hash = rte_hash_crc_4byte((tcp->src_port << 16) | tcp->dst_port, hash);
        } else if (ip->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)
                                      ((uint8_t *)ip + sizeof(struct rte_ipv4_hdr));
            hash = rte_hash_crc_4byte((udp->src_port << 16) | udp->dst_port, hash);
        }
    } else {
        /* Fallback to L2 hash */
        hash = bond_hash_l2(pkt);
    }

    return hash;
#else
    return 0;
#endif
}

/**
 * @brief Hash packet for load balancing
 */
uint32_t bond_hash_packet(struct pkt_buf *pkt, enum bond_xmit_hash_policy policy)
{
    switch (policy) {
    case BOND_XMIT_POLICY_LAYER2:
        return bond_hash_l2(pkt);

    case BOND_XMIT_POLICY_LAYER34:
    case BOND_XMIT_POLICY_LAYER23:
        return bond_hash_l34(pkt);

    default:
        return bond_hash_l34(pkt);
    }
}

/**
 * @brief Select a member for transmitting a packet
 */
struct interface *bond_select_tx_member(struct bond_interface *bond, struct pkt_buf *pkt)
{
    if (!bond || bond->num_ports == 0) {
        return NULL;
    }

    uint32_t member_idx = 0;

    switch (bond->mode) {
    case BOND_MODE_ACTIVE_BACKUP:
        /* Use active member only */
        member_idx = bond->active_member;
        if (member_idx >= bond->num_ports) {
            member_idx = 0;
        }
        break;

    case BOND_MODE_BALANCE_RR:
        /* Round-robin: use next member */
        member_idx = (bond->active_member + 1) % bond->num_ports;
        bond->active_member = member_idx;
        break;

    case BOND_MODE_BALANCE_XOR:
    case BOND_MODE_802_3AD:
        /* Hash-based selection */
        if (pkt) {
            uint32_t hash = bond_hash_packet(pkt, bond->xmit_hash_policy);
            member_idx = hash % bond->num_ports;
        } else {
            member_idx = 0;
        }
        break;

    default:
        member_idx = 0;
        break;
    }

    /* Find first UP member starting from selected index */
    for (uint32_t i = 0; i < bond->num_ports; i++) {
        uint32_t idx = (member_idx + i) % bond->num_ports;
        struct lacp_port *port = bond->ports[idx];

        if (port && port->iface && port->iface->state == IF_STATE_UP) {
            return port->iface;
        }
    }

    return NULL;  /* No UP members available */
}

/**
 * @brief Process received LACP PDU
 */
int lacp_rx_pdu(struct interface *iface, struct pkt_buf *pkt)
{
    if (!iface || !pkt) {
        return -1;
    }

    /* Find the bond that contains this interface */
    for (uint32_t i = 0; i < g_num_bonds; i++) {
        struct bond_interface *bond = g_bonds[i];
        if (!bond) continue;

        for (uint32_t j = 0; j < bond->num_ports; j++) {
            struct lacp_port *port = bond->ports[j];
            if (port && port->iface == iface) {
                /* Found the port */
                port->lacpdu_rx++;

                /* TODO: Parse and process LACP PDU */
                /* For now, just count it */

                printf("LACP PDU received on %s (total: %lu)\n",
                       iface->name, port->lacpdu_rx);

                return 0;
            }
        }
    }

    return -1;
}

/**
 * @brief Transmit LACP PDU
 */
int lacp_tx_pdu(struct lacp_port *port)
{
    if (!port || !port->iface) {
        return -1;
    }

    /* TODO: Build and transmit LACP PDU */
    /* This requires mbuf allocation and proper frame construction */

    port->lacpdu_tx++;

    return 0;
}

/**
 * @brief LACP periodic timer tick (called every 1 second)
 */
void lacp_periodic_tick(void)
{
    static uint64_t tick_count = 0;
    tick_count++;

    for (uint32_t i = 0; i < g_num_bonds; i++) {
        struct bond_interface *bond = g_bonds[i];
        if (!bond || bond->mode != BOND_MODE_802_3AD) {
            continue;
        }

        /* Process each port */
        for (uint32_t j = 0; j < bond->num_ports; j++) {
            struct lacp_port *port = bond->ports[j];
            if (!port) continue;

            /* Send LACP PDU if needed */
            uint32_t period = bond->lacp_fast ?
                             LACP_FAST_PERIODIC_TIME / 1000 :
                             LACP_SLOW_PERIODIC_TIME / 1000;

            if (tick_count % period == 0) {
                lacp_tx_pdu(port);
            }
        }
    }
}

/**
 * @brief Cleanup LACP subsystem
 */
void lacp_cleanup(void)
{
    for (uint32_t i = 0; i < g_num_bonds; i++) {
        if (g_bonds[i]) {
            for (uint32_t j = 0; j < g_bonds[i]->num_ports; j++) {
                free(g_bonds[i]->ports[j]);
            }
            free(g_bonds[i]);
        }
    }

    g_num_bonds = 0;
    printf("LACP subsystem cleaned up\n");
}
