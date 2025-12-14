/**
 * @file pppoe_tx.c
 * @brief PPPoE TX with NIC Capability Detection
 *
 * Fixes double VLAN tagging bug by detecting NIC capabilities and using
 * appropriate tagging method (hardware offload for Intel/Mellanox,
 * software tagging for virtio/paravirt NICs).
 */

#include <stdio.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#include "pppoe_tx.h"
#include "pppoe_defs.h"
#include "dpdk_init.h"
#include "log.h"

/* Global NIC capability flags (per-port) */
static bool g_port_vlan_insert[RTE_MAX_ETHPORTS] = {false};
static bool g_port_caps_initialized = false;

/**
 * Initialize PPPoE TX subsystem
 * Detects NIC capabilities for each DPDK port
 * @return 0 on success, -1 on error
 */
int pppoe_tx_init(void)
{
    if (g_port_caps_initialized) {
        return 0;
    }

    uint16_t num_ports = rte_eth_dev_count_avail();
    if (num_ports == 0) {
        YLOG_WARNING("[PPPoE-TX] No DPDK ports available");
        g_port_caps_initialized = true;
        return 0;
    }

    YLOG_INFO("[PPPoE-TX] Detecting NIC capabilities for %u ports", num_ports);

    for (uint16_t port = 0; port < num_ports; port++) {
        struct rte_eth_dev_info dev_info;
        int ret = rte_eth_dev_info_get(port, &dev_info);

        if (ret != 0) {
            YLOG_ERROR("[PPPoE-TX] Failed to get device info for port %u: %s",
                      port, rte_strerror(-ret));
            continue;
        }

        /* Check VLAN insertion offload capability */
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT) {
            g_port_vlan_insert[port] = true;
            YLOG_INFO("[PPPoE-TX] Port %u (%s): HW VLAN insert AVAILABLE",
                     port, dev_info.driver_name ? dev_info.driver_name : "unknown");
        } else {
            /* Virtio/paravirt NICs typically don't support this */
            g_port_vlan_insert[port] = false;
            YLOG_WARNING("[PPPoE-TX] Port %u (%s): HW VLAN insert NOT available (will use SW tagging)",
                        port, dev_info.driver_name ? dev_info.driver_name : "unknown");
        }
    }

    g_port_caps_initialized = true;
    YLOG_INFO("[PPPoE-TX] Initialization complete");
    return 0;
}

/**
 * Send PPPoE discovery packet (PADO/PADS/PADT) with VLAN support
 *
 * Uses NIC capability detection to choose between hardware VLAN offload
 * and software VLAN tagging to avoid double-tagging bug.
 *
 * @param port_id DPDK port ID
 * @param queue_id TX queue ID
 * @param dst_mac Destination MAC address
 * @param src_mac Source MAC address
 * @param vlan_id VLAN ID (0 = untagged)
 * @param pppoe_payload PPPoE header + payload (already formatted)
 * @param payload_len Length of PPPoE header + payload
 * @return 0 on success, -1 on error
 */
int pppoe_tx_send_discovery(uint16_t port_id, uint16_t queue_id,
                            const struct rte_ether_addr *dst_mac,
                            const uint8_t *src_mac,
                            uint16_t vlan_id,
                            const uint8_t *pppoe_payload,
                            uint16_t payload_len)
{
    /* Get mempool for mbuf allocation */
    struct rte_mempool *mp = dpdk_get_mempool();
    if (!mp) {
        YLOG_ERROR("[PPPoE-TX] Failed to get DPDK mempool");
        return -1;
    }

    /* Allocate mbuf */
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m) {
        YLOG_ERROR("[PPPoE-TX] Failed to allocate mbuf");
        return -1;
    }

    /* Build packet based on NIC capabilities */
    uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;
    uint16_t frame_len;

    /* Ethernet header */
    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    memcpy(&eth->src_addr, src_mac, 6);

    if (vlan_id > 0 && port_id < RTE_MAX_ETHPORTS && g_port_vlan_insert[port_id]) {
        /* HARDWARE VLAN OFFLOAD PATH (Intel, Mellanox, etc.) */
        eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);

        /* Copy PPPoE payload right after Ethernet header */
        memcpy(pkt + sizeof(struct rte_ether_hdr), pppoe_payload, payload_len);

        /* Set hardware offload flags */
        m->vlan_tci = vlan_id;
        m->ol_flags |= RTE_MBUF_F_TX_VLAN;

        frame_len = sizeof(struct rte_ether_hdr) + payload_len;

        YLOG_DEBUG("[PPPoE-TX] HW offload: port=%u queue=%u vlan=%u len=%u",
                  port_id, queue_id, vlan_id, frame_len);

    } else if (vlan_id > 0) {
        /* SOFTWARE VLAN TAGGING (Virtio, tap, etc.) */
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);

        /* Insert VLAN tag manually */
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        vlan->vlan_tci = rte_cpu_to_be_16(vlan_id);
        vlan->eth_proto = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);

        /* Copy PPPoE payload after VLAN header */
        memcpy(pkt + sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr),
               pppoe_payload, payload_len);

        /* NO hardware offload flags */
        m->ol_flags &= ~RTE_MBUF_F_TX_VLAN;

        frame_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr) + payload_len;

        YLOG_DEBUG("[PPPoE-TX] SW tagging: port=%u queue=%u vlan=%u len=%u",
                  port_id, queue_id, vlan_id, frame_len);

    } else {
        /* UNTAGGED */
        eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);
        memcpy(pkt + sizeof(struct rte_ether_hdr), pppoe_payload, payload_len);
        frame_len = sizeof(struct rte_ether_hdr) + payload_len;

        YLOG_DEBUG("[PPPoE-TX] Untagged: port=%u queue=%u len=%u",
                  port_id, queue_id, frame_len);
    }

    /* Enforce minimum Ethernet frame size (60 bytes without FCS) */
    if (frame_len < 60) {
        memset(pkt + frame_len, 0, 60 - frame_len);
        frame_len = 60;
    }

    /* Set mbuf lengths */
    m->data_len = frame_len;
    m->pkt_len = frame_len;
    m->port = port_id;  /* Set egress port for TX */

    /* Send packet using DPDK TX burst */
    uint16_t sent = rte_eth_tx_burst(port_id, queue_id, &m, 1);

    if (sent == 0) {
        YLOG_WARNING("[PPPoE-TX] Failed to send packet on port %u queue %u (TX queue full?)",
                    port_id, queue_id);
        rte_pktmbuf_free(m);
        return -1;
    }

    /* TX descriptor cleanup to avoid queue starvation */
    rte_eth_tx_done_cleanup(port_id, queue_id, 0);

    return 0;
}

/**
 * Check if port supports hardware VLAN insertion
 * @param port_id DPDK port ID
 * @return true if HW VLAN insert is supported, false otherwise
 */
bool pppoe_tx_has_hw_vlan_insert(uint16_t port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) {
        return false;
    }
    return g_port_vlan_insert[port_id];
}

/**
 * Cleanup PPPoE TX subsystem
 */
void pppoe_tx_cleanup(void)
{
    g_port_caps_initialized = false;
    YLOG_INFO("[PPPoE-TX] Cleanup complete");
}
