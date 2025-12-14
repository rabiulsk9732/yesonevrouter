/**
 * @file pppoe_tx.h
 * @brief PPPoE TX with NIC Capability Detection API
 */

#ifndef PPPOE_TX_H
#define PPPOE_TX_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>

/**
 * Initialize PPPoE TX subsystem
 * Detects NIC capabilities for each DPDK port
 * @return 0 on success, -1 on error
 */
int pppoe_tx_init(void);

/**
 * Send PPPoE discovery packet (PADO/PADS/PADT) with VLAN support
 *
 * Automatically selects hardware VLAN offload or software tagging
 * based on NIC capabilities to avoid double-tagging bug.
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
                            uint16_t payload_len);

/**
 * Check if port supports hardware VLAN insertion
 * @param port_id DPDK port ID
 * @return true if HW VLAN insert is supported, false otherwise
 */
bool pppoe_tx_has_hw_vlan_insert(uint16_t port_id);

/**
 * Cleanup PPPoE TX subsystem
 */
void pppoe_tx_cleanup(void);

#endif /* PPPOE_TX_H */
