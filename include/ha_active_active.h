/**
 * @file ha_active_active.h
 * @brief Active-Active Load Balancing API
 */

#ifndef HA_ACTIVE_ACTIVE_H
#define HA_ACTIVE_ACTIVE_H

#include <stdint.h>
#include <stdbool.h>

/* Load balancing modes */
#define HA_LB_ROUND_ROBIN   0
#define HA_LB_LEAST_SESSIONS 1
#define HA_LB_HASH          2

/**
 * Initialize active-active subsystem
 * @param local_node_id This node's unique ID
 * @param local_ip This node's IP (host order)
 */
int ha_active_active_init(uint32_t local_node_id, uint32_t local_ip);

/**
 * Cleanup active-active subsystem
 */
void ha_active_active_cleanup(void);

/**
 * Add a peer node
 */
int ha_add_peer(uint32_t node_id, uint32_t ip, uint16_t port);

/**
 * Set load balancing mode
 */
void ha_set_lb_mode(int mode);

/**
 * Select node for new session
 * @param client_mac Client MAC for hash-based LB
 * @return Node ID that should handle the session
 */
uint32_t ha_select_node_for_session(const uint8_t *client_mac);

/**
 * Check if session belongs to local node
 */
bool ha_is_local_session(uint32_t owner_node);

/**
 * Update session count for node
 */
void ha_update_session_count(uint32_t node_id, int delta);

/**
 * Record heartbeat from peer
 */
void ha_node_heartbeat(uint32_t node_id);

/**
 * Check node health (call periodically)
 */
void ha_check_node_health(uint32_t timeout_sec);

/**
 * Show HA status
 */
void ha_show_status(void);

#endif /* HA_ACTIVE_ACTIVE_H */
