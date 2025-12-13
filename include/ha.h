/**
 * @file ha.h
 * @brief High Availability (Session Sync) Definitions
 */

#ifndef YESROUTER_HA_H
#define YESROUTER_HA_H

#include <stdint.h>
#include <rte_ether.h>

#define HA_PORT 8080
#define HA_MCAST_IP "224.0.0.100" /* Example multicast group */

enum ha_msg_type {
    HA_MSG_SESSION_ADD = 1,
    HA_MSG_SESSION_DEL = 2,
    HA_MSG_SESSION_UPDATE = 3,
    HA_MSG_HEARTBEAT = 4
};

enum ha_state {
    HA_STATE_MASTER,
    HA_STATE_BACKUP
};

struct ha_sync_msg {
    uint8_t type;
    uint16_t session_id;
    uint8_t mac_addr[6];
    uint32_t ip_addr; /* Host order */
    uint8_t state;
} __attribute__((packed));

struct ha_config {
    enum ha_state mode;
    uint32_t local_ip;
    uint32_t peer_ip;
    uint32_t vip_ip;
    uint32_t vip_mask;
    char vip_iface[32];
};

extern struct ha_config g_ha_config;

/**
 * Configure HA
 */
void ha_config_set(enum ha_state mode, uint32_t local_ip, uint32_t peer_ip, uint32_t vip_ip, uint32_t vip_mask, const char *vip_iface);

/**
 * Check HA Failover status (call periodically)
 */
void ha_check_failover(void);

/**
 * Initialize HA subsystem
 * @param local_ip Local IP to bind to (optional)
 * @param peer_ip Peer IP to send updates to
 */
int ha_init(uint32_t local_ip, uint32_t peer_ip);

/**
 * Send session sync message
 */
int ha_send_sync(uint8_t type, uint16_t session_id, const uint8_t *mac, uint32_t ip, uint8_t state);

/**
 * Poll for incoming HA messages
 */
void ha_poll(void);

#endif /* YESROUTER_HA_H */
