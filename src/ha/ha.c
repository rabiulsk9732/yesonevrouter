/**
 * @file ha.c
 * @brief High Availability Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ha.h"
#include "log.h"
#include "pppoe.h" /* To update session state */

#include <time.h>

struct ha_config g_ha_config = {
    .mode = HA_STATE_MASTER, /* Default */
    .local_ip = 0,
    .peer_ip = 0,
    .vip_ip = 0,
    .vip_mask = 0,
    .vip_iface = {0}
};

static int g_ha_sock = -1;
static struct sockaddr_in g_peer_addr;
static uint64_t g_last_heartbeat_ts = 0;

void ha_config_set(enum ha_state mode, uint32_t local_ip, uint32_t peer_ip, uint32_t vip_ip, uint32_t vip_mask, const char *vip_iface)
{
    g_ha_config.mode = mode;
    g_ha_config.local_ip = local_ip;
    g_ha_config.peer_ip = peer_ip;
    g_ha_config.vip_ip = vip_ip;
    g_ha_config.vip_mask = vip_mask;
    if (vip_iface) strncpy(g_ha_config.vip_iface, vip_iface, sizeof(g_ha_config.vip_iface) - 1);

    /* Re-init if needed */
    if (g_ha_sock >= 0) {
        close(g_ha_sock);
        g_ha_sock = -1;
    }
    ha_init(local_ip, peer_ip);
}

int ha_init(uint32_t local_ip, uint32_t peer_ip)
{
    g_ha_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ha_sock < 0) {
        YLOG_ERROR("HA: Failed to create socket");
        return -1;
    }

    /* Bind to local port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(local_ip); /* Bind to specific IP if provided */
    addr.sin_port = htons(HA_PORT);

    if (bind(g_ha_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("HA: Failed to bind socket");
        close(g_ha_sock);
        return -1;
    }

    /* Setup peer address */
    memset(&g_peer_addr, 0, sizeof(g_peer_addr));
    g_peer_addr.sin_family = AF_INET;
    g_peer_addr.sin_addr.s_addr = htonl(peer_ip);
    g_peer_addr.sin_port = htons(HA_PORT);

    g_last_heartbeat_ts = time(NULL);

    YLOG_INFO("HA: Initialized. Mode: %s, Peer: %u.%u.%u.%u",
              g_ha_config.mode == HA_STATE_MASTER ? "MASTER" : "BACKUP",
              (peer_ip >> 24) & 0xFF, (peer_ip >> 16) & 0xFF,
              (peer_ip >> 8) & 0xFF, peer_ip & 0xFF);
    return 0;
}

int ha_send_sync(uint8_t type, uint16_t session_id, const uint8_t *mac, uint32_t ip, uint8_t state)
{
    if (g_ha_sock < 0) return -1;

    struct ha_sync_msg msg;
    msg.type = type;
    msg.session_id = htons(session_id);
    if (mac) memcpy(msg.mac_addr, mac, 6);
    else memset(msg.mac_addr, 0, 6);
    msg.ip_addr = htonl(ip);
    msg.state = state;

    sendto(g_ha_sock, &msg, sizeof(msg), 0, (struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
    return 0;
}

static void ha_send_heartbeat(void)
{
    ha_send_sync(HA_MSG_HEARTBEAT, 0, NULL, 0, g_ha_config.mode);
}

static void ha_set_vip(bool enable)
{
    if (g_ha_config.vip_ip == 0 || g_ha_config.vip_iface[0] == '\0') return;

    char cmd[256];
    uint32_t ip = g_ha_config.vip_ip;

    /* Convert mask to prefix length (simplified) */
    int prefix = 32;
    /* TODO: Calculate prefix from mask */

    snprintf(cmd, sizeof(cmd), "ip addr %s %u.%u.%u.%u/%d dev %s",
             enable ? "add" : "del",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
             prefix, g_ha_config.vip_iface);

    YLOG_INFO("HA: VIP %s: %s", enable ? "Adding" : "Removing", cmd);
    if (system(cmd) != 0) {
        YLOG_ERROR("HA: Failed to execute VIP command: %s", cmd);
    }
}

void ha_check_failover(void)
{
    static uint64_t last_check = 0;
    uint64_t now = time(NULL);

    if (now - last_check >= 1) {
        ha_send_heartbeat();
        last_check = now;
    }

    if (g_ha_config.mode == HA_STATE_BACKUP) {
        if (now - g_last_heartbeat_ts > 3) {
            YLOG_WARNING("HA: Peer timeout! Promoting to MASTER");
            g_ha_config.mode = HA_STATE_MASTER;
            ha_set_vip(true);
        }
    }
}

void ha_poll(void)
{
    if (g_ha_sock < 0) return;

    struct ha_sync_msg msg;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    ssize_t len = recvfrom(g_ha_sock, &msg, sizeof(msg), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addr_len);
    if (len != sizeof(msg)) return;

    if (msg.type == HA_MSG_HEARTBEAT) {
        g_last_heartbeat_ts = time(NULL);
        if (g_ha_config.mode == HA_STATE_MASTER && msg.state == HA_STATE_MASTER) {
            YLOG_ERROR("HA: Split-brain detected! Peer claims to be MASTER.");
            /* Simple resolution: If my IP < peer IP, I yield? Or just log for now. */
        }
        return;
    }

    uint16_t session_id = ntohs(msg.session_id);
    uint32_t ip = ntohl(msg.ip_addr);
    (void)session_id;
    (void)ip;

    YLOG_INFO("HA: Received Sync Type %d for Session %u (IP: %u.%u.%u.%u)",
              msg.type, session_id,
              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);

    /* TODO: Update local session table */
}
