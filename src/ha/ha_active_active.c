/**
 * @file ha_active_active.c
 * @brief Active-Active Load Balancing for PPPoE Sessions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ha_active_active.h"
#include "log.h"

#define MAX_HA_NODES 4
#define HA_SYNC_PORT 4789

/* Node state */
typedef enum {
    HA_NODE_UNKNOWN,
    HA_NODE_ACTIVE,
    HA_NODE_STANDBY,
    HA_NODE_FAILED
} ha_node_state_t;

/* HA node info */
struct ha_node {
    uint32_t node_id;
    uint32_t ip;
    uint16_t port;
    ha_node_state_t state;
    uint32_t session_count;
    uint64_t last_heartbeat;
    int socket;
    bool local;
};

/* Session ownership */
struct session_owner {
    uint16_t session_id;
    uint32_t owner_node;
};

static struct {
    struct ha_node nodes[MAX_HA_NODES];
    int node_count;
    uint32_t local_node_id;

    /* Load balancing */
    uint32_t lb_mode;  /* 0=round-robin, 1=least-sessions, 2=hash */
    int rr_index;

    /* Sync */
    int sync_socket;
    pthread_t sync_thread;
    volatile int running;

    pthread_mutex_t lock;
} g_ha = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int ha_active_active_init(uint32_t local_node_id, uint32_t local_ip)
{
    memset(&g_ha, 0, sizeof(g_ha) - sizeof(pthread_mutex_t));
    pthread_mutex_init(&g_ha.lock, NULL);

    g_ha.local_node_id = local_node_id;

    /* Add local node */
    g_ha.nodes[0].node_id = local_node_id;
    g_ha.nodes[0].ip = local_ip;
    g_ha.nodes[0].port = HA_SYNC_PORT;
    g_ha.nodes[0].state = HA_NODE_ACTIVE;
    g_ha.nodes[0].local = true;
    g_ha.node_count = 1;

    YLOG_INFO("HA Active-Active: Initialized (node %u, mode: %s)",
              local_node_id, g_ha.lb_mode == 0 ? "round-robin" : "least-sessions");
    return 0;
}

int ha_add_peer(uint32_t node_id, uint32_t ip, uint16_t port)
{
    pthread_mutex_lock(&g_ha.lock);

    if (g_ha.node_count >= MAX_HA_NODES) {
        pthread_mutex_unlock(&g_ha.lock);
        return -1;
    }

    struct ha_node *node = &g_ha.nodes[g_ha.node_count];
    node->node_id = node_id;
    node->ip = ip;
    node->port = port;
    node->state = HA_NODE_UNKNOWN;
    node->local = false;

    /* Create sync socket */
    node->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (node->socket >= 0) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = htonl(ip)
        };
        connect(node->socket, (struct sockaddr *)&addr, sizeof(addr));
    }

    g_ha.node_count++;

    YLOG_INFO("HA: Added peer node %u (%u.%u.%u.%u:%u)",
              node_id,
              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
              (ip >> 8) & 0xFF, ip & 0xFF, port);

    pthread_mutex_unlock(&g_ha.lock);
    return 0;
}

void ha_set_lb_mode(int mode)
{
    g_ha.lb_mode = mode;
    YLOG_INFO("HA: Load balancing mode set to %s",
              mode == 0 ? "round-robin" : mode == 1 ? "least-sessions" : "hash");
}

uint32_t ha_select_node_for_session(const uint8_t *client_mac)
{
    pthread_mutex_lock(&g_ha.lock);

    uint32_t selected = g_ha.local_node_id;

    switch (g_ha.lb_mode) {
    case 0: /* Round-robin */
        {
            int start = g_ha.rr_index;
            for (int i = 0; i < g_ha.node_count; i++) {
                int idx = (start + i) % g_ha.node_count;
                if (g_ha.nodes[idx].state == HA_NODE_ACTIVE) {
                    selected = g_ha.nodes[idx].node_id;
                    g_ha.rr_index = (idx + 1) % g_ha.node_count;
                    break;
                }
            }
        }
        break;

    case 1: /* Least sessions */
        {
            uint32_t min_sessions = UINT32_MAX;
            for (int i = 0; i < g_ha.node_count; i++) {
                if (g_ha.nodes[i].state == HA_NODE_ACTIVE &&
                    g_ha.nodes[i].session_count < min_sessions) {
                    min_sessions = g_ha.nodes[i].session_count;
                    selected = g_ha.nodes[i].node_id;
                }
            }
        }
        break;

    case 2: /* Hash-based (sticky) */
        if (client_mac) {
            uint32_t hash = 0;
            for (int i = 0; i < 6; i++) {
                hash = (hash * 31) + client_mac[i];
            }
            int active_nodes = 0;
            for (int i = 0; i < g_ha.node_count; i++) {
                if (g_ha.nodes[i].state == HA_NODE_ACTIVE) active_nodes++;
            }
            if (active_nodes > 0) {
                int target = hash % active_nodes;
                int count = 0;
                for (int i = 0; i < g_ha.node_count; i++) {
                    if (g_ha.nodes[i].state == HA_NODE_ACTIVE) {
                        if (count == target) {
                            selected = g_ha.nodes[i].node_id;
                            break;
                        }
                        count++;
                    }
                }
            }
        }
        break;
    }

    pthread_mutex_unlock(&g_ha.lock);
    return selected;
}

bool ha_is_local_session(uint32_t owner_node)
{
    return owner_node == g_ha.local_node_id;
}

void ha_update_session_count(uint32_t node_id, int delta)
{
    pthread_mutex_lock(&g_ha.lock);

    for (int i = 0; i < g_ha.node_count; i++) {
        if (g_ha.nodes[i].node_id == node_id) {
            if (delta > 0) {
                g_ha.nodes[i].session_count += delta;
            } else if (g_ha.nodes[i].session_count >= (uint32_t)(-delta)) {
                g_ha.nodes[i].session_count += delta;
            }
            break;
        }
    }

    pthread_mutex_unlock(&g_ha.lock);
}

void ha_node_heartbeat(uint32_t node_id)
{
    pthread_mutex_lock(&g_ha.lock);

    for (int i = 0; i < g_ha.node_count; i++) {
        if (g_ha.nodes[i].node_id == node_id) {
            g_ha.nodes[i].last_heartbeat = (uint64_t)time(NULL);
            if (g_ha.nodes[i].state != HA_NODE_ACTIVE) {
                g_ha.nodes[i].state = HA_NODE_ACTIVE;
                YLOG_INFO("HA: Node %u is now ACTIVE", node_id);
            }
            break;
        }
    }

    pthread_mutex_unlock(&g_ha.lock);
}

void ha_check_node_health(uint32_t timeout_sec)
{
    uint64_t now = (uint64_t)time(NULL);

    pthread_mutex_lock(&g_ha.lock);

    for (int i = 0; i < g_ha.node_count; i++) {
        if (!g_ha.nodes[i].local &&
            g_ha.nodes[i].state == HA_NODE_ACTIVE &&
            now - g_ha.nodes[i].last_heartbeat > timeout_sec) {

            g_ha.nodes[i].state = HA_NODE_FAILED;
            YLOG_WARNING("HA: Node %u FAILED (no heartbeat for %lus)",
                         g_ha.nodes[i].node_id, timeout_sec);
        }
    }

    pthread_mutex_unlock(&g_ha.lock);
}

void ha_show_status(void)
{
    pthread_mutex_lock(&g_ha.lock);

    printf("HA Active-Active Status:\n");
    printf("Local Node: %u\n", g_ha.local_node_id);
    printf("LB Mode: %s\n", g_ha.lb_mode == 0 ? "round-robin" :
                           g_ha.lb_mode == 1 ? "least-sessions" : "hash");
    printf("\nNodes (%d):\n", g_ha.node_count);
    printf("%-8s %-16s %-10s %-10s %s\n", "ID", "IP", "State", "Sessions", "Local");

    for (int i = 0; i < g_ha.node_count; i++) {
        struct ha_node *n = &g_ha.nodes[i];
        const char *state = n->state == HA_NODE_ACTIVE ? "ACTIVE" :
                           n->state == HA_NODE_STANDBY ? "STANDBY" :
                           n->state == HA_NODE_FAILED ? "FAILED" : "UNKNOWN";
        printf("%-8u %u.%u.%u.%u       %-10s %-10u %s\n",
               n->node_id,
               (n->ip >> 24) & 0xFF, (n->ip >> 16) & 0xFF,
               (n->ip >> 8) & 0xFF, n->ip & 0xFF,
               state, n->session_count, n->local ? "yes" : "no");
    }

    pthread_mutex_unlock(&g_ha.lock);
}

void ha_active_active_cleanup(void)
{
    pthread_mutex_lock(&g_ha.lock);

    for (int i = 0; i < g_ha.node_count; i++) {
        if (g_ha.nodes[i].socket >= 0) {
            close(g_ha.nodes[i].socket);
        }
    }

    g_ha.node_count = 0;

    pthread_mutex_unlock(&g_ha.lock);
    pthread_mutex_destroy(&g_ha.lock);

    YLOG_INFO("HA Active-Active: Cleanup complete");
}
