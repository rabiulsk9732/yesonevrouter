/**
 * @file nat_ha.c
 * @brief NAT High Availability - Session Synchronization
 *
 * Implements session state synchronization between active and standby
 * NAT engines for hitless failover.
 */

#include "nat.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

/* External references */
extern struct nat_config g_nat_config;

/* HA Sync Message Types */
#define HA_MSG_SESSION_CREATE   1
#define HA_MSG_SESSION_DELETE   2
#define HA_MSG_SESSION_UPDATE   3
#define HA_MSG_HEARTBEAT        4
#define HA_MSG_BULK_SYNC        5

/* HA Sync Message Header */
struct ha_msg_header {
    uint32_t magic;         /* Protocol magic: 0x4E415448 ("NATH") */
    uint8_t  version;       /* Protocol version */
    uint8_t  msg_type;      /* Message type */
    uint16_t msg_len;       /* Total message length */
    uint32_t sequence;      /* Sequence number */
    uint64_t timestamp;     /* Timestamp in ns */
} __attribute__((packed));

#define HA_MAGIC 0x4E415448

/* Session Sync Message */
struct ha_session_msg {
    struct ha_msg_header hdr;
    uint64_t session_id;
    uint32_t inside_ip;
    uint32_t outside_ip;
    uint16_t inside_port;
    uint16_t outside_port;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint8_t  protocol;
    uint8_t  flags;
    uint32_t timeout;
    uint64_t created_ts;
    uint64_t last_used_ts;
} __attribute__((packed));

/* Heartbeat Message */
struct ha_heartbeat_msg {
    struct ha_msg_header hdr;
    uint64_t active_sessions;
    uint64_t packets_translated;
    uint8_t  role;          /* 0=standby, 1=active */
    uint8_t  health;        /* 0-100 health score */
    uint8_t  pad[6];
} __attribute__((packed));

/* HA Configuration */
static struct {
    bool enabled;
    bool is_active;                 /* true = active, false = standby */
    struct sockaddr_in peer_addr;   /* Peer's sync address */
    int sync_socket;                /* UDP socket for sync */
    uint32_t sequence;              /* Send sequence number */
    uint32_t peer_sequence;         /* Last received peer sequence */
    uint64_t last_heartbeat_rx;     /* Last heartbeat received (ns) */
    uint64_t last_heartbeat_tx;     /* Last heartbeat sent (ns) */
    pthread_mutex_t lock;

    /* Statistics */
    uint64_t sessions_synced;
    uint64_t heartbeats_sent;
    uint64_t heartbeats_received;
    uint64_t sync_errors;
} g_ha_config = {
    .enabled = false,
    .is_active = true,
    .sync_socket = -1,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/**
 * Initialize HA subsystem
 */
int nat_ha_init(void)
{
    g_ha_config.enabled = false;
    g_ha_config.is_active = true;
    g_ha_config.sync_socket = -1;
    g_ha_config.sequence = 0;

    YLOG_INFO("NAT HA initialized (disabled)");
    return 0;
}

/**
 * Configure HA peer address
 */
int nat_ha_set_peer(const char *peer_ip, uint16_t port)
{
    if (!peer_ip || port == 0) {
        YLOG_ERROR("NAT HA: Invalid peer address");
        return -1;
    }

    memset(&g_ha_config.peer_addr, 0, sizeof(g_ha_config.peer_addr));
    g_ha_config.peer_addr.sin_family = AF_INET;
    g_ha_config.peer_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, peer_ip, &g_ha_config.peer_addr.sin_addr) != 1) {
        YLOG_ERROR("NAT HA: Invalid peer IP %s", peer_ip);
        return -1;
    }

    YLOG_INFO("NAT HA: Peer set to %s:%u", peer_ip, port);
    return 0;
}

/**
 * Enable/disable HA
 */
int nat_ha_enable(bool enable, uint16_t local_port)
{
    pthread_mutex_lock(&g_ha_config.lock);

    if (enable && !g_ha_config.enabled) {
        /* Create sync socket */
        g_ha_config.sync_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_ha_config.sync_socket < 0) {
            YLOG_ERROR("NAT HA: Failed to create socket: %s", strerror(errno));
            pthread_mutex_unlock(&g_ha_config.lock);
            return -1;
        }

        /* Bind to local port */
        struct sockaddr_in local_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(local_port),
            .sin_addr.s_addr = INADDR_ANY
        };

        if (bind(g_ha_config.sync_socket, (struct sockaddr *)&local_addr,
                 sizeof(local_addr)) < 0) {
            YLOG_ERROR("NAT HA: Failed to bind to port %u: %s",
                       local_port, strerror(errno));
            close(g_ha_config.sync_socket);
            g_ha_config.sync_socket = -1;
            pthread_mutex_unlock(&g_ha_config.lock);
            return -1;
        }

        g_ha_config.enabled = true;
        YLOG_INFO("NAT HA: Enabled on port %u", local_port);

    } else if (!enable && g_ha_config.enabled) {
        if (g_ha_config.sync_socket >= 0) {
            close(g_ha_config.sync_socket);
            g_ha_config.sync_socket = -1;
        }
        g_ha_config.enabled = false;
        YLOG_INFO("NAT HA: Disabled");
    }

    pthread_mutex_unlock(&g_ha_config.lock);
    return 0;
}

/**
 * Set HA role
 */
void nat_ha_set_role(bool is_active)
{
    g_ha_config.is_active = is_active;
    YLOG_INFO("NAT HA: Role set to %s", is_active ? "ACTIVE" : "STANDBY");
}

/**
 * Check if HA is enabled
 */
bool nat_ha_is_enabled(void)
{
    return g_ha_config.enabled;
}

/**
 * Check if this node is active
 */
bool nat_ha_is_active(void)
{
    return g_ha_config.is_active;
}

/**
 * Get current timestamp in nanoseconds
 */
static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/**
 * Send session sync message to peer
 */
int nat_ha_sync_session(struct nat_session *session, uint8_t msg_type)
{
    if (!g_ha_config.enabled || !session) return 0;
    if (!g_ha_config.is_active) return 0; /* Only active syncs to standby */

    struct ha_session_msg msg = {
        .hdr = {
            .magic = HA_MAGIC,
            .version = 1,
            .msg_type = msg_type,
            .msg_len = sizeof(struct ha_session_msg),
            .sequence = __atomic_fetch_add(&g_ha_config.sequence, 1, __ATOMIC_RELAXED),
            .timestamp = get_timestamp_ns()
        },
        .session_id = session->session_id,
        .inside_ip = session->inside_ip,
        .outside_ip = session->outside_ip,
        .inside_port = session->inside_port,
        .outside_port = session->outside_port,
        .dest_ip = session->dest_ip,
        .dest_port = session->dest_port,
        .protocol = session->protocol,
        .flags = session->flags,
        .timeout = session->timeout,
        .created_ts = session->created_ts,
        .last_used_ts = session->last_used_ts
    };

    ssize_t sent = sendto(g_ha_config.sync_socket, &msg, sizeof(msg), 0,
                          (struct sockaddr *)&g_ha_config.peer_addr,
                          sizeof(g_ha_config.peer_addr));

    if (sent != sizeof(msg)) {
        __atomic_fetch_add(&g_ha_config.sync_errors, 1, __ATOMIC_RELAXED);
        return -1;
    }

    __atomic_fetch_add(&g_ha_config.sessions_synced, 1, __ATOMIC_RELAXED);
    return 0;
}

/**
 * Send heartbeat to peer
 */
int nat_ha_send_heartbeat(void)
{
    if (!g_ha_config.enabled) return 0;

    struct ha_heartbeat_msg msg = {
        .hdr = {
            .magic = HA_MAGIC,
            .version = 1,
            .msg_type = HA_MSG_HEARTBEAT,
            .msg_len = sizeof(struct ha_heartbeat_msg),
            .sequence = __atomic_fetch_add(&g_ha_config.sequence, 1, __ATOMIC_RELAXED),
            .timestamp = get_timestamp_ns()
        },
        .active_sessions = g_nat_config.stats.active_sessions,
        .packets_translated = g_nat_config.stats.packets_translated,
        .role = g_ha_config.is_active ? 1 : 0,
        .health = 100
    };

    ssize_t sent = sendto(g_ha_config.sync_socket, &msg, sizeof(msg), 0,
                          (struct sockaddr *)&g_ha_config.peer_addr,
                          sizeof(g_ha_config.peer_addr));

    if (sent == sizeof(msg)) {
        g_ha_config.last_heartbeat_tx = get_timestamp_ns();
        __atomic_fetch_add(&g_ha_config.heartbeats_sent, 1, __ATOMIC_RELAXED);
        return 0;
    }

    return -1;
}

/**
 * Process received HA message (called from rx thread)
 */
int nat_ha_process_message(const uint8_t *data, int len)
{
    if (len < (int)sizeof(struct ha_msg_header)) return -1;

    const struct ha_msg_header *hdr = (const struct ha_msg_header *)data;

    if (hdr->magic != HA_MAGIC) {
        YLOG_WARNING("NAT HA: Invalid magic 0x%08X", hdr->magic);
        return -1;
    }

    switch (hdr->msg_type) {
        case HA_MSG_HEARTBEAT: {
            const struct ha_heartbeat_msg *hb = (const struct ha_heartbeat_msg *)data;
            (void)hb; /* Used for logging when debug enabled */
            g_ha_config.last_heartbeat_rx = get_timestamp_ns();
            g_ha_config.peer_sequence = hdr->sequence;
            __atomic_fetch_add(&g_ha_config.heartbeats_received, 1, __ATOMIC_RELAXED);

            YLOG_DEBUG("NAT HA: Heartbeat from peer");
            break;
        }

        case HA_MSG_SESSION_CREATE:
        case HA_MSG_SESSION_UPDATE: {
            if (!g_ha_config.is_active) {
                /* Standby receives session sync from active */
                const struct ha_session_msg *sm = (const struct ha_session_msg *)data;
                (void)sm; /* Used for future session creation */
                /* TODO: Create/update local session from sync message */
                YLOG_DEBUG("NAT HA: Session sync received");
            }
            break;
        }

        case HA_MSG_SESSION_DELETE: {
            if (!g_ha_config.is_active) {
                const struct ha_session_msg *sm = (const struct ha_session_msg *)data;
                (void)sm; /* Used for future session deletion */
                /* TODO: Delete local session */
                YLOG_DEBUG("NAT HA: Session delete received");
            }
            break;
        }

        default:
            YLOG_WARNING("NAT HA: Unknown message type %u", hdr->msg_type);
            return -1;
    }

    return 0;
}

/**
 * Check peer health (call periodically)
 */
bool nat_ha_peer_alive(void)
{
    if (!g_ha_config.enabled) return false;

    uint64_t now = get_timestamp_ns();
    uint64_t timeout_ns = 3000000000ULL; /* 3 seconds */

    return (now - g_ha_config.last_heartbeat_rx) < timeout_ns;
}

/**
 * Trigger failover (promote standby to active)
 */
void nat_ha_trigger_failover(void)
{
    if (g_ha_config.is_active) {
        YLOG_WARNING("NAT HA: Already active, ignoring failover trigger");
        return;
    }

    YLOG_WARNING("NAT HA: FAILOVER TRIGGERED - Promoting to ACTIVE");
    g_ha_config.is_active = true;
}

/**
 * Get HA statistics
 */
void nat_ha_get_stats(uint64_t *sessions_synced, uint64_t *heartbeats_sent,
                      uint64_t *heartbeats_received, uint64_t *sync_errors)
{
    if (sessions_synced) *sessions_synced = g_ha_config.sessions_synced;
    if (heartbeats_sent) *heartbeats_sent = g_ha_config.heartbeats_sent;
    if (heartbeats_received) *heartbeats_received = g_ha_config.heartbeats_received;
    if (sync_errors) *sync_errors = g_ha_config.sync_errors;
}

/**
 * Print HA configuration and status
 */
void nat_ha_print_status(void)
{
    printf("\nNAT High Availability Status:\n");
    printf("  Enabled: %s\n", g_ha_config.enabled ? "Yes" : "No");
    printf("  Role: %s\n", g_ha_config.is_active ? "ACTIVE" : "STANDBY");

    if (g_ha_config.enabled) {
        char peer_str[32];
        inet_ntop(AF_INET, &g_ha_config.peer_addr.sin_addr, peer_str, sizeof(peer_str));
        printf("  Peer: %s:%u\n", peer_str, ntohs(g_ha_config.peer_addr.sin_port));
        printf("  Peer Alive: %s\n", nat_ha_peer_alive() ? "Yes" : "No");
        printf("  Sessions Synced: %lu\n", g_ha_config.sessions_synced);
        printf("  Heartbeats Sent: %lu\n", g_ha_config.heartbeats_sent);
        printf("  Heartbeats Received: %lu\n", g_ha_config.heartbeats_received);
        printf("  Sync Errors: %lu\n", g_ha_config.sync_errors);
    }
}

/**
 * Cleanup HA subsystem
 */
void nat_ha_cleanup(void)
{
    if (g_ha_config.sync_socket >= 0) {
        close(g_ha_config.sync_socket);
        g_ha_config.sync_socket = -1;
    }
    g_ha_config.enabled = false;
    YLOG_INFO("NAT HA: Cleanup complete");
}
