/**
 * @file ha_accounting_sync.c
 * @brief RADIUS Accounting Synchronization Between HA Nodes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ha_accounting_sync.h"
#include "log.h"

#define SYNC_MAGIC 0x48415343  /* "HASC" */
#define MAX_SYNC_QUEUE 1024

/* Sync message types */
typedef enum {
    SYNC_MSG_ACCT_START,
    SYNC_MSG_ACCT_INTERIM,
    SYNC_MSG_ACCT_STOP,
    SYNC_MSG_ACCT_UPDATE
} sync_msg_type_t;

/* Accounting sync message */
struct acct_sync_msg {
    uint32_t magic;
    uint16_t msg_type;
    uint16_t session_id;
    uint32_t client_ip;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
    uint32_t session_time;
    char username[64];
};

/* Sync queue entry */
struct sync_entry {
    struct acct_sync_msg msg;
    uint32_t peer_ip;
    uint16_t peer_port;
    int retries;
};

static struct {
    /* Outbound queue */
    struct sync_entry queue[MAX_SYNC_QUEUE];
    int queue_head;
    int queue_tail;

    /* Socket */
    int sock;
    uint16_t port;

    /* Thread */
    pthread_t sync_thread;
    volatile int running;

    /* Peers */
    uint32_t peer_ips[4];
    uint16_t peer_ports[4];
    int peer_count;

    /* Stats */
    uint64_t msgs_sent;
    uint64_t msgs_received;
    uint64_t msgs_failed;

    pthread_mutex_t lock;
} g_sync = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static void *sync_thread_func(void *arg)
{
    (void)arg;
    char buf[sizeof(struct acct_sync_msg)];
    struct sockaddr_in from;
    socklen_t from_len;

    while (g_sync.running) {
        /* Check for incoming messages */
        from_len = sizeof(from);
        ssize_t n = recvfrom(g_sync.sock, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &from_len);

        if (n == sizeof(struct acct_sync_msg)) {
            struct acct_sync_msg *msg = (struct acct_sync_msg *)buf;
            if (ntohl(msg->magic) == SYNC_MAGIC) {
                g_sync.msgs_received++;
                YLOG_DEBUG("HA Sync: Received %s for session %u",
                           msg->msg_type == SYNC_MSG_ACCT_START ? "START" :
                           msg->msg_type == SYNC_MSG_ACCT_STOP ? "STOP" : "UPDATE",
                           ntohs(msg->session_id));
            }
        }

        /* Process outbound queue */
        pthread_mutex_lock(&g_sync.lock);
        while (g_sync.queue_head != g_sync.queue_tail) {
            struct sync_entry *entry = &g_sync.queue[g_sync.queue_head];

            struct sockaddr_in to = {
                .sin_family = AF_INET,
                .sin_port = htons(entry->peer_port),
                .sin_addr.s_addr = htonl(entry->peer_ip)
            };

            ssize_t sent = sendto(g_sync.sock, &entry->msg, sizeof(entry->msg), 0,
                                  (struct sockaddr *)&to, sizeof(to));

            if (sent == sizeof(entry->msg)) {
                g_sync.msgs_sent++;
            } else {
                g_sync.msgs_failed++;
            }

            g_sync.queue_head = (g_sync.queue_head + 1) % MAX_SYNC_QUEUE;
        }
        pthread_mutex_unlock(&g_sync.lock);

        usleep(10000); /* 10ms */
    }

    return NULL;
}

int ha_acct_sync_init(uint16_t port)
{
    memset(&g_sync, 0, sizeof(g_sync) - sizeof(pthread_mutex_t));
    pthread_mutex_init(&g_sync.lock, NULL);

    g_sync.port = port;
    g_sync.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sync.sock < 0) {
        YLOG_ERROR("HA Accounting Sync: Failed to create socket");
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };

    if (bind(g_sync.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        YLOG_ERROR("HA Accounting Sync: Failed to bind port %u", port);
        close(g_sync.sock);
        return -1;
    }

    g_sync.running = 1;
    pthread_create(&g_sync.sync_thread, NULL, sync_thread_func, NULL);

    YLOG_INFO("HA Accounting Sync: Initialized on port %u", port);
    return 0;
}

int ha_acct_sync_add_peer(uint32_t ip, uint16_t port)
{
    if (g_sync.peer_count >= 4) return -1;

    g_sync.peer_ips[g_sync.peer_count] = ip;
    g_sync.peer_ports[g_sync.peer_count] = port;
    g_sync.peer_count++;

    YLOG_INFO("HA Accounting Sync: Added peer %u.%u.%u.%u:%u",
              (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
              (ip >> 8) & 0xFF, ip & 0xFF, port);
    return 0;
}

static void queue_sync_message(struct acct_sync_msg *msg)
{
    pthread_mutex_lock(&g_sync.lock);

    for (int i = 0; i < g_sync.peer_count; i++) {
        int next = (g_sync.queue_tail + 1) % MAX_SYNC_QUEUE;
        if (next != g_sync.queue_head) {
            struct sync_entry *entry = &g_sync.queue[g_sync.queue_tail];
            memcpy(&entry->msg, msg, sizeof(*msg));
            entry->peer_ip = g_sync.peer_ips[i];
            entry->peer_port = g_sync.peer_ports[i];
            entry->retries = 0;
            g_sync.queue_tail = next;
        }
    }

    pthread_mutex_unlock(&g_sync.lock);
}

void ha_acct_sync_start(uint16_t session_id, const char *username, uint32_t client_ip)
{
    struct acct_sync_msg msg = {
        .magic = htonl(SYNC_MAGIC),
        .msg_type = htons(SYNC_MSG_ACCT_START),
        .session_id = htons(session_id),
        .client_ip = htonl(client_ip)
    };

    if (username) {
        strncpy(msg.username, username, sizeof(msg.username) - 1);
    }

    queue_sync_message(&msg);
}

void ha_acct_sync_interim(uint16_t session_id, uint64_t bytes_in, uint64_t bytes_out,
                          uint64_t packets_in, uint64_t packets_out, uint32_t session_time)
{
    struct acct_sync_msg msg = {
        .magic = htonl(SYNC_MAGIC),
        .msg_type = htons(SYNC_MSG_ACCT_INTERIM),
        .session_id = htons(session_id),
        .bytes_in = htobe64(bytes_in),
        .bytes_out = htobe64(bytes_out),
        .packets_in = htobe64(packets_in),
        .packets_out = htobe64(packets_out),
        .session_time = htonl(session_time)
    };

    queue_sync_message(&msg);
}

void ha_acct_sync_stop(uint16_t session_id, uint64_t bytes_in, uint64_t bytes_out,
                       uint32_t session_time)
{
    struct acct_sync_msg msg = {
        .magic = htonl(SYNC_MAGIC),
        .msg_type = htons(SYNC_MSG_ACCT_STOP),
        .session_id = htons(session_id),
        .bytes_in = htobe64(bytes_in),
        .bytes_out = htobe64(bytes_out),
        .session_time = htonl(session_time)
    };

    queue_sync_message(&msg);
}

void ha_acct_sync_stats(uint64_t *sent, uint64_t *received, uint64_t *failed)
{
    if (sent) *sent = g_sync.msgs_sent;
    if (received) *received = g_sync.msgs_received;
    if (failed) *failed = g_sync.msgs_failed;
}

void ha_acct_sync_cleanup(void)
{
    g_sync.running = 0;
    if (g_sync.sync_thread) {
        pthread_join(g_sync.sync_thread, NULL);
    }
    if (g_sync.sock >= 0) {
        close(g_sync.sock);
    }
    pthread_mutex_destroy(&g_sync.lock);

    YLOG_INFO("HA Accounting Sync: Cleanup complete (sent=%lu, recv=%lu, failed=%lu)",
              g_sync.msgs_sent, g_sync.msgs_received, g_sync.msgs_failed);
}
