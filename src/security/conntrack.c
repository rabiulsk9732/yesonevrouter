/**
 * @file conntrack.c
 * @brief Stateful Connection Tracking with Full TCP State Machine
 * @details Implements RFC 6146 connection tracking for stateful filtering
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "log.h"

/*============================================================================
 * Connection Tracking Configuration
 *============================================================================*/

#define CT_HASH_SIZE        65536   /* 64K buckets */
#define CT_MAX_ENTRIES      2000000 /* 2M connections */

/* Timeouts (seconds) */
#define CT_TIMEOUT_TCP_SYN_SENT     120
#define CT_TIMEOUT_TCP_SYN_RECV     60
#define CT_TIMEOUT_TCP_ESTABLISHED  432000  /* 5 days */
#define CT_TIMEOUT_TCP_FIN_WAIT     120
#define CT_TIMEOUT_TCP_CLOSE_WAIT   60
#define CT_TIMEOUT_TCP_LAST_ACK     30
#define CT_TIMEOUT_TCP_TIME_WAIT    120
#define CT_TIMEOUT_TCP_CLOSE        10
#define CT_TIMEOUT_UDP              180
#define CT_TIMEOUT_ICMP             30
#define CT_TIMEOUT_GENERIC          600

/*============================================================================
 * TCP State Machine
 *============================================================================*/

enum tcp_state {
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECV,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE
};

/* TCP flags */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

/*============================================================================
 * Connection Entry
 *============================================================================*/

enum ct_status {
    CT_STATUS_NEW,
    CT_STATUS_ESTABLISHED,
    CT_STATUS_RELATED,
    CT_STATUS_INVALID
};

struct ct_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

struct ct_entry {
    struct ct_tuple orig;       /* Original direction */
    struct ct_tuple reply;      /* Reply direction */

    enum ct_status status;
    enum tcp_state tcp_state;

    uint64_t timeout;           /* Expiry timestamp */
    uint64_t packets[2];        /* Original/Reply packet count */
    uint64_t bytes[2];          /* Original/Reply byte count */

    time_t   created;
    time_t   last_seen;

    struct ct_entry *next;      /* Hash chain */
};

/*============================================================================
 * Connection Tracking Table
 *============================================================================*/

static struct {
    struct ct_entry *buckets[CT_HASH_SIZE];
    uint32_t count;
    pthread_rwlock_t lock;
    bool enabled;

    /* Statistics */
    uint64_t lookups;
    uint64_t hits;
    uint64_t inserts;
    uint64_t deletes;
    uint64_t timeouts;
} g_ct = {
    .count = 0,
    .enabled = false,
    .lock = PTHREAD_RWLOCK_INITIALIZER
};

/*============================================================================
 * Hash Function
 *============================================================================*/

static uint32_t ct_hash(const struct ct_tuple *t)
{
    uint32_t hash = t->src_ip ^ t->dst_ip ^ t->protocol;
    hash ^= (t->src_port << 16) | t->dst_port;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    return hash % CT_HASH_SIZE;
}

/*============================================================================
 * TCP State Machine
 *============================================================================*/

static const char *tcp_state_name(enum tcp_state state)
{
    switch (state) {
        case TCP_STATE_NONE:        return "NONE";
        case TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case TCP_STATE_SYN_RECV:    return "SYN_RECV";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT:    return "FIN_WAIT";
        case TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        case TCP_STATE_CLOSE:       return "CLOSE";
        default:                    return "UNKNOWN";
    }
}

static uint32_t tcp_state_timeout(enum tcp_state state)
{
    switch (state) {
        case TCP_STATE_SYN_SENT:    return CT_TIMEOUT_TCP_SYN_SENT;
        case TCP_STATE_SYN_RECV:    return CT_TIMEOUT_TCP_SYN_RECV;
        case TCP_STATE_ESTABLISHED: return CT_TIMEOUT_TCP_ESTABLISHED;
        case TCP_STATE_FIN_WAIT:    return CT_TIMEOUT_TCP_FIN_WAIT;
        case TCP_STATE_CLOSE_WAIT:  return CT_TIMEOUT_TCP_CLOSE_WAIT;
        case TCP_STATE_LAST_ACK:    return CT_TIMEOUT_TCP_LAST_ACK;
        case TCP_STATE_TIME_WAIT:   return CT_TIMEOUT_TCP_TIME_WAIT;
        case TCP_STATE_CLOSE:       return CT_TIMEOUT_TCP_CLOSE;
        default:                    return CT_TIMEOUT_GENERIC;
    }
}

static enum tcp_state tcp_state_update(enum tcp_state current, uint8_t flags, bool is_reply)
{
    enum tcp_state next = current;

    if (flags & TH_RST) {
        return TCP_STATE_CLOSE;
    }

    switch (current) {
        case TCP_STATE_NONE:
            if ((flags & TH_SYN) && !(flags & TH_ACK)) {
                next = TCP_STATE_SYN_SENT;
            }
            break;

        case TCP_STATE_SYN_SENT:
            if (is_reply && (flags & TH_SYN) && (flags & TH_ACK)) {
                next = TCP_STATE_SYN_RECV;
            }
            break;

        case TCP_STATE_SYN_RECV:
            if (!is_reply && (flags & TH_ACK)) {
                next = TCP_STATE_ESTABLISHED;
            }
            break;

        case TCP_STATE_ESTABLISHED:
            if (flags & TH_FIN) {
                next = is_reply ? TCP_STATE_CLOSE_WAIT : TCP_STATE_FIN_WAIT;
            }
            break;

        case TCP_STATE_FIN_WAIT:
            if (is_reply && (flags & TH_FIN)) {
                next = TCP_STATE_TIME_WAIT;
            } else if (is_reply && (flags & TH_ACK)) {
                next = TCP_STATE_CLOSE_WAIT;
            }
            break;

        case TCP_STATE_CLOSE_WAIT:
            if (!is_reply && (flags & TH_FIN)) {
                next = TCP_STATE_LAST_ACK;
            }
            break;

        case TCP_STATE_LAST_ACK:
            if (is_reply && (flags & TH_ACK)) {
                next = TCP_STATE_TIME_WAIT;
            }
            break;

        case TCP_STATE_TIME_WAIT:
            /* Wait for timeout */
            break;

        default:
            break;
    }

    return next;
}

/*============================================================================
 * Connection Tracking Functions
 *============================================================================*/

int conntrack_init(void)
{
    memset(g_ct.buckets, 0, sizeof(g_ct.buckets));
    g_ct.count = 0;
    g_ct.enabled = true;
    pthread_rwlock_init(&g_ct.lock, NULL);
    YLOG_INFO("Connection tracking initialized (max %u entries)", CT_MAX_ENTRIES);
    return 0;
}

void conntrack_enable(bool enable)
{
    g_ct.enabled = enable;
    YLOG_INFO("Connection tracking %s", enable ? "enabled" : "disabled");
}

struct ct_entry *conntrack_lookup(uint8_t protocol,
                                  uint32_t src_ip, uint16_t src_port,
                                  uint32_t dst_ip, uint16_t dst_port,
                                  bool *is_reply)
{
    if (!g_ct.enabled) return NULL;

    struct ct_tuple orig = {src_ip, dst_ip, src_port, dst_port, protocol};
    struct ct_tuple reply = {dst_ip, src_ip, dst_port, src_port, protocol};

    pthread_rwlock_rdlock(&g_ct.lock);
    g_ct.lookups++;

    /* Check original direction */
    uint32_t hash = ct_hash(&orig);
    for (struct ct_entry *e = g_ct.buckets[hash]; e; e = e->next) {
        if (e->orig.src_ip == src_ip && e->orig.dst_ip == dst_ip &&
            e->orig.src_port == src_port && e->orig.dst_port == dst_port &&
            e->orig.protocol == protocol) {
            g_ct.hits++;
            if (is_reply) *is_reply = false;
            pthread_rwlock_unlock(&g_ct.lock);
            return e;
        }
    }

    /* Check reply direction */
    hash = ct_hash(&reply);
    for (struct ct_entry *e = g_ct.buckets[hash]; e; e = e->next) {
        if (e->orig.src_ip == dst_ip && e->orig.dst_ip == src_ip &&
            e->orig.src_port == dst_port && e->orig.dst_port == src_port &&
            e->orig.protocol == protocol) {
            g_ct.hits++;
            if (is_reply) *is_reply = true;
            pthread_rwlock_unlock(&g_ct.lock);
            return e;
        }
    }

    pthread_rwlock_unlock(&g_ct.lock);
    return NULL;
}

struct ct_entry *conntrack_create(uint8_t protocol,
                                  uint32_t src_ip, uint16_t src_port,
                                  uint32_t dst_ip, uint16_t dst_port)
{
    if (!g_ct.enabled) return NULL;

    pthread_rwlock_wrlock(&g_ct.lock);

    if (g_ct.count >= CT_MAX_ENTRIES) {
        pthread_rwlock_unlock(&g_ct.lock);
        YLOG_WARNING("Conntrack: Table full");
        return NULL;
    }

    struct ct_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_rwlock_unlock(&g_ct.lock);
        return NULL;
    }

    entry->orig.src_ip = src_ip;
    entry->orig.dst_ip = dst_ip;
    entry->orig.src_port = src_port;
    entry->orig.dst_port = dst_port;
    entry->orig.protocol = protocol;

    entry->reply.src_ip = dst_ip;
    entry->reply.dst_ip = src_ip;
    entry->reply.src_port = dst_port;
    entry->reply.dst_port = src_port;
    entry->reply.protocol = protocol;

    entry->status = CT_STATUS_NEW;
    entry->tcp_state = (protocol == 6) ? TCP_STATE_NONE : TCP_STATE_NONE;
    entry->created = time(NULL);
    entry->last_seen = entry->created;

    /* Set initial timeout */
    uint32_t timeout;
    switch (protocol) {
        case 6:  timeout = CT_TIMEOUT_TCP_SYN_SENT; break;
        case 17: timeout = CT_TIMEOUT_UDP; break;
        case 1:  timeout = CT_TIMEOUT_ICMP; break;
        default: timeout = CT_TIMEOUT_GENERIC;
    }
    entry->timeout = entry->created + timeout;

    /* Insert into hash table */
    uint32_t hash = ct_hash(&entry->orig);
    entry->next = g_ct.buckets[hash];
    g_ct.buckets[hash] = entry;
    g_ct.count++;
    g_ct.inserts++;

    pthread_rwlock_unlock(&g_ct.lock);
    return entry;
}

void conntrack_update(struct ct_entry *entry, uint32_t pkt_len,
                      uint8_t tcp_flags, bool is_reply)
{
    if (!entry) return;

    entry->last_seen = time(NULL);
    entry->packets[is_reply ? 1 : 0]++;
    entry->bytes[is_reply ? 1 : 0] += pkt_len;

    /* Update status */
    if (entry->status == CT_STATUS_NEW && is_reply) {
        entry->status = CT_STATUS_ESTABLISHED;
    }

    /* Update TCP state */
    if (entry->orig.protocol == 6) {
        enum tcp_state old_state = entry->tcp_state;
        entry->tcp_state = tcp_state_update(entry->tcp_state, tcp_flags, is_reply);

        if (old_state != entry->tcp_state) {
            YLOG_DEBUG("Conntrack: TCP %s -> %s",
                       tcp_state_name(old_state), tcp_state_name(entry->tcp_state));
        }

        entry->timeout = entry->last_seen + tcp_state_timeout(entry->tcp_state);
    } else {
        /* UDP/ICMP: refresh timeout */
        uint32_t timeout = (entry->orig.protocol == 17) ? CT_TIMEOUT_UDP : CT_TIMEOUT_ICMP;
        entry->timeout = entry->last_seen + timeout;
    }
}

void conntrack_delete(struct ct_entry *entry)
{
    if (!entry) return;

    pthread_rwlock_wrlock(&g_ct.lock);

    uint32_t hash = ct_hash(&entry->orig);
    struct ct_entry **pp = &g_ct.buckets[hash];

    while (*pp) {
        if (*pp == entry) {
            *pp = entry->next;
            free(entry);
            g_ct.count--;
            g_ct.deletes++;
            break;
        }
        pp = &(*pp)->next;
    }

    pthread_rwlock_unlock(&g_ct.lock);
}

void conntrack_expire(void)
{
    time_t now = time(NULL);

    pthread_rwlock_wrlock(&g_ct.lock);

    for (int i = 0; i < CT_HASH_SIZE; i++) {
        struct ct_entry **pp = &g_ct.buckets[i];
        while (*pp) {
            if ((*pp)->timeout <= (uint64_t)now) {
                struct ct_entry *del = *pp;
                *pp = del->next;
                free(del);
                g_ct.count--;
                g_ct.timeouts++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    pthread_rwlock_unlock(&g_ct.lock);
}

void conntrack_print_stats(void)
{
    printf("Connection Tracking Statistics\n");
    printf("==============================\n");
    printf("Enabled:    %s\n", g_ct.enabled ? "yes" : "no");
    printf("Entries:    %u / %u\n", g_ct.count, CT_MAX_ENTRIES);
    printf("Lookups:    %lu\n", g_ct.lookups);
    printf("Hits:       %lu (%.1f%%)\n", g_ct.hits,
           g_ct.lookups > 0 ? (100.0 * g_ct.hits / g_ct.lookups) : 0.0);
    printf("Inserts:    %lu\n", g_ct.inserts);
    printf("Deletes:    %lu\n", g_ct.deletes);
    printf("Timeouts:   %lu\n", g_ct.timeouts);
}

void conntrack_cleanup(void)
{
    pthread_rwlock_wrlock(&g_ct.lock);

    for (int i = 0; i < CT_HASH_SIZE; i++) {
        struct ct_entry *e = g_ct.buckets[i];
        while (e) {
            struct ct_entry *next = e->next;
            free(e);
            e = next;
        }
        g_ct.buckets[i] = NULL;
    }
    g_ct.count = 0;

    pthread_rwlock_unlock(&g_ct.lock);
    YLOG_INFO("Conntrack: Cleanup complete");
}
