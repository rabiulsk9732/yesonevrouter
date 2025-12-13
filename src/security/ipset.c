/**
 * @file ipset.c
 * @brief IP Set Implementation for Large-Scale IP Filtering
 * @details Hash-based IP set with O(1) lookup, supports 1M+ entries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "log.h"

/*============================================================================
 * IP Set Configuration
 *============================================================================*/

#define IPSET_MAX_SETS          64
#define IPSET_HASH_SIZE         65536   /* 64K buckets */
#define IPSET_MAX_ENTRIES       1048576 /* 1M entries per set */

/*============================================================================
 * Hash Functions
 *============================================================================*/

static inline uint32_t ipset_hash_ip(uint32_t ip)
{
    /* FNV-1a hash for IPv4 */
    uint32_t hash = 2166136261u;
    hash ^= (ip & 0xFF); hash *= 16777619u;
    hash ^= ((ip >> 8) & 0xFF); hash *= 16777619u;
    hash ^= ((ip >> 16) & 0xFF); hash *= 16777619u;
    hash ^= ((ip >> 24) & 0xFF); hash *= 16777619u;
    return hash % IPSET_HASH_SIZE;
}

static inline uint32_t ipset_hash_net(uint32_t ip, uint8_t prefix)
{
    uint32_t mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    return ipset_hash_ip(ip & mask);
}

/*============================================================================
 * IP Set Structures
 *============================================================================*/

enum ipset_type {
    IPSET_TYPE_HASH_IP,     /* Single IPs */
    IPSET_TYPE_HASH_NET,    /* IP/prefix networks */
    IPSET_TYPE_HASH_IPPORT  /* IP:port pairs */
};

struct ipset_entry {
    uint32_t ip;
    uint8_t  prefix;        /* 32 for single IP, < 32 for network */
    uint16_t port;          /* For hash:ip,port */
    uint8_t  protocol;      /* For hash:ip,port */
    uint64_t timeout;       /* Expiry time (0 = permanent) */
    struct ipset_entry *next;
};

struct ipset {
    char name[32];
    enum ipset_type type;
    struct ipset_entry *buckets[IPSET_HASH_SIZE];
    uint32_t entry_count;
    uint32_t max_entries;
    pthread_rwlock_t lock;
    bool enabled;

    /* Statistics */
    uint64_t lookups;
    uint64_t hits;
    uint64_t misses;
};

static struct {
    struct ipset *sets[IPSET_MAX_SETS];
    int count;
    pthread_mutex_t lock;
} g_ipset = {
    .count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/*============================================================================
 * IP Set Functions
 *============================================================================*/

int ipset_init(void)
{
    memset(&g_ipset.sets, 0, sizeof(g_ipset.sets));
    g_ipset.count = 0;
    YLOG_INFO("IP Set subsystem initialized");
    return 0;
}

int ipset_create(const char *name, enum ipset_type type, uint32_t max_entries)
{
    if (!name) return -1;

    pthread_mutex_lock(&g_ipset.lock);

    /* Check for duplicate */
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            pthread_mutex_unlock(&g_ipset.lock);
            return i;
        }
    }

    if (g_ipset.count >= IPSET_MAX_SETS) {
        pthread_mutex_unlock(&g_ipset.lock);
        return -1;
    }

    struct ipset *set = calloc(1, sizeof(*set));
    if (!set) {
        pthread_mutex_unlock(&g_ipset.lock);
        return -1;
    }

    snprintf(set->name, sizeof(set->name), "%s", name);
    set->type = type;
    set->max_entries = max_entries > 0 ? max_entries : IPSET_MAX_ENTRIES;
    set->enabled = true;
    pthread_rwlock_init(&set->lock, NULL);

    int id = g_ipset.count;
    g_ipset.sets[g_ipset.count++] = set;

    pthread_mutex_unlock(&g_ipset.lock);

    YLOG_INFO("IP Set: Created '%s' (type=%d, max=%u)", name, type, set->max_entries);
    return id;
}

int ipset_add_ip(const char *name, uint32_t ip)
{
    return ipset_add_net(name, ip, 32);
}

int ipset_add_net(const char *name, uint32_t ip, uint8_t prefix)
{
    struct ipset *set = NULL;

    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            set = g_ipset.sets[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_ipset.lock);

    if (!set) return -1;

    pthread_rwlock_wrlock(&set->lock);

    if (set->entry_count >= set->max_entries) {
        pthread_rwlock_unlock(&set->lock);
        return -1;
    }

    uint32_t hash = (set->type == IPSET_TYPE_HASH_NET) ?
                    ipset_hash_net(ip, prefix) : ipset_hash_ip(ip);

    /* Check for duplicate */
    for (struct ipset_entry *e = set->buckets[hash]; e; e = e->next) {
        if (e->ip == ip && e->prefix == prefix) {
            pthread_rwlock_unlock(&set->lock);
            return 0;  /* Already exists */
        }
    }

    struct ipset_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_rwlock_unlock(&set->lock);
        return -1;
    }

    entry->ip = ip;
    entry->prefix = prefix;
    entry->next = set->buckets[hash];
    set->buckets[hash] = entry;
    set->entry_count++;

    pthread_rwlock_unlock(&set->lock);
    return 0;
}

int ipset_del_ip(const char *name, uint32_t ip)
{
    return ipset_del_net(name, ip, 32);
}

int ipset_del_net(const char *name, uint32_t ip, uint8_t prefix)
{
    struct ipset *set = NULL;

    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            set = g_ipset.sets[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_ipset.lock);

    if (!set) return -1;

    pthread_rwlock_wrlock(&set->lock);

    uint32_t hash = (set->type == IPSET_TYPE_HASH_NET) ?
                    ipset_hash_net(ip, prefix) : ipset_hash_ip(ip);

    struct ipset_entry **pp = &set->buckets[hash];
    while (*pp) {
        if ((*pp)->ip == ip && (*pp)->prefix == prefix) {
            struct ipset_entry *del = *pp;
            *pp = del->next;
            free(del);
            set->entry_count--;
            pthread_rwlock_unlock(&set->lock);
            return 0;
        }
        pp = &(*pp)->next;
    }

    pthread_rwlock_unlock(&set->lock);
    return -1;
}

bool ipset_test_ip(const char *name, uint32_t ip)
{
    struct ipset *set = NULL;

    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            set = g_ipset.sets[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_ipset.lock);

    if (!set || !set->enabled) return false;

    pthread_rwlock_rdlock(&set->lock);
    set->lookups++;

    if (set->type == IPSET_TYPE_HASH_IP) {
        /* Exact IP match */
        uint32_t hash = ipset_hash_ip(ip);
        for (struct ipset_entry *e = set->buckets[hash]; e; e = e->next) {
            if (e->ip == ip) {
                set->hits++;
                pthread_rwlock_unlock(&set->lock);
                return true;
            }
        }
    } else if (set->type == IPSET_TYPE_HASH_NET) {
        /* Check all prefix lengths from /32 down to /1 */
        for (int prefix = 32; prefix >= 1; prefix--) {
            uint32_t mask = 0xFFFFFFFF << (32 - prefix);
            uint32_t net = ip & mask;
            uint32_t hash = ipset_hash_net(net, prefix);

            for (struct ipset_entry *e = set->buckets[hash]; e; e = e->next) {
                if (e->prefix == prefix && (e->ip & mask) == net) {
                    set->hits++;
                    pthread_rwlock_unlock(&set->lock);
                    return true;
                }
            }
        }
    }

    set->misses++;
    pthread_rwlock_unlock(&set->lock);
    return false;
}

void ipset_flush(const char *name)
{
    struct ipset *set = NULL;

    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            set = g_ipset.sets[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_ipset.lock);

    if (!set) return;

    pthread_rwlock_wrlock(&set->lock);

    for (int i = 0; i < IPSET_HASH_SIZE; i++) {
        struct ipset_entry *e = set->buckets[i];
        while (e) {
            struct ipset_entry *next = e->next;
            free(e);
            e = next;
        }
        set->buckets[i] = NULL;
    }
    set->entry_count = 0;

    pthread_rwlock_unlock(&set->lock);
    YLOG_INFO("IP Set: Flushed '%s'", name);
}

void ipset_print(const char *name)
{
    struct ipset *set = NULL;

    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i] && strcmp(g_ipset.sets[i]->name, name) == 0) {
            set = g_ipset.sets[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_ipset.lock);

    if (!set) {
        printf("IP Set '%s' not found\n", name);
        return;
    }

    pthread_rwlock_rdlock(&set->lock);

    printf("Name: %s  Type: %s  Entries: %u/%u\n",
           set->name,
           set->type == IPSET_TYPE_HASH_IP ? "hash:ip" :
           set->type == IPSET_TYPE_HASH_NET ? "hash:net" : "hash:ip,port",
           set->entry_count, set->max_entries);
    printf("Lookups: %lu  Hits: %lu  Misses: %lu  Hit%%: %.1f%%\n",
           set->lookups, set->hits, set->misses,
           set->lookups > 0 ? (100.0 * set->hits / set->lookups) : 0.0);

    pthread_rwlock_unlock(&set->lock);
}

void ipset_list_all(void)
{
    pthread_mutex_lock(&g_ipset.lock);
    printf("IP Sets (%d):\n", g_ipset.count);
    printf("%-20s %-12s %-10s %s\n", "Name", "Type", "Entries", "Status");

    for (int i = 0; i < g_ipset.count; i++) {
        struct ipset *s = g_ipset.sets[i];
        if (!s) continue;
        printf("%-20s %-12s %-10u %s\n",
               s->name,
               s->type == IPSET_TYPE_HASH_IP ? "hash:ip" :
               s->type == IPSET_TYPE_HASH_NET ? "hash:net" : "hash:ip,port",
               s->entry_count,
               s->enabled ? "enabled" : "disabled");
    }
    pthread_mutex_unlock(&g_ipset.lock);
}

void ipset_cleanup(void)
{
    pthread_mutex_lock(&g_ipset.lock);
    for (int i = 0; i < g_ipset.count; i++) {
        if (g_ipset.sets[i]) {
            ipset_flush(g_ipset.sets[i]->name);
            pthread_rwlock_destroy(&g_ipset.sets[i]->lock);
            free(g_ipset.sets[i]);
        }
    }
    g_ipset.count = 0;
    pthread_mutex_unlock(&g_ipset.lock);
    YLOG_INFO("IP Set: Cleanup complete");
}
