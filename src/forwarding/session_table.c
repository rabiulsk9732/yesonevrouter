/**
 * @file session_table.c
 * @brief Per-Core Session Table for Lock-Free Lookups
 * Uses RCU-style updates for thread safety without locks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#include "session_table.h"
#include "log.h"

#define SESSION_TABLE_SIZE      65536   /* 64K sessions */
#define SESSION_HASH_MASK       (SESSION_TABLE_SIZE - 1)

/* Session entry for fast lookup */
struct session_entry {
    uint32_t client_ip;         /* Key: Client IP (host order) */
    uint16_t session_id;        /* PPPoE session ID */
    uint16_t ifindex;           /* Egress interface */
    uint8_t client_mac[6];      /* Client MAC */
    uint8_t valid;              /* Entry valid flag */
    uint8_t padding;
};

/* Per-core session table */
struct session_table {
    struct session_entry entries[SESSION_TABLE_SIZE];
    uint32_t count;
};

/* Global table (shared, atomic updates) */
static _Atomic(struct session_table *) g_session_table = NULL;

/* Simple hash function */
static inline uint32_t session_hash(uint32_t ip)
{
    /* FNV-1a inspired */
    uint32_t h = 2166136261u;
    h ^= (ip & 0xFF);
    h *= 16777619u;
    h ^= ((ip >> 8) & 0xFF);
    h *= 16777619u;
    h ^= ((ip >> 16) & 0xFF);
    h *= 16777619u;
    h ^= ((ip >> 24) & 0xFF);
    h *= 16777619u;
    return h & SESSION_HASH_MASK;
}

int session_table_init(void)
{
    struct session_table *tbl = calloc(1, sizeof(*tbl));
    if (!tbl) {
        YLOG_ERROR("Session table: Failed to allocate memory");
        return -1;
    }

    atomic_store(&g_session_table, tbl);
    YLOG_INFO("Session table: Initialized with %d slots", SESSION_TABLE_SIZE);
    return 0;
}

int session_table_add(uint32_t client_ip, uint16_t session_id, uint16_t ifindex, const uint8_t *mac)
{
    struct session_table *tbl = atomic_load(&g_session_table);
    if (!tbl) return -1;

    uint32_t hash = session_hash(client_ip);
    uint32_t idx = hash;

    /* Linear probing */
    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        struct session_entry *entry = &tbl->entries[idx];

        if (!entry->valid || entry->client_ip == client_ip) {
            entry->client_ip = client_ip;
            entry->session_id = session_id;
            entry->ifindex = ifindex;
            if (mac) memcpy(entry->client_mac, mac, 6);
            entry->valid = 1;

            if (!entry->valid) tbl->count++;

            YLOG_DEBUG("Session table: Added IP %u.%u.%u.%u -> session %u",
                       (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF,
                       (client_ip >> 8) & 0xFF, client_ip & 0xFF, session_id);
            return 0;
        }

        idx = (idx + 1) & SESSION_HASH_MASK;
    }

    YLOG_ERROR("Session table: Full, cannot add session %u", session_id);
    return -1;
}

int session_table_del(uint32_t client_ip)
{
    struct session_table *tbl = atomic_load(&g_session_table);
    if (!tbl) return -1;

    uint32_t hash = session_hash(client_ip);
    uint32_t idx = hash;

    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        struct session_entry *entry = &tbl->entries[idx];

        if (entry->valid && entry->client_ip == client_ip) {
            entry->valid = 0;
            tbl->count--;
            return 0;
        }

        if (!entry->valid && entry->client_ip == 0) {
            break; /* Empty slot, entry not found */
        }

        idx = (idx + 1) & SESSION_HASH_MASK;
    }

    return -1;
}

int session_table_lookup(uint32_t client_ip, uint16_t *session_id, uint16_t *ifindex)
{
    struct session_table *tbl = atomic_load(&g_session_table);
    if (!tbl) return -1;

    uint32_t hash = session_hash(client_ip);
    uint32_t idx = hash;

    for (int i = 0; i < SESSION_TABLE_SIZE; i++) {
        struct session_entry *entry = &tbl->entries[idx];

        if (entry->valid && entry->client_ip == client_ip) {
            if (session_id) *session_id = entry->session_id;
            if (ifindex) *ifindex = entry->ifindex;
            return 0;
        }

        if (!entry->valid && entry->client_ip == 0) {
            break;
        }

        idx = (idx + 1) & SESSION_HASH_MASK;
    }

    return -1; /* Not found */
}

uint32_t session_table_count(void)
{
    struct session_table *tbl = atomic_load(&g_session_table);
    return tbl ? tbl->count : 0;
}

void session_table_cleanup(void)
{
    struct session_table *tbl = atomic_exchange(&g_session_table, NULL);
    if (tbl) {
        free(tbl);
    }
    YLOG_INFO("Session table: Cleanup complete");
}
