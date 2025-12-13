/**
 * @file pppoe_security.c
 * @brief PPPoE Security Module - Anti-flood, MAC binding, Hijack detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>

#include "pppoe_security.h"
#include "pppoe.h"
#include "log.h"

/* Security Configuration */
static struct {
    /* Anti-flood */
    uint32_t padi_rate_limit;       /* Max PADI per second globally */
    uint32_t session_rate_limit;    /* Max sessions per MAC per minute */

    /* Current counters */
    uint32_t padi_count;
    uint64_t padi_window_start;

    /* MAC rate limit table */
    struct mac_rate_entry {
        struct rte_ether_addr mac;
        uint32_t session_count;
        uint64_t window_start;
        struct mac_rate_entry *next;
    } *mac_rate_table[256];

    /* Bound MAC table (session_id -> MAC) */
    struct mac_binding {
        uint16_t session_id;
        struct rte_ether_addr bound_mac;
        uint32_t bound_ip;
        struct mac_binding *next;
    } *bindings[256];

    bool enabled;
} g_security = {
    .padi_rate_limit = 1000,      /* 1000 PADI/sec */
    .session_rate_limit = 5,      /* 5 sessions/MAC/minute */
    .enabled = true
};

/**
 * Initialize security module
 */
int pppoe_security_init(void)
{
    memset(g_security.mac_rate_table, 0, sizeof(g_security.mac_rate_table));
    memset(g_security.bindings, 0, sizeof(g_security.bindings));
    g_security.padi_count = 0;
    g_security.padi_window_start = time(NULL);

    YLOG_INFO("PPPoE Security module initialized (PADI limit: %u/s, Session limit: %u/MAC/min)",
              g_security.padi_rate_limit, g_security.session_rate_limit);
    return 0;
}

/**
 * Check PADI rate limit (anti-PADI flood)
 * @return true if allowed, false if rate limited
 */
bool pppoe_security_check_padi(const struct rte_ether_addr *src_mac)
{
    if (!g_security.enabled) return true;

    uint64_t now = time(NULL);

    /* Reset counter every second */
    if (now != g_security.padi_window_start) {
        g_security.padi_count = 0;
        g_security.padi_window_start = now;
    }

    g_security.padi_count++;

    if (g_security.padi_count > g_security.padi_rate_limit) {
        YLOG_WARNING("PADI flood detected! Rate limit exceeded (%u/s)",
                     g_security.padi_rate_limit);
        return false;
    }

    /* Also check per-MAC rate */
    uint8_t hash = src_mac->addr_bytes[5];
    struct mac_rate_entry *entry = g_security.mac_rate_table[hash];

    while (entry) {
        if (rte_is_same_ether_addr(&entry->mac, src_mac)) {
            /* Reset if window expired (60 seconds) */
            if (now - entry->window_start >= 60) {
                entry->session_count = 0;
                entry->window_start = now;
            }
            entry->session_count++;

            if (entry->session_count > g_security.session_rate_limit) {
                YLOG_WARNING("Session flood from %02x:%02x:%02x:%02x:%02x:%02x",
                             src_mac->addr_bytes[0], src_mac->addr_bytes[1],
                             src_mac->addr_bytes[2], src_mac->addr_bytes[3],
                             src_mac->addr_bytes[4], src_mac->addr_bytes[5]);
                return false;
            }
            return true;
        }
        entry = entry->next;
    }

    /* New MAC, create entry */
    entry = calloc(1, sizeof(*entry));
    if (entry) {
        rte_ether_addr_copy(src_mac, &entry->mac);
        entry->session_count = 1;
        entry->window_start = now;
        entry->next = g_security.mac_rate_table[hash];
        g_security.mac_rate_table[hash] = entry;
    }

    return true;
}

/**
 * Bind session to MAC and IP
 */
void pppoe_security_bind_session(uint16_t session_id, const struct rte_ether_addr *mac, uint32_t ip)
{
    uint8_t hash = session_id & 0xFF;

    struct mac_binding *binding = calloc(1, sizeof(*binding));
    if (!binding) return;

    binding->session_id = session_id;
    rte_ether_addr_copy(mac, &binding->bound_mac);
    binding->bound_ip = ip;
    binding->next = g_security.bindings[hash];
    g_security.bindings[hash] = binding;

    YLOG_DEBUG("Session %u bound to MAC %02x:%02x:%02x:%02x:%02x:%02x IP %u.%u.%u.%u",
               session_id,
               mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
               mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5],
               (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

/**
 * Unbind session
 */
void pppoe_security_unbind_session(uint16_t session_id)
{
    uint8_t hash = session_id & 0xFF;
    struct mac_binding **pp = &g_security.bindings[hash];

    while (*pp) {
        if ((*pp)->session_id == session_id) {
            struct mac_binding *old = *pp;
            *pp = (*pp)->next;
            free(old);
            return;
        }
        pp = &(*pp)->next;
    }
}

/**
 * Validate session packet (MAC binding + IP spoof detection)
 * @return true if valid, false if hijack/spoof detected
 */
bool pppoe_security_validate_packet(uint16_t session_id, const struct rte_ether_addr *src_mac, uint32_t src_ip)
{
    if (!g_security.enabled) return true;

    uint8_t hash = session_id & 0xFF;
    struct mac_binding *binding = g_security.bindings[hash];

    while (binding) {
        if (binding->session_id == session_id) {
            /* Check MAC */
            if (!rte_is_same_ether_addr(&binding->bound_mac, src_mac)) {
                YLOG_WARNING("Session hijack detected! Session %u MAC mismatch", session_id);
                return false;
            }

            /* Check IP */
            if (src_ip != 0 && binding->bound_ip != 0 && src_ip != binding->bound_ip) {
                YLOG_WARNING("IP spoof detected! Session %u expected %u.%u.%u.%u got %u.%u.%u.%u",
                             session_id,
                             (binding->bound_ip >> 24) & 0xFF, (binding->bound_ip >> 16) & 0xFF,
                             (binding->bound_ip >> 8) & 0xFF, binding->bound_ip & 0xFF,
                             (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                             (src_ip >> 8) & 0xFF, src_ip & 0xFF);
                return false;
            }
            return true;
        }
        binding = binding->next;
    }

    /* No binding found - allow for now (binding happens after IP assignment) */
    return true;
}

/**
 * Configure security settings
 */
void pppoe_security_config(uint32_t padi_limit, uint32_t session_limit)
{
    g_security.padi_rate_limit = padi_limit;
    g_security.session_rate_limit = session_limit;
    YLOG_INFO("Security config: PADI limit %u/s, Session limit %u/MAC/min",
              padi_limit, session_limit);
}

/**
 * Enable/disable security
 */
void pppoe_security_enable(bool enable)
{
    g_security.enabled = enable;
    YLOG_INFO("PPPoE Security %s", enable ? "enabled" : "disabled");
}

/**
 * Get security statistics
 */
void pppoe_security_stats(uint32_t *padi_count, uint32_t *blocked_count)
{
    if (padi_count) *padi_count = g_security.padi_count;
    if (blocked_count) *blocked_count = 0; /* TODO: Track blocked count */
}

/**
 * Cleanup security module
 */
void pppoe_security_cleanup(void)
{
    /* Free MAC rate table */
    for (int i = 0; i < 256; i++) {
        struct mac_rate_entry *entry = g_security.mac_rate_table[i];
        while (entry) {
            struct mac_rate_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        g_security.mac_rate_table[i] = NULL;
    }

    /* Free bindings */
    for (int i = 0; i < 256; i++) {
        struct mac_binding *binding = g_security.bindings[i];
        while (binding) {
            struct mac_binding *next = binding->next;
            free(binding);
            binding = next;
        }
        g_security.bindings[i] = NULL;
    }

    YLOG_INFO("PPPoE Security module cleanup complete");
}
