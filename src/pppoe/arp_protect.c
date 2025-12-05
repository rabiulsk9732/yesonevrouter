/**
 * @file arp_protect.c
 * @brief ARP Protection and Anti-Spoofing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp_protect.h"
#include "log.h"

#define MAX_ARP_ENTRIES 65536

/* ARP binding table */
struct arp_entry {
    uint32_t ip;            /* Host order */
    uint8_t mac[6];
    uint16_t session_id;
    bool valid;
};

static struct {
    struct arp_entry *entries;
    int count;
    bool enabled;

    /* Stats */
    uint64_t arp_requests;
    uint64_t arp_replies;
    uint64_t spoofs_detected;
    uint64_t dropped;
} g_arp = {
    .entries = NULL,
    .count = 0,
    .enabled = true
};

int arp_protect_init(void)
{
    g_arp.entries = calloc(MAX_ARP_ENTRIES, sizeof(struct arp_entry));
    if (!g_arp.entries) {
        YLOG_ERROR("ARP Protect: Failed to allocate memory");
        return -1;
    }

    g_arp.count = 0;
    g_arp.enabled = true;

    YLOG_INFO("ARP Protect: Initialized (max %d entries)", MAX_ARP_ENTRIES);
    return 0;
}

int arp_protect_add_binding(uint32_t ip, const uint8_t *mac, uint16_t session_id)
{
    if (!g_arp.entries || !mac) return -1;

    /* Check for existing */
    for (int i = 0; i < g_arp.count; i++) {
        if (g_arp.entries[i].valid && g_arp.entries[i].ip == ip) {
            /* Update existing */
            memcpy(g_arp.entries[i].mac, mac, 6);
            g_arp.entries[i].session_id = session_id;
            return 0;
        }
    }

    /* Find free slot */
    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (!g_arp.entries[i].valid) {
            g_arp.entries[i].ip = ip;
            memcpy(g_arp.entries[i].mac, mac, 6);
            g_arp.entries[i].session_id = session_id;
            g_arp.entries[i].valid = true;
            g_arp.count++;

            YLOG_DEBUG("ARP Protect: Bound %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x",
                       (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF, ip & 0xFF,
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return 0;
        }
    }

    YLOG_ERROR("ARP Protect: Table full");
    return -1;
}

void arp_protect_del_binding(uint32_t ip)
{
    if (!g_arp.entries) return;

    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (g_arp.entries[i].valid && g_arp.entries[i].ip == ip) {
            g_arp.entries[i].valid = false;
            g_arp.count--;
            return;
        }
    }
}

void arp_protect_del_by_session(uint16_t session_id)
{
    if (!g_arp.entries) return;

    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (g_arp.entries[i].valid && g_arp.entries[i].session_id == session_id) {
            g_arp.entries[i].valid = false;
            g_arp.count--;
        }
    }
}

arp_result_t arp_protect_validate(uint32_t ip, const uint8_t *mac)
{
    if (!g_arp.enabled || !g_arp.entries || !mac) {
        return ARP_RESULT_PASS;
    }

    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (g_arp.entries[i].valid && g_arp.entries[i].ip == ip) {
            /* Found binding - check MAC */
            if (memcmp(g_arp.entries[i].mac, mac, 6) == 0) {
                return ARP_RESULT_PASS;
            } else {
                /* MAC mismatch - spoof detected */
                g_arp.spoofs_detected++;
                YLOG_WARNING("ARP Spoof: IP %u.%u.%u.%u claimed by %02x:%02x:%02x:%02x:%02x:%02x "
                             "(bound to %02x:%02x:%02x:%02x:%02x:%02x)",
                             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                             g_arp.entries[i].mac[0], g_arp.entries[i].mac[1],
                             g_arp.entries[i].mac[2], g_arp.entries[i].mac[3],
                             g_arp.entries[i].mac[4], g_arp.entries[i].mac[5]);
                return ARP_RESULT_SPOOF;
            }
        }
    }

    /* No binding found - unknown IP */
    return ARP_RESULT_UNKNOWN;
}

void arp_protect_enable(bool enable)
{
    g_arp.enabled = enable;
    YLOG_INFO("ARP Protect: %s", enable ? "enabled" : "disabled");
}

void arp_protect_stats(uint64_t *requests, uint64_t *replies, uint64_t *spoofs, uint64_t *dropped)
{
    if (requests) *requests = g_arp.arp_requests;
    if (replies) *replies = g_arp.arp_replies;
    if (spoofs) *spoofs = g_arp.spoofs_detected;
    if (dropped) *dropped = g_arp.dropped;
}

void arp_protect_cleanup(void)
{
    if (g_arp.entries) {
        free(g_arp.entries);
        g_arp.entries = NULL;
    }
    g_arp.count = 0;
    YLOG_INFO("ARP Protect: Cleanup complete");
}
