/**
 * @file acl.c
 * @brief Access Control Lists for Packet Filtering
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "acl.h"
#include "log.h"

#define MAX_ACLS 64
#define MAX_ACL_ENTRIES 256

/* ACL entry */
struct acl_entry {
    acl_action_t action;
    uint8_t protocol;       /* 0 = any */
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port_min;
    uint16_t src_port_max;
    uint16_t dst_port_min;
    uint16_t dst_port_max;
    uint64_t hit_count;
    bool enabled;
};

/* ACL */
struct acl {
    char name[32];
    struct acl_entry entries[MAX_ACL_ENTRIES];
    int entry_count;
    bool enabled;
};

static struct {
    struct acl acls[MAX_ACLS];
    int count;
    pthread_mutex_t lock;
} g_acl = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int acl_init(void)
{
    memset(&g_acl.acls, 0, sizeof(g_acl.acls));
    g_acl.count = 0;
    pthread_mutex_init(&g_acl.lock, NULL);

    YLOG_INFO("ACL: Initialized");
    return 0;
}

int acl_create(const char *name)
{
    if (!name) return -1;

    pthread_mutex_lock(&g_acl.lock);

    /* Check for duplicate */
    for (int i = 0; i < g_acl.count; i++) {
        if (strcmp(g_acl.acls[i].name, name) == 0) {
            pthread_mutex_unlock(&g_acl.lock);
            return i; /* Already exists */
        }
    }

    if (g_acl.count >= MAX_ACLS) {
        pthread_mutex_unlock(&g_acl.lock);
        return -1;
    }

    struct acl *a = &g_acl.acls[g_acl.count];
    snprintf(a->name, sizeof(a->name), "%s", name);
    a->entry_count = 0;
    a->enabled = true;

    int id = g_acl.count;
    g_acl.count++;

    pthread_mutex_unlock(&g_acl.lock);

    YLOG_INFO("ACL: Created '%s' (id=%d)", name, id);
    return id;
}

int acl_delete(const char *name)
{
    pthread_mutex_lock(&g_acl.lock);

    for (int i = 0; i < g_acl.count; i++) {
        if (strcmp(g_acl.acls[i].name, name) == 0) {
            memmove(&g_acl.acls[i], &g_acl.acls[i + 1],
                    (g_acl.count - i - 1) * sizeof(struct acl));
            g_acl.count--;
            pthread_mutex_unlock(&g_acl.lock);
            YLOG_INFO("ACL: Deleted '%s'", name);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_acl.lock);
    return -1;
}

int acl_find(const char *name)
{
    for (int i = 0; i < g_acl.count; i++) {
        if (strcmp(g_acl.acls[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int acl_add_entry(const char *acl_name, acl_action_t action, uint8_t protocol,
                  uint32_t src_ip, uint32_t src_mask,
                  uint32_t dst_ip, uint32_t dst_mask,
                  uint16_t src_port_min, uint16_t src_port_max,
                  uint16_t dst_port_min, uint16_t dst_port_max)
{
    pthread_mutex_lock(&g_acl.lock);

    int acl_id = acl_find(acl_name);
    if (acl_id < 0) {
        pthread_mutex_unlock(&g_acl.lock);
        return -1;
    }

    struct acl *a = &g_acl.acls[acl_id];
    if (a->entry_count >= MAX_ACL_ENTRIES) {
        pthread_mutex_unlock(&g_acl.lock);
        return -1;
    }

    struct acl_entry *e = &a->entries[a->entry_count];
    e->action = action;
    e->protocol = protocol;
    e->src_ip = src_ip;
    e->src_mask = src_mask;
    e->dst_ip = dst_ip;
    e->dst_mask = dst_mask;
    e->src_port_min = src_port_min;
    e->src_port_max = src_port_max;
    e->dst_port_min = dst_port_min;
    e->dst_port_max = dst_port_max;
    e->hit_count = 0;
    e->enabled = true;

    a->entry_count++;

    pthread_mutex_unlock(&g_acl.lock);
    return a->entry_count - 1;
}

acl_action_t acl_check(const char *acl_name, uint8_t protocol,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port)
{
    pthread_mutex_lock(&g_acl.lock);

    int acl_id = acl_find(acl_name);
    if (acl_id < 0) {
        pthread_mutex_unlock(&g_acl.lock);
        return ACL_PERMIT; /* No ACL = permit */
    }

    struct acl *a = &g_acl.acls[acl_id];
    if (!a->enabled) {
        pthread_mutex_unlock(&g_acl.lock);
        return ACL_PERMIT;
    }

    for (int i = 0; i < a->entry_count; i++) {
        struct acl_entry *e = &a->entries[i];
        if (!e->enabled) continue;

        /* Check protocol */
        if (e->protocol != 0 && e->protocol != protocol) continue;

        /* Check source IP */
        if ((src_ip & e->src_mask) != (e->src_ip & e->src_mask)) continue;

        /* Check destination IP */
        if ((dst_ip & e->dst_mask) != (e->dst_ip & e->dst_mask)) continue;

        /* Check source port */
        if (e->src_port_min != 0 || e->src_port_max != 0) {
            if (src_port < e->src_port_min || src_port > e->src_port_max) continue;
        }

        /* Check destination port */
        if (e->dst_port_min != 0 || e->dst_port_max != 0) {
            if (dst_port < e->dst_port_min || dst_port > e->dst_port_max) continue;
        }

        /* Match found */
        e->hit_count++;
        acl_action_t action = e->action;
        pthread_mutex_unlock(&g_acl.lock);
        return action;
    }

    pthread_mutex_unlock(&g_acl.lock);
    return ACL_DENY; /* Implicit deny at end */
}

void acl_show(const char *acl_name)
{
    pthread_mutex_lock(&g_acl.lock);

    if (acl_name) {
        int acl_id = acl_find(acl_name);
        if (acl_id < 0) {
            printf("ACL '%s' not found\n", acl_name);
            pthread_mutex_unlock(&g_acl.lock);
            return;
        }

        struct acl *a = &g_acl.acls[acl_id];
        printf("ACL: %s (%s, %d entries)\n", a->name,
               a->enabled ? "enabled" : "disabled", a->entry_count);
        printf("%-6s %-8s %-8s %-16s %-16s %s\n",
               "Entry", "Action", "Proto", "Source", "Destination", "Hits");

        for (int i = 0; i < a->entry_count; i++) {
            struct acl_entry *e = &a->entries[i];
            char src[32], dst[32];

            struct in_addr s = { .s_addr = htonl(e->src_ip) };
            struct in_addr d = { .s_addr = htonl(e->dst_ip) };
            snprintf(src, sizeof(src), "%s", inet_ntoa(s));
            snprintf(dst, sizeof(dst), "%s", inet_ntoa(d));

            printf("%-6d %-8s %-8u %-16s %-16s %lu\n",
                   i, e->action == ACL_PERMIT ? "permit" : "deny",
                   e->protocol, src, dst, e->hit_count);
        }
    } else {
        /* Show all ACLs */
        printf("ACLs (%d):\n", g_acl.count);
        printf("%-20s %-10s %s\n", "Name", "Status", "Entries");

        for (int i = 0; i < g_acl.count; i++) {
            printf("%-20s %-10s %d\n",
                   g_acl.acls[i].name,
                   g_acl.acls[i].enabled ? "enabled" : "disabled",
                   g_acl.acls[i].entry_count);
        }
    }

    pthread_mutex_unlock(&g_acl.lock);
}

void acl_cleanup(void)
{
    pthread_mutex_destroy(&g_acl.lock);
    g_acl.count = 0;
    YLOG_INFO("ACL: Cleanup complete");
}
