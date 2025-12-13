/**
 * @file vrf.c
 * @brief VRF (Virtual Routing and Forwarding) Implementation
 * @details Supports multiple routing tables and L3VPN
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "routing_table.h"
#include "log.h"

/*============================================================================
 * VRF Configuration
 *============================================================================*/

#define VRF_MAX_INSTANCES   256
#define VRF_NAME_MAX        32

/*============================================================================
 * VRF Structure
 *============================================================================*/

struct vrf {
    char name[VRF_NAME_MAX];
    uint32_t id;                    /* VRF ID / Table ID */
    uint64_t rd;                    /* Route Distinguisher */
    struct routing_table *table;    /* Per-VRF routing table */
    uint32_t *interfaces;           /* Bound interfaces */
    int interface_count;
    bool enabled;

    /* Statistics */
    uint64_t packets_in;
    uint64_t packets_out;
};

static struct {
    struct vrf *vrfs[VRF_MAX_INSTANCES];
    int count;
    struct vrf *default_vrf;
    pthread_mutex_t lock;
} g_vrf = {
    .count = 0,
    .default_vrf = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/*============================================================================
 * VRF Functions
 *============================================================================*/

int vrf_init(void)
{
    memset(g_vrf.vrfs, 0, sizeof(g_vrf.vrfs));
    g_vrf.count = 0;

    /* Create default VRF */
    g_vrf.default_vrf = calloc(1, sizeof(struct vrf));
    if (!g_vrf.default_vrf) return -1;

    snprintf(g_vrf.default_vrf->name, VRF_NAME_MAX, "default");
    g_vrf.default_vrf->id = 0;
    g_vrf.default_vrf->table = routing_table_init();
    g_vrf.default_vrf->enabled = true;

    g_vrf.vrfs[0] = g_vrf.default_vrf;
    g_vrf.count = 1;

    YLOG_INFO("VRF subsystem initialized (max %d instances)", VRF_MAX_INSTANCES);
    return 0;
}

struct vrf *vrf_create(const char *name, uint32_t id)
{
    if (!name) return NULL;

    pthread_mutex_lock(&g_vrf.lock);

    /* Check for duplicate */
    for (int i = 0; i < g_vrf.count; i++) {
        if (g_vrf.vrfs[i] && strcmp(g_vrf.vrfs[i]->name, name) == 0) {
            pthread_mutex_unlock(&g_vrf.lock);
            return g_vrf.vrfs[i];
        }
    }

    if (g_vrf.count >= VRF_MAX_INSTANCES) {
        pthread_mutex_unlock(&g_vrf.lock);
        return NULL;
    }

    struct vrf *v = calloc(1, sizeof(*v));
    if (!v) {
        pthread_mutex_unlock(&g_vrf.lock);
        return NULL;
    }

    snprintf(v->name, VRF_NAME_MAX, "%s", name);
    v->id = (id > 0) ? id : g_vrf.count;
    v->table = routing_table_init();
    v->enabled = true;

    g_vrf.vrfs[g_vrf.count++] = v;

    pthread_mutex_unlock(&g_vrf.lock);

    YLOG_INFO("VRF: Created '%s' (ID %u)", name, v->id);
    return v;
}

struct vrf *vrf_lookup(const char *name)
{
    pthread_mutex_lock(&g_vrf.lock);
    for (int i = 0; i < g_vrf.count; i++) {
        if (g_vrf.vrfs[i] && strcmp(g_vrf.vrfs[i]->name, name) == 0) {
            pthread_mutex_unlock(&g_vrf.lock);
            return g_vrf.vrfs[i];
        }
    }
    pthread_mutex_unlock(&g_vrf.lock);
    return NULL;
}

struct vrf *vrf_lookup_by_id(uint32_t id)
{
    pthread_mutex_lock(&g_vrf.lock);
    for (int i = 0; i < g_vrf.count; i++) {
        if (g_vrf.vrfs[i] && g_vrf.vrfs[i]->id == id) {
            pthread_mutex_unlock(&g_vrf.lock);
            return g_vrf.vrfs[i];
        }
    }
    pthread_mutex_unlock(&g_vrf.lock);
    return NULL;
}

struct vrf *vrf_get_default(void)
{
    return g_vrf.default_vrf;
}

int vrf_bind_interface(struct vrf *v, uint32_t ifindex)
{
    if (!v) return -1;

    /* Reallocate interface array */
    v->interfaces = realloc(v->interfaces,
                            (v->interface_count + 1) * sizeof(uint32_t));
    if (!v->interfaces) return -1;

    v->interfaces[v->interface_count++] = ifindex;
    YLOG_INFO("VRF '%s': Bound interface %u", v->name, ifindex);
    return 0;
}

struct routing_table *vrf_get_table(struct vrf *v)
{
    return v ? v->table : (g_vrf.default_vrf ? g_vrf.default_vrf->table : NULL);
}

void vrf_set_rd(struct vrf *v, uint64_t rd)
{
    if (v) v->rd = rd;
}

void vrf_print(void)
{
    pthread_mutex_lock(&g_vrf.lock);

    printf("VRF Instances (%d):\n", g_vrf.count);
    printf("%-20s %-8s %-16s %-10s %s\n", "Name", "ID", "RD", "Routes", "Status");

    for (int i = 0; i < g_vrf.count; i++) {
        struct vrf *v = g_vrf.vrfs[i];
        if (!v) continue;

        uint64_t lookups, hits, misses, rib, fib;
        routing_table_get_stats(v->table, &lookups, &hits, &misses, &rib, &fib);

        printf("%-20s %-8u %lu:%-8lu %-10lu %s\n",
               v->name, v->id, v->rd >> 32, v->rd & 0xFFFFFFFF,
               rib, v->enabled ? "enabled" : "disabled");
    }

    pthread_mutex_unlock(&g_vrf.lock);
}

void vrf_cleanup(void)
{
    pthread_mutex_lock(&g_vrf.lock);

    for (int i = 0; i < g_vrf.count; i++) {
        if (g_vrf.vrfs[i]) {
            if (g_vrf.vrfs[i]->table) {
                routing_table_cleanup(g_vrf.vrfs[i]->table);
            }
            free(g_vrf.vrfs[i]->interfaces);
            free(g_vrf.vrfs[i]);
        }
    }
    g_vrf.count = 0;
    g_vrf.default_vrf = NULL;

    pthread_mutex_unlock(&g_vrf.lock);
    YLOG_INFO("VRF cleanup complete");
}
