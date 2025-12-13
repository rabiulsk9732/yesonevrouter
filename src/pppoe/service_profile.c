/**
 * @file service_profile.c
 * @brief PPPoE Service Profile Management (Enhanced)
 *
 * Supports: interface binding, multiple service-names, pool name
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "service_profile.h"
#include "log.h"

#define MAX_SERVICE_PROFILES 64

/* Internal service profile entry */
struct service_profile {
    char name[32];

    /* Interface binding */
    char iface_name[32];
    uint16_t vlan_id;

    /* AC-Name (empty = use global) */
    char ac_name[64];

    /* Pool name */
    char pool_name[32];

    /* Multiple service-names */
    char service_names[MAX_SERVICE_NAMES][32];
    int num_service_names;

    /* QoS */
    uint64_t cir_up;
    uint64_t cir_down;
    uint64_t mir_up;
    uint64_t mir_down;

    /* Timeouts */
    uint32_t session_timeout;
    uint32_t idle_timeout;

    bool enabled;
};

static struct {
    struct service_profile profiles[MAX_SERVICE_PROFILES];
    int count;
    int default_profile;
} g_svc_ctx = {
    .count = 0,
    .default_profile = -1
};

/* Helper: find profile index by name */
static int find_profile_idx(const char *name) {
    for (int i = 0; i < g_svc_ctx.count; i++) {
        if (strcmp(g_svc_ctx.profiles[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int service_profile_init(void)
{
    memset(&g_svc_ctx, 0, sizeof(g_svc_ctx));
    g_svc_ctx.default_profile = -1;

    /* Create default profile */
    service_profile_create("default");
    service_profile_set_default("default");

    YLOG_INFO("Service Profile: Initialized");
    return 0;
}

int service_profile_create(const char *name)
{
    if (!name || g_svc_ctx.count >= MAX_SERVICE_PROFILES) {
        return -1;
    }

    /* Check for duplicate */
    if (find_profile_idx(name) >= 0) {
        YLOG_WARNING("Service Profile: '%s' already exists", name);
        return -1;
    }

    struct service_profile *p = &g_svc_ctx.profiles[g_svc_ctx.count];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->enabled = true;

    g_svc_ctx.count++;
    YLOG_INFO("Service Profile: Created '%s'", name);
    return g_svc_ctx.count - 1;
}

int service_profile_delete(const char *name)
{
    int idx = find_profile_idx(name);
    if (idx < 0) return -1;

    /* Shift remaining */
    memmove(&g_svc_ctx.profiles[idx], &g_svc_ctx.profiles[idx + 1],
            (g_svc_ctx.count - idx - 1) * sizeof(struct service_profile));
    g_svc_ctx.count--;

    if (g_svc_ctx.default_profile == idx) {
        g_svc_ctx.default_profile = -1;
    } else if (g_svc_ctx.default_profile > idx) {
        g_svc_ctx.default_profile--;
    }

    YLOG_INFO("Service Profile: Deleted '%s'", name);
    return 0;
}

int service_profile_set_interface(const char *profile, const char *iface, uint16_t vlan_id)
{
    int idx = find_profile_idx(profile);
    if (idx < 0) return -1;

    struct service_profile *p = &g_svc_ctx.profiles[idx];
    snprintf(p->iface_name, sizeof(p->iface_name), "%s", iface ? iface : "");
    p->vlan_id = vlan_id;

    YLOG_INFO("Service Profile: '%s' -> interface %s vlan %u", profile, iface, vlan_id);
    return 0;
}

int service_profile_set_pool(const char *profile, const char *pool_name)
{
    int idx = find_profile_idx(profile);
    if (idx < 0) return -1;

    struct service_profile *p = &g_svc_ctx.profiles[idx];
    snprintf(p->pool_name, sizeof(p->pool_name), "%s", pool_name ? pool_name : "");

    YLOG_INFO("Service Profile: '%s' -> pool %s", profile, pool_name);
    return 0;
}

int service_profile_set_ac_name(const char *profile, const char *ac_name)
{
    int idx = find_profile_idx(profile);
    if (idx < 0) return -1;

    struct service_profile *p = &g_svc_ctx.profiles[idx];
    snprintf(p->ac_name, sizeof(p->ac_name), "%s", ac_name ? ac_name : "");

    YLOG_INFO("Service Profile: '%s' -> ac-name %s", profile, ac_name);
    return 0;
}

int service_profile_add_service_name(const char *profile, const char *service_name)
{
    int idx = find_profile_idx(profile);
    if (idx < 0) return -1;

    struct service_profile *p = &g_svc_ctx.profiles[idx];
    if (p->num_service_names >= MAX_SERVICE_NAMES) {
        YLOG_ERROR("Service Profile: '%s' max service-names reached", profile);
        return -1;
    }

    /* Check duplicate */
    for (int i = 0; i < p->num_service_names; i++) {
        if (strcmp(p->service_names[i], service_name) == 0) {
            return 0; /* Already exists */
        }
    }

    snprintf(p->service_names[p->num_service_names], 32, "%s", service_name);
    p->num_service_names++;

    YLOG_INFO("Service Profile: '%s' -> +service-name '%s'", profile, service_name);
    return 0;
}

int service_profile_remove_service_name(const char *profile, const char *service_name)
{
    int idx = find_profile_idx(profile);
    if (idx < 0) return -1;

    struct service_profile *p = &g_svc_ctx.profiles[idx];
    for (int i = 0; i < p->num_service_names; i++) {
        if (strcmp(p->service_names[i], service_name) == 0) {
            memmove(&p->service_names[i], &p->service_names[i + 1],
                    (p->num_service_names - i - 1) * 32);
            p->num_service_names--;
            YLOG_INFO("Service Profile: '%s' -> -service-name '%s'", profile, service_name);
            return 0;
        }
    }
    return -1;
}

int service_profile_find(const char *name, struct service_profile_info *info)
{
    int idx = find_profile_idx(name);
    if (idx < 0) return -1;

    if (info) {
        struct service_profile *p = &g_svc_ctx.profiles[idx];
        snprintf(info->name, sizeof(info->name), "%s", p->name);
        snprintf(info->iface_name, sizeof(info->iface_name), "%s", p->iface_name);
        info->vlan_id = p->vlan_id;
        snprintf(info->ac_name, sizeof(info->ac_name), "%s", p->ac_name);
        snprintf(info->pool_name, sizeof(info->pool_name), "%s", p->pool_name);
        info->num_service_names = p->num_service_names;
        for (int i = 0; i < p->num_service_names; i++) {
            snprintf(info->service_names[i], 32, "%s", p->service_names[i]);
        }
        info->cir_up = p->cir_up;
        info->cir_down = p->cir_down;
        info->mir_up = p->mir_up;
        info->mir_down = p->mir_down;
        info->session_timeout = p->session_timeout;
        info->idle_timeout = p->idle_timeout;
        info->enabled = p->enabled;
    }
    return idx;
}

int service_profile_match(const char *iface, uint16_t vlan_id, const char *service_name,
                          struct service_profile_info *info)
{
    for (int i = 0; i < g_svc_ctx.count; i++) {
        struct service_profile *p = &g_svc_ctx.profiles[i];
        if (!p->enabled) continue;

        /* Match interface (empty = any) */
        if (p->iface_name[0] && strcmp(p->iface_name, iface) != 0) {
            continue;
        }

        /* Match VLAN (0 = any) */
        if (p->vlan_id != 0 && p->vlan_id != vlan_id) {
            continue;
        }

        /* Match service-name (empty list = any, otherwise must match one) */
        if (p->num_service_names > 0 && service_name && service_name[0]) {
            bool found = false;
            for (int j = 0; j < p->num_service_names; j++) {
                if (strcmp(p->service_names[j], service_name) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) continue;
        }

        /* Match! */
        return service_profile_find(p->name, info);
    }

    /* No match, try default */
    if (g_svc_ctx.default_profile >= 0) {
        return service_profile_find(g_svc_ctx.profiles[g_svc_ctx.default_profile].name, info);
    }

    return -1;
}

int service_profile_set_default(const char *name)
{
    int idx = find_profile_idx(name);
    if (idx >= 0) {
        g_svc_ctx.default_profile = idx;
        YLOG_INFO("Service Profile: Default set to '%s'", name);
        return 0;
    }
    return -1;
}

int service_profile_get_default(struct service_profile_info *info)
{
    if (g_svc_ctx.default_profile < 0 || g_svc_ctx.default_profile >= g_svc_ctx.count) {
        return -1;
    }
    return service_profile_find(g_svc_ctx.profiles[g_svc_ctx.default_profile].name, info);
}

void service_profile_list(void)
{
    printf("Service Profiles (%d):\n", g_svc_ctx.count);
    printf("%-12s %-10s %-6s %-12s %s\n", "Name", "Interface", "VLAN", "Pool", "Service-Names");
    printf("%-12s %-10s %-6s %-12s %s\n", "------------", "----------", "------", "------------", "--------------");

    for (int i = 0; i < g_svc_ctx.count; i++) {
        struct service_profile *p = &g_svc_ctx.profiles[i];

        /* Build service-names string */
        char svc_str[128] = "";
        for (int j = 0; j < p->num_service_names; j++) {
            if (j > 0) strcat(svc_str, ", ");
            strcat(svc_str, p->service_names[j]);
        }

        printf("%-12s %-10s %-6u %-12s %s%s\n",
               p->name,
               p->iface_name[0] ? p->iface_name : "*",
               p->vlan_id,
               p->pool_name[0] ? p->pool_name : "-",
               svc_str[0] ? svc_str : "*",
               (i == g_svc_ctx.default_profile) ? " [default]" : "");
    }
}

void service_profile_cleanup(void)
{
    g_svc_ctx.count = 0;
    g_svc_ctx.default_profile = -1;
    YLOG_INFO("Service Profile: Cleanup complete");
}
