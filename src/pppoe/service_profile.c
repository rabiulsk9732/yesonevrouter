/**
 * @file service_profile.c
 * @brief PPPoE Service Profile Management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "service_profile.h"
#include "log.h"

#define MAX_SERVICE_PROFILES 64

/* Service profile entry */
struct service_profile {
    char name[32];
    char ac_name[64];
    uint32_t ip_pool_id;
    uint64_t cir_up;
    uint64_t cir_down;
    uint64_t mir_up;
    uint64_t mir_down;
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

int service_profile_init(void)
{
    memset(&g_svc_ctx, 0, sizeof(g_svc_ctx));
    g_svc_ctx.default_profile = -1;

    /* Create default profile */
    service_profile_create("default", "YESRouter", 0,
                           10000000, 10000000,  /* 10 Mbps CIR */
                           100000000, 100000000, /* 100 Mbps MIR */
                           0, 0);
    service_profile_set_default("default");

    YLOG_INFO("Service Profile: Initialized with default profile");
    return 0;
}

int service_profile_create(const char *name, const char *ac_name, uint32_t pool_id,
                           uint64_t cir_up, uint64_t cir_down,
                           uint64_t mir_up, uint64_t mir_down,
                           uint32_t session_timeout, uint32_t idle_timeout)
{
    if (!name || g_svc_ctx.count >= MAX_SERVICE_PROFILES) {
        return -1;
    }

    /* Check for duplicate */
    for (int i = 0; i < g_svc_ctx.count; i++) {
        if (strcmp(g_svc_ctx.profiles[i].name, name) == 0) {
            YLOG_WARNING("Service Profile: '%s' already exists", name);
            return -1;
        }
    }

    struct service_profile *p = &g_svc_ctx.profiles[g_svc_ctx.count];
    snprintf(p->name, sizeof(p->name), "%s", name);
    snprintf(p->ac_name, sizeof(p->ac_name), "%s", ac_name ? ac_name : "YESRouter");
    p->ip_pool_id = pool_id;
    p->cir_up = cir_up;
    p->cir_down = cir_down;
    p->mir_up = mir_up;
    p->mir_down = mir_down;
    p->session_timeout = session_timeout;
    p->idle_timeout = idle_timeout;
    p->enabled = true;

    g_svc_ctx.count++;
    YLOG_INFO("Service Profile: Created '%s' (CIR: %lu/%lu, MIR: %lu/%lu)",
              name, cir_up, cir_down, mir_up, mir_down);
    return g_svc_ctx.count - 1;
}

int service_profile_delete(const char *name)
{
    for (int i = 0; i < g_svc_ctx.count; i++) {
        if (strcmp(g_svc_ctx.profiles[i].name, name) == 0) {
            /* Shift remaining */
            memmove(&g_svc_ctx.profiles[i], &g_svc_ctx.profiles[i + 1],
                    (g_svc_ctx.count - i - 1) * sizeof(struct service_profile));
            g_svc_ctx.count--;

            if (g_svc_ctx.default_profile == i) {
                g_svc_ctx.default_profile = -1;
            } else if (g_svc_ctx.default_profile > i) {
                g_svc_ctx.default_profile--;
            }

            YLOG_INFO("Service Profile: Deleted '%s'", name);
            return 0;
        }
    }
    return -1;
}

int service_profile_find(const char *name, struct service_profile_info *info)
{
    for (int i = 0; i < g_svc_ctx.count; i++) {
        if (strcmp(g_svc_ctx.profiles[i].name, name) == 0) {
            if (info) {
                struct service_profile *p = &g_svc_ctx.profiles[i];
                snprintf(info->name, sizeof(info->name), "%s", p->name);
                snprintf(info->ac_name, sizeof(info->ac_name), "%s", p->ac_name);
                info->ip_pool_id = p->ip_pool_id;
                info->cir_up = p->cir_up;
                info->cir_down = p->cir_down;
                info->mir_up = p->mir_up;
                info->mir_down = p->mir_down;
                info->session_timeout = p->session_timeout;
                info->idle_timeout = p->idle_timeout;
            }
            return i;
        }
    }
    return -1;
}

int service_profile_set_default(const char *name)
{
    int idx = service_profile_find(name, NULL);
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

    struct service_profile *p = &g_svc_ctx.profiles[g_svc_ctx.default_profile];
    if (info) {
        snprintf(info->name, sizeof(info->name), "%s", p->name);
        snprintf(info->ac_name, sizeof(info->ac_name), "%s", p->ac_name);
        info->ip_pool_id = p->ip_pool_id;
        info->cir_up = p->cir_up;
        info->cir_down = p->cir_down;
        info->mir_up = p->mir_up;
        info->mir_down = p->mir_down;
        info->session_timeout = p->session_timeout;
        info->idle_timeout = p->idle_timeout;
    }
    return g_svc_ctx.default_profile;
}

void service_profile_list(void)
{
    printf("Service Profiles (%d):\n", g_svc_ctx.count);
    printf("%-16s %-16s %-12s %-12s %s\n", "Name", "AC-Name", "CIR Up/Down", "MIR Up/Down", "Default");
    printf("%-16s %-16s %-12s %-12s %s\n", "----------------", "----------------", "------------", "------------", "-------");

    for (int i = 0; i < g_svc_ctx.count; i++) {
        struct service_profile *p = &g_svc_ctx.profiles[i];
        printf("%-16s %-16s %5lu/%-5lu %5lu/%-5lu %s\n",
               p->name, p->ac_name,
               p->cir_up / 1000000, p->cir_down / 1000000,
               p->mir_up / 1000000, p->mir_down / 1000000,
               (i == g_svc_ctx.default_profile) ? "*" : "");
    }
}

void service_profile_cleanup(void)
{
    g_svc_ctx.count = 0;
    g_svc_ctx.default_profile = -1;
    YLOG_INFO("Service Profile: Cleanup complete");
}
