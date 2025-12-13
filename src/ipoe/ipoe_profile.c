/**
 * @file ipoe_profile.c
 * @brief IPoE Service Profile Implementation - BISON-style
 */

#include <ipoe_profile.h>
#include <ipoe_session.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/*============================================================================
 * Global Profile Manager
 *============================================================================*/

static struct ipoe_profile_mgr g_profile_mgr = {0};

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_profile_init(void)
{
    memset(&g_profile_mgr, 0, sizeof(g_profile_mgr));
    printf("ipoe_profile: initialized\n");
    return 0;
}

void ipoe_profile_cleanup(void)
{
    memset(&g_profile_mgr, 0, sizeof(g_profile_mgr));
}

/*============================================================================
 * Service Profile CRUD
 *============================================================================*/

static int find_profile_idx(const char *name)
{
    for (uint32_t i = 0; i < g_profile_mgr.num_profiles; i++) {
        if (strcmp(g_profile_mgr.profiles[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int ipoe_profile_create(const char *name)
{
    if (!name || g_profile_mgr.num_profiles >= IPOE_MAX_PROFILES) {
        return -1;
    }

    if (find_profile_idx(name) >= 0) {
        return -1;  /* Already exists */
    }

    struct ipoe_service_profile *p = &g_profile_mgr.profiles[g_profile_mgr.num_profiles];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, name, IPOE_PROFILE_NAME_LEN - 1);
    p->enabled = true;
    p->priority = 100;

    /* Default Option 82 templates */
    strncpy(p->opt82.circuit_id_template, "%ifname%:%svlan%:%cvlan%",
            IPOE_OPT82_TEMPLATE_LEN - 1);
    strncpy(p->opt82.remote_id_template, "%mac%",
            IPOE_OPT82_TEMPLATE_LEN - 1);
    p->opt82.enabled = true;

    g_profile_mgr.num_profiles++;
    printf("ipoe_profile: created '%s'\n", name);
    return 0;
}

int ipoe_profile_delete(const char *name)
{
    int idx = find_profile_idx(name);
    if (idx < 0) return -1;

    /* Shift remaining profiles */
    memmove(&g_profile_mgr.profiles[idx],
            &g_profile_mgr.profiles[idx + 1],
            (g_profile_mgr.num_profiles - idx - 1) * sizeof(struct ipoe_service_profile));
    g_profile_mgr.num_profiles--;

    printf("ipoe_profile: deleted '%s'\n", name);
    return 0;
}

struct ipoe_service_profile *ipoe_profile_find(const char *name)
{
    int idx = find_profile_idx(name);
    return (idx >= 0) ? &g_profile_mgr.profiles[idx] : NULL;
}

/*============================================================================
 * Profile Matching (VLAN → Profile)
 *============================================================================*/

struct ipoe_service_profile *ipoe_profile_match(uint16_t svlan, uint16_t cvlan,
                                                  uint32_t ifindex)
{
    struct ipoe_service_profile *best = NULL;
    uint8_t best_priority = 255;

    for (uint32_t i = 0; i < g_profile_mgr.num_profiles; i++) {
        struct ipoe_service_profile *p = &g_profile_mgr.profiles[i];
        if (!p->enabled) continue;

        /* Check SVLAN match */
        if (p->svlan != 0) {
            uint16_t masked_svlan = svlan & p->svlan_mask;
            if (masked_svlan != (p->svlan & p->svlan_mask)) {
                continue;
            }
        }

        /* Check CVLAN match */
        if (p->cvlan != 0) {
            uint16_t masked_cvlan = cvlan & p->cvlan_mask;
            if (masked_cvlan != (p->cvlan & p->cvlan_mask)) {
                continue;
            }
        }

        /* Check interface match */
        if (p->ifindex != 0 && p->ifindex != ifindex) {
            continue;
        }

        /* Check priority */
        if (p->priority < best_priority) {
            best = p;
            best_priority = p->priority;
        }
    }

    /* Fall back to default profile */
    if (!best && g_profile_mgr.default_profile[0]) {
        best = ipoe_profile_find(g_profile_mgr.default_profile);
    }

    return best;
}

int ipoe_profile_set_default(const char *name)
{
    if (name) {
        strncpy(g_profile_mgr.default_profile, name, IPOE_PROFILE_NAME_LEN - 1);
    } else {
        g_profile_mgr.default_profile[0] = '\0';
    }
    return 0;
}

/*============================================================================
 * Profile Configuration
 *============================================================================*/

int ipoe_profile_set_pool(const char *profile, const char *pool_name)
{
    struct ipoe_service_profile *p = ipoe_profile_find(profile);
    if (!p) return -1;

    strncpy(p->pool_name, pool_name ? pool_name : "", IPOE_POOL_NAME_LEN - 1);
    return 0;
}

int ipoe_profile_set_vlan(const char *profile, uint16_t svlan, uint16_t cvlan)
{
    struct ipoe_service_profile *p = ipoe_profile_find(profile);
    if (!p) return -1;

    p->svlan = svlan;
    p->svlan_mask = 0xFFFF;
    p->cvlan = cvlan;
    p->cvlan_mask = 0xFFFF;
    return 0;
}

int ipoe_profile_set_rate_limit(const char *profile, uint32_t up, uint32_t down)
{
    struct ipoe_service_profile *p = ipoe_profile_find(profile);
    if (!p) return -1;

    p->rate_limit_up = up;
    p->rate_limit_down = down;
    return 0;
}

int ipoe_profile_set_opt82(const char *profile, const char *circuit_id_tmpl,
                            const char *remote_id_tmpl)
{
    struct ipoe_service_profile *p = ipoe_profile_find(profile);
    if (!p) return -1;

    if (circuit_id_tmpl) {
        strncpy(p->opt82.circuit_id_template, circuit_id_tmpl,
                IPOE_OPT82_TEMPLATE_LEN - 1);
    }
    if (remote_id_tmpl) {
        strncpy(p->opt82.remote_id_template, remote_id_tmpl,
                IPOE_OPT82_TEMPLATE_LEN - 1);
    }

    return 0;
}

/*============================================================================
 * Pool Profile CRUD
 *============================================================================*/

static int find_pool_idx(const char *name)
{
    for (uint32_t i = 0; i < g_profile_mgr.num_pools; i++) {
        if (strcmp(g_profile_mgr.pools[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int ipoe_pool_create(const char *name)
{
    if (!name || g_profile_mgr.num_pools >= IPOE_MAX_PROFILES) {
        return -1;
    }

    if (find_pool_idx(name) >= 0) {
        return -1;
    }

    struct ipoe_pool_profile *pool = &g_profile_mgr.pools[g_profile_mgr.num_pools];
    memset(pool, 0, sizeof(*pool));
    strncpy(pool->name, name, IPOE_POOL_NAME_LEN - 1);
    pool->enabled = true;
    pool->default_lease = 3600;
    pool->min_lease = 300;
    pool->max_lease = 86400;

    g_profile_mgr.num_pools++;
    printf("ipoe_pool: created '%s'\n", name);
    return 0;
}

struct ipoe_pool_profile *ipoe_pool_find(const char *name)
{
    int idx = find_pool_idx(name);
    return (idx >= 0) ? &g_profile_mgr.pools[idx] : NULL;
}

int ipoe_pool_set_range(const char *pool, uint32_t start, uint32_t end, uint32_t mask)
{
    struct ipoe_pool_profile *p = ipoe_pool_find(pool);
    if (!p) return -1;

    p->start_ip = start;
    p->end_ip = end;
    p->netmask = mask;
    p->total_ips = end - start + 1;
    p->used_ips = 0;

    return 0;
}

int ipoe_pool_set_dns(const char *pool, uint32_t primary, uint32_t secondary)
{
    struct ipoe_pool_profile *p = ipoe_pool_find(pool);
    if (!p) return -1;

    p->dns_primary = primary;
    p->dns_secondary = secondary;
    return 0;
}

int ipoe_pool_set_gateway(const char *pool, uint32_t gateway)
{
    struct ipoe_pool_profile *p = ipoe_pool_find(pool);
    if (!p) return -1;

    p->gateway = gateway;
    return 0;
}

/*============================================================================
 * Option 82 Template Expansion
 *============================================================================*/

int ipoe_opt82_expand_template(const char *tmpl, struct ipoe_session *sess,
                                char *output, size_t len)
{
    if (!tmpl || !sess || !output || len == 0) return -1;

    char mac_str[18];
    ipoe_session_format_mac(sess->mac, mac_str, sizeof(mac_str));

    const char *p = tmpl;
    char *out = output;
    char *end = output + len - 1;

    while (*p && out < end) {
        if (*p == '%') {
            const char *var_start = p + 1;
            const char *var_end = strchr(var_start, '%');

            if (var_end) {
                size_t var_len = var_end - var_start;
                char var[32] = {0};
                if (var_len < sizeof(var)) {
                    memcpy(var, var_start, var_len);
                }

                /* Expand variables */
                int written = 0;
                if (strcmp(var, "mac") == 0) {
                    written = snprintf(out, end - out, "%s", mac_str);
                } else if (strcmp(var, "svlan") == 0) {
                    written = snprintf(out, end - out, "%u", sess->svlan);
                } else if (strcmp(var, "cvlan") == 0) {
                    written = snprintf(out, end - out, "%u", sess->cvlan);
                } else if (strcmp(var, "port") == 0 || strcmp(var, "ifname") == 0) {
                    written = snprintf(out, end - out, "eth%u", sess->ifindex);
                } else if (strcmp(var, "slot") == 0) {
                    written = snprintf(out, end - out, "0");
                }

                out += written;
                p = var_end + 1;
                continue;
            }
        }

        *out++ = *p++;
    }

    *out = '\0';
    return 0;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_profile_print_all(void)
{
    printf("\nIPoE Service Profiles (%u):\n", g_profile_mgr.num_profiles);
    printf("%-20s %-8s %-8s %-12s %-8s\n",
           "Name", "SVLAN", "CVLAN", "Pool", "Priority");
    printf("----------------------------------------------------------\n");

    for (uint32_t i = 0; i < g_profile_mgr.num_profiles; i++) {
        struct ipoe_service_profile *p = &g_profile_mgr.profiles[i];
        printf("%-20s %-8u %-8u %-12s %-8u\n",
               p->name,
               p->svlan,
               p->cvlan,
               p->pool_name[0] ? p->pool_name : "-",
               p->priority);
    }
    printf("\n");
}

void ipoe_pool_print_all(void)
{
    printf("\nIPoE DHCP Pools (%u):\n", g_profile_mgr.num_pools);
    printf("%-16s %-16s %-16s %-8s %-8s\n",
           "Name", "Start IP", "End IP", "Total", "Used");
    printf("----------------------------------------------------------\n");

    for (uint32_t i = 0; i < g_profile_mgr.num_pools; i++) {
        struct ipoe_pool_profile *p = &g_profile_mgr.pools[i];
        char start_str[16], end_str[16];

        struct in_addr start = { .s_addr = htonl(p->start_ip) };
        struct in_addr end = { .s_addr = htonl(p->end_ip) };
        inet_ntop(AF_INET, &start, start_str, sizeof(start_str));
        inet_ntop(AF_INET, &end, end_str, sizeof(end_str));

        printf("%-16s %-16s %-16s %-8u %-8u\n",
               p->name,
               start_str,
               end_str,
               p->total_ips,
               p->used_ips);
    }
    printf("\n");
}
