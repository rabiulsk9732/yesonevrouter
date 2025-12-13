/**
 * @file pbr.c
 * @brief Policy-Based Routing Implementation
 * @details Route packets based on source, destination, protocol, ports
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
 * PBR Configuration
 *============================================================================*/

#define PBR_MAX_POLICIES    64
#define PBR_MAX_RULES       256
#define PBR_NAME_MAX        32

/*============================================================================
 * PBR Match Criteria
 *============================================================================*/

struct pbr_match {
    /* Source matching */
    uint32_t src_ip;
    uint32_t src_mask;
    uint16_t src_port_min;
    uint16_t src_port_max;

    /* Destination matching */
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t dst_port_min;
    uint16_t dst_port_max;

    /* Protocol matching */
    uint8_t  protocol;          /* 0 = any */

    /* DSCP matching */
    uint8_t  dscp;
    uint8_t  dscp_mask;

    /* Ingress interface */
    uint32_t in_ifindex;        /* 0 = any */

    /* ACL reference */
    char acl_name[32];          /* "" = no ACL */
};

/*============================================================================
 * PBR Actions
 *============================================================================*/

enum pbr_action_type {
    PBR_ACTION_NEXTHOP,         /* Forward to specific next-hop */
    PBR_ACTION_INTERFACE,       /* Forward out specific interface */
    PBR_ACTION_VRF,             /* Forward via specific VRF */
    PBR_ACTION_DROP,            /* Drop packet */
    PBR_ACTION_PERMIT           /* Permit and route normally */
};

struct pbr_action {
    enum pbr_action_type type;
    union {
        struct in_addr next_hop;
        uint32_t ifindex;
        uint32_t vrf_id;
    };
    uint8_t set_dscp;           /* 0xFF = don't set */
};

/*============================================================================
 * PBR Rule and Policy
 *============================================================================*/

struct pbr_rule {
    uint32_t seq;               /* Sequence number */
    struct pbr_match match;
    struct pbr_action action;
    bool enabled;

    /* Statistics */
    uint64_t hit_count;
    uint64_t byte_count;
};

struct pbr_policy {
    char name[PBR_NAME_MAX];
    struct pbr_rule rules[PBR_MAX_RULES];
    int rule_count;
    bool enabled;
};

static struct {
    struct pbr_policy policies[PBR_MAX_POLICIES];
    int count;
    pthread_mutex_t lock;
} g_pbr = {
    .count = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/*============================================================================
 * PBR Functions
 *============================================================================*/

int pbr_init(void)
{
    memset(g_pbr.policies, 0, sizeof(g_pbr.policies));
    g_pbr.count = 0;
    YLOG_INFO("PBR subsystem initialized");
    return 0;
}

int pbr_create_policy(const char *name)
{
    if (!name) return -1;

    pthread_mutex_lock(&g_pbr.lock);

    /* Check for duplicate */
    for (int i = 0; i < g_pbr.count; i++) {
        if (strcmp(g_pbr.policies[i].name, name) == 0) {
            pthread_mutex_unlock(&g_pbr.lock);
            return i;
        }
    }

    if (g_pbr.count >= PBR_MAX_POLICIES) {
        pthread_mutex_unlock(&g_pbr.lock);
        return -1;
    }

    struct pbr_policy *p = &g_pbr.policies[g_pbr.count];
    snprintf(p->name, PBR_NAME_MAX, "%s", name);
    p->rule_count = 0;
    p->enabled = true;

    int id = g_pbr.count++;
    pthread_mutex_unlock(&g_pbr.lock);

    YLOG_INFO("PBR: Created policy '%s'", name);
    return id;
}

int pbr_add_rule(const char *policy_name, uint32_t seq,
                 const struct pbr_match *match,
                 const struct pbr_action *action)
{
    pthread_mutex_lock(&g_pbr.lock);

    struct pbr_policy *p = NULL;
    for (int i = 0; i < g_pbr.count; i++) {
        if (strcmp(g_pbr.policies[i].name, policy_name) == 0) {
            p = &g_pbr.policies[i];
            break;
        }
    }

    if (!p || p->rule_count >= PBR_MAX_RULES) {
        pthread_mutex_unlock(&g_pbr.lock);
        return -1;
    }

    /* Insert in sequence order */
    int insert_pos = p->rule_count;
    for (int i = 0; i < p->rule_count; i++) {
        if (p->rules[i].seq > seq) {
            insert_pos = i;
            break;
        }
    }

    /* Shift rules */
    if (insert_pos < p->rule_count) {
        memmove(&p->rules[insert_pos + 1], &p->rules[insert_pos],
                (p->rule_count - insert_pos) * sizeof(struct pbr_rule));
    }

    struct pbr_rule *r = &p->rules[insert_pos];
    r->seq = seq;
    r->match = *match;
    r->action = *action;
    r->enabled = true;
    r->hit_count = 0;
    r->byte_count = 0;

    p->rule_count++;
    pthread_mutex_unlock(&g_pbr.lock);
    return 0;
}

static bool pbr_match_packet(const struct pbr_match *m,
                             uint8_t protocol, uint32_t src_ip, uint16_t src_port,
                             uint32_t dst_ip, uint16_t dst_port, uint32_t in_ifindex)
{
    /* Protocol */
    if (m->protocol != 0 && m->protocol != protocol) return false;

    /* Source IP */
    if ((src_ip & m->src_mask) != (m->src_ip & m->src_mask)) return false;

    /* Destination IP */
    if ((dst_ip & m->dst_mask) != (m->dst_ip & m->dst_mask)) return false;

    /* Source port */
    if (m->src_port_min || m->src_port_max) {
        if (src_port < m->src_port_min || src_port > m->src_port_max) return false;
    }

    /* Destination port */
    if (m->dst_port_min || m->dst_port_max) {
        if (dst_port < m->dst_port_min || dst_port > m->dst_port_max) return false;
    }

    /* Ingress interface */
    if (m->in_ifindex != 0 && m->in_ifindex != in_ifindex) return false;

    return true;
}

struct pbr_action *pbr_lookup(const char *policy_name,
                              uint8_t protocol, uint32_t src_ip, uint16_t src_port,
                              uint32_t dst_ip, uint16_t dst_port, uint32_t in_ifindex)
{
    pthread_mutex_lock(&g_pbr.lock);

    struct pbr_policy *p = NULL;
    for (int i = 0; i < g_pbr.count; i++) {
        if (strcmp(g_pbr.policies[i].name, policy_name) == 0) {
            p = &g_pbr.policies[i];
            break;
        }
    }

    if (!p || !p->enabled) {
        pthread_mutex_unlock(&g_pbr.lock);
        return NULL;
    }

    for (int i = 0; i < p->rule_count; i++) {
        struct pbr_rule *r = &p->rules[i];
        if (!r->enabled) continue;

        if (pbr_match_packet(&r->match, protocol, src_ip, src_port,
                             dst_ip, dst_port, in_ifindex)) {
            r->hit_count++;
            pthread_mutex_unlock(&g_pbr.lock);
            return &r->action;
        }
    }

    pthread_mutex_unlock(&g_pbr.lock);
    return NULL;
}

void pbr_print(const char *policy_name)
{
    pthread_mutex_lock(&g_pbr.lock);

    if (policy_name) {
        struct pbr_policy *p = NULL;
        for (int i = 0; i < g_pbr.count; i++) {
            if (strcmp(g_pbr.policies[i].name, policy_name) == 0) {
                p = &g_pbr.policies[i];
                break;
            }
        }

        if (!p) {
            printf("Policy '%s' not found\n", policy_name);
            pthread_mutex_unlock(&g_pbr.lock);
            return;
        }

        printf("Policy: %s (%d rules, %s)\n", p->name, p->rule_count,
               p->enabled ? "enabled" : "disabled");

        for (int i = 0; i < p->rule_count; i++) {
            struct pbr_rule *r = &p->rules[i];
            printf("  seq %u: match ..., action %d, hits %lu\n",
                   r->seq, r->action.type, r->hit_count);
        }
    } else {
        printf("PBR Policies (%d):\n", g_pbr.count);
        for (int i = 0; i < g_pbr.count; i++) {
            printf("  %s: %d rules, %s\n",
                   g_pbr.policies[i].name,
                   g_pbr.policies[i].rule_count,
                   g_pbr.policies[i].enabled ? "enabled" : "disabled");
        }
    }

    pthread_mutex_unlock(&g_pbr.lock);
}

void pbr_cleanup(void)
{
    g_pbr.count = 0;
    YLOG_INFO("PBR cleanup complete");
}
