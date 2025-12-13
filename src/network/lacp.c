/**
 * @file lacp.c
 * @brief LACP (Link Aggregation Control Protocol) Implementation
 * @details IEEE 802.3ad / IEEE 802.1AX
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "interface.h"
#include "log.h"
#include "packet.h"

/*============================================================================
 * LACP Constants
 *============================================================================*/

#define LACP_ETHERTYPE          0x8809
#define LACP_SUBTYPE            0x01

#define LACP_ACTOR_TLV          0x01
#define LACP_PARTNER_TLV        0x02
#define LACP_COLLECTOR_TLV      0x03
#define LACP_TERMINATOR_TLV     0x00

#define LACP_STATE_ACTIVE       0x01
#define LACP_STATE_SHORT_TIMEOUT 0x02
#define LACP_STATE_AGGREGATION  0x04
#define LACP_STATE_SYNCHRONIZATION 0x08
#define LACP_STATE_COLLECTING   0x10
#define LACP_STATE_DISTRIBUTING 0x20
#define LACP_STATE_DEFAULTED    0x40
#define LACP_STATE_EXPIRED      0x80

#define MAX_LAG_GROUPS          8
#define MAX_LAG_MEMBERS         8

/*============================================================================
 * LACP PDU Structures
 *============================================================================*/

struct lacp_info {
    uint16_t system_priority;
    uint8_t  system_id[6];
    uint16_t key;
    uint16_t port_priority;
    uint16_t port;
    uint8_t  state;
    uint8_t  reserved[3];
} __attribute__((packed));

struct lacpdu {
    uint8_t  subtype;
    uint8_t  version;
    uint8_t  actor_tlv_type;
    uint8_t  actor_tlv_len;
    struct lacp_info actor;
    uint8_t  partner_tlv_type;
    uint8_t  partner_tlv_len;
    struct lacp_info partner;
    uint8_t  collector_tlv_type;
    uint8_t  collector_tlv_len;
    uint16_t collector_max_delay;
    uint8_t  collector_reserved[12];
    uint8_t  terminator_type;
    uint8_t  terminator_len;
    uint8_t  reserved[50];
} __attribute__((packed));

/*============================================================================
 * LAG State
 *============================================================================*/

enum lag_member_state {
    LAG_MEMBER_DETACHED,
    LAG_MEMBER_WAITING,
    LAG_MEMBER_ATTACHED,
    LAG_MEMBER_COLLECTING,
    LAG_MEMBER_DISTRIBUTING
};

struct lag_member {
    uint32_t ifindex;
    enum lag_member_state state;
    struct lacp_info actor;
    struct lacp_info partner;
    uint64_t last_lacpdu_rx;
    uint64_t lacpdus_tx;
    uint64_t lacpdus_rx;
    bool     active;
};

struct lag_group {
    char     name[32];
    uint16_t lag_id;
    uint16_t system_priority;
    uint8_t  system_id[6];
    uint16_t admin_key;
    struct lag_member members[MAX_LAG_MEMBERS];
    int      member_count;
    bool     lacp_enabled;
    bool     active_mode;
    uint8_t  lacp_rate;
    uint64_t packets_tx;
    uint64_t packets_rx;
};

static struct {
    struct lag_group groups[MAX_LAG_GROUPS];
    int group_count;
    bool initialized;
} g_lacp = {0};

/*============================================================================
 * LACP Functions
 *============================================================================*/

int lacp_init(void) {
    memset(&g_lacp, 0, sizeof(g_lacp));
    g_lacp.initialized = true;
    YLOG_INFO("LACP subsystem initialized");
    return 0;
}

int lacp_create_lag(const char *name, uint16_t admin_key) {
    if (g_lacp.group_count >= MAX_LAG_GROUPS) return -1;
    struct lag_group *lag = &g_lacp.groups[g_lacp.group_count];
    memset(lag, 0, sizeof(*lag));
    strncpy(lag->name, name, sizeof(lag->name) - 1);
    lag->lag_id = g_lacp.group_count + 1;
    lag->admin_key = admin_key;
    lag->system_priority = 32768;
    lag->lacp_enabled = true;
    lag->active_mode = true;
    lag->lacp_rate = 1;
    g_lacp.group_count++;
    YLOG_INFO("LACP: Created LAG %s", name);
    return lag->lag_id;
}

int lacp_add_member(uint16_t lag_id, uint32_t ifindex) {
    if (lag_id == 0 || lag_id > g_lacp.group_count) return -1;
    struct lag_group *lag = &g_lacp.groups[lag_id - 1];
    if (lag->member_count >= MAX_LAG_MEMBERS) return -1;
    struct lag_member *m = &lag->members[lag->member_count++];
    memset(m, 0, sizeof(*m));
    m->ifindex = ifindex;
    m->state = LAG_MEMBER_DETACHED;
    YLOG_INFO("LACP: Added port %u to LAG %s", ifindex, lag->name);
    return 0;
}

int lacp_process_pdu(const uint8_t *pkt, uint16_t len, uint32_t ifindex) {
    if (len < sizeof(struct lacpdu)) return -1;
    const struct lacpdu *pdu = (const struct lacpdu *)pkt;
    if (pdu->subtype != LACP_SUBTYPE) return -1;

    for (int g = 0; g < g_lacp.group_count; g++) {
        struct lag_group *lag = &g_lacp.groups[g];
        for (int m = 0; m < lag->member_count; m++) {
            struct lag_member *member = &lag->members[m];
            if (member->ifindex == ifindex) {
                memcpy(&member->partner, &pdu->actor, sizeof(struct lacp_info));
                member->last_lacpdu_rx = time(NULL);
                member->lacpdus_rx++;
                if (member->state == LAG_MEMBER_DETACHED) member->state = LAG_MEMBER_WAITING;
                if (pdu->actor.state & LACP_STATE_SYNCHRONIZATION) {
                    member->state = LAG_MEMBER_COLLECTING;
                    member->active = true;
                }
                return 0;
            }
        }
    }
    return -1;
}

void lacp_periodic(void) {
    uint64_t now = time(NULL);
    for (int g = 0; g < g_lacp.group_count; g++) {
        struct lag_group *lag = &g_lacp.groups[g];
        if (!lag->lacp_enabled) continue;
        for (int m = 0; m < lag->member_count; m++) {
            struct lag_member *member = &lag->members[m];
            uint64_t timeout = (lag->lacp_rate == 1) ? 3 : 90;
            if (now - member->last_lacpdu_rx > timeout && member->state != LAG_MEMBER_DETACHED) {
                member->state = LAG_MEMBER_DETACHED;
                member->active = false;
                YLOG_WARNING("LACP: Port %u timed out", member->ifindex);
            }
        }
    }
}

uint32_t lacp_select_port(uint16_t lag_id, uint32_t hash) {
    if (lag_id == 0 || lag_id > g_lacp.group_count) return 0;
    struct lag_group *lag = &g_lacp.groups[lag_id - 1];
    uint32_t ports[MAX_LAG_MEMBERS];
    int count = 0;
    for (int m = 0; m < lag->member_count; m++) {
        if (lag->members[m].active) ports[count++] = lag->members[m].ifindex;
    }
    if (count == 0) return 0;
    return ports[hash % count];
}

void lacp_print(void) {
    printf("LACP Status (%d LAGs)\n", g_lacp.group_count);
    for (int g = 0; g < g_lacp.group_count; g++) {
        struct lag_group *lag = &g_lacp.groups[g];
        printf("  %s: %d members, Key %u\n", lag->name, lag->member_count, lag->admin_key);
        for (int m = 0; m < lag->member_count; m++) {
            struct lag_member *member = &lag->members[m];
            printf("    Port %u: %s\n", member->ifindex, member->active ? "Active" : "Standby");
        }
    }
}

void lacp_cleanup(void) {
    memset(&g_lacp, 0, sizeof(g_lacp));
    YLOG_INFO("LACP cleanup complete");
}
