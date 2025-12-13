/**
 * @file vrrp.c
 * @brief VRRP (Virtual Router Redundancy Protocol) Implementation
 * @details RFC 5798 - VRRPv3, with VRRPv2 compatibility
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "interface.h"
#include "log.h"
#include "packet.h"

/*============================================================================
 * VRRP Constants
 *============================================================================*/

#define VRRP_VERSION            3
#define VRRP_PROTO              112     /* IP protocol number */
#define VRRP_MCAST_ADDR         0xE0000012  /* 224.0.0.18 */
#define VRRP_ADVERTISE_INTERVAL 100     /* centiseconds (1 second) */
#define VRRP_PRIORITY_OWNER     255
#define VRRP_PRIORITY_DEFAULT   100
#define VRRP_PRIORITY_STOP      0

#define MAX_VRRP_GROUPS         32
#define MAX_VRRP_VIP_PER_GROUP  8

/*============================================================================
 * VRRP Packet Structure
 *============================================================================*/

struct vrrp_hdr {
    uint8_t  version_type;      /* Version (4 bits) + Type (4 bits) */
    uint8_t  vrid;              /* Virtual Router ID */
    uint8_t  priority;          /* Priority (0-255) */
    uint8_t  count_ipaddr;      /* Number of IP addresses */
    uint16_t advert_int;        /* Advertisement interval (centiseconds) */
    uint16_t checksum;          /* Checksum */
    uint32_t ip_addrs[];        /* Virtual IP addresses */
} __attribute__((packed));

/*============================================================================
 * VRRP State Machine
 *============================================================================*/

enum vrrp_state {
    VRRP_STATE_INIT,
    VRRP_STATE_BACKUP,
    VRRP_STATE_MASTER
};

struct vrrp_group {
    uint8_t  vrid;              /* Virtual Router ID (1-255) */
    uint8_t  priority;          /* Configured priority */
    uint8_t  effective_priority;/* Effective priority */
    enum vrrp_state state;

    uint32_t virtual_ip[MAX_VRRP_VIP_PER_GROUP];
    int      vip_count;
    uint8_t  virtual_mac[6];    /* 00:00:5E:00:01:VRID */

    uint32_t master_ip;         /* Current master IP */
    uint8_t  master_priority;   /* Current master priority */

    uint32_t ifindex;           /* Interface index */
    char     iface_name[32];

    uint16_t advert_interval;   /* Advertisement interval (centiseconds) */
    uint64_t master_down_timer; /* Master down timer (ms) */
    uint64_t advert_timer;      /* Advertisement timer (ms) */

    uint64_t last_advert_rx;    /* Last advertisement received */
    uint64_t adverts_tx;        /* Advertisements sent */
    uint64_t adverts_rx;        /* Advertisements received */

    bool     preempt;           /* Preempt mode */
    bool     enabled;
    bool     track_interface;   /* Track interface status */
};

static struct {
    struct vrrp_group groups[MAX_VRRP_GROUPS];
    int group_count;
    bool initialized;
} g_vrrp = {0};

/*============================================================================
 * VRRP Functions
 *============================================================================*/

/**
 * @brief Initialize VRRP subsystem
 */
int vrrp_init(void)
{
    memset(&g_vrrp, 0, sizeof(g_vrrp));
    g_vrrp.initialized = true;
    YLOG_INFO("VRRP subsystem initialized");
    return 0;
}

/**
 * @brief Create VRRP group
 */
int vrrp_create_group(uint8_t vrid, const char *iface_name)
{
    if (g_vrrp.group_count >= MAX_VRRP_GROUPS) {
        YLOG_ERROR("VRRP: Maximum groups reached");
        return -1;
    }

    struct vrrp_group *g = &g_vrrp.groups[g_vrrp.group_count];
    memset(g, 0, sizeof(*g));

    g->vrid = vrid;
    g->priority = VRRP_PRIORITY_DEFAULT;
    g->effective_priority = g->priority;
    g->state = VRRP_STATE_INIT;
    g->advert_interval = VRRP_ADVERTISE_INTERVAL;
    g->preempt = true;
    g->enabled = false;

    strncpy(g->iface_name, iface_name, sizeof(g->iface_name) - 1);

    /* Generate virtual MAC: 00:00:5E:00:01:VRID */
    g->virtual_mac[0] = 0x00;
    g->virtual_mac[1] = 0x00;
    g->virtual_mac[2] = 0x5E;
    g->virtual_mac[3] = 0x00;
    g->virtual_mac[4] = 0x01;
    g->virtual_mac[5] = vrid;

    g_vrrp.group_count++;
    YLOG_INFO("VRRP: Created group %u on %s", vrid, iface_name);

    return 0;
}

/**
 * @brief Add virtual IP to group
 */
int vrrp_add_vip(uint8_t vrid, uint32_t vip)
{
    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];
        if (g->vrid == vrid) {
            if (g->vip_count >= MAX_VRRP_VIP_PER_GROUP) return -1;
            g->virtual_ip[g->vip_count++] = vip;

            char ip_str[32];
            struct in_addr a = {.s_addr = htonl(vip)};
            inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
            YLOG_INFO("VRRP %u: Added VIP %s", vrid, ip_str);
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Set VRRP priority
 */
int vrrp_set_priority(uint8_t vrid, uint8_t priority)
{
    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];
        if (g->vrid == vrid) {
            g->priority = priority;
            g->effective_priority = priority;
            YLOG_INFO("VRRP %u: Priority set to %u", vrid, priority);
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Enable VRRP group
 */
int vrrp_enable(uint8_t vrid, bool enable)
{
    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];
        if (g->vrid == vrid) {
            g->enabled = enable;
            if (enable) {
                g->state = VRRP_STATE_BACKUP;
                g->master_down_timer = (3 * g->advert_interval) +
                    ((256 - g->priority) * g->advert_interval / 256);
            } else {
                g->state = VRRP_STATE_INIT;
            }
            YLOG_INFO("VRRP %u: %s", vrid, enable ? "Enabled" : "Disabled");
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Transition to Master state
 */
static void vrrp_become_master(struct vrrp_group *g)
{
    g->state = VRRP_STATE_MASTER;

    /* Install virtual IP on interface */
    for (int i = 0; i < g->vip_count; i++) {
        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(g->virtual_ip[i])};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        YLOG_INFO("VRRP %u: Installing VIP %s (MASTER)", g->vrid, ip_str);
        /* TODO: Actually install IP on interface */
    }

    /* Send gratuitous ARP for virtual IPs */
    YLOG_INFO("VRRP %u: Became MASTER (priority %u)", g->vrid, g->effective_priority);
}

/**
 * @brief Transition to Backup state
 */
static void vrrp_become_backup(struct vrrp_group *g)
{
    g->state = VRRP_STATE_BACKUP;

    /* Remove virtual IP from interface */
    for (int i = 0; i < g->vip_count; i++) {
        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(g->virtual_ip[i])};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        YLOG_INFO("VRRP %u: Removing VIP %s (BACKUP)", g->vrid, ip_str);
        /* TODO: Remove IP from interface */
    }

    YLOG_INFO("VRRP %u: Became BACKUP", g->vrid);
}

/**
 * @brief Process incoming VRRP advertisement
 */
int vrrp_process_advert(const uint8_t *pkt, uint16_t len, uint32_t src_ip)
{
    if (len < sizeof(struct vrrp_hdr)) return -1;

    const struct vrrp_hdr *hdr = (const struct vrrp_hdr *)pkt;
    uint8_t version = (hdr->version_type >> 4) & 0x0F;
    uint8_t vrid = hdr->vrid;
    uint8_t prio = hdr->priority;

    if (version < 2 || version > 3) return -1;

    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];
        if (g->vrid != vrid || !g->enabled) continue;

        g->adverts_rx++;
        g->last_advert_rx = time(NULL) * 1000;
        g->master_ip = src_ip;
        g->master_priority = prio;

        if (g->state == VRRP_STATE_BACKUP) {
            /* Reset master down timer */
            g->master_down_timer = (3 * g->advert_interval) +
                ((256 - g->priority) * g->advert_interval / 256);
        } else if (g->state == VRRP_STATE_MASTER) {
            /* Received higher priority or same priority with higher IP */
            if (prio > g->effective_priority ||
                (prio == g->effective_priority && src_ip > 0)) {
                vrrp_become_backup(g);
            }
        }

        return 0;
    }

    return -1;
}

/**
 * @brief Send VRRP advertisement
 */
int vrrp_send_advert(struct vrrp_group *g)
{
    if (!g->enabled || g->state != VRRP_STATE_MASTER) return 0;

    /* Build VRRP advertisement packet */
    /* TODO: Allocate packet and send via multicast */

    g->adverts_tx++;
    return 0;
}

/**
 * @brief Periodic VRRP timer (call every 100ms)
 */
void vrrp_periodic(void)
{
    uint64_t now_ms = time(NULL) * 1000;

    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];
        if (!g->enabled) continue;

        if (g->state == VRRP_STATE_BACKUP) {
            /* Check master down timer */
            uint64_t elapsed = now_ms - g->last_advert_rx;
            if (elapsed > g->master_down_timer * 10) {
                YLOG_INFO("VRRP %u: Master down timer expired", g->vrid);
                vrrp_become_master(g);
            }
        } else if (g->state == VRRP_STATE_MASTER) {
            /* Send periodic advertisements */
            vrrp_send_advert(g);
        }
    }
}

/**
 * @brief Print VRRP status
 */
void vrrp_print(void)
{
    printf("VRRP Status (%d groups)\n", g_vrrp.group_count);
    printf("========================\n\n");

    for (int i = 0; i < g_vrrp.group_count; i++) {
        struct vrrp_group *g = &g_vrrp.groups[i];

        const char *state_str;
        switch (g->state) {
            case VRRP_STATE_INIT: state_str = "Init"; break;
            case VRRP_STATE_BACKUP: state_str = "Backup"; break;
            case VRRP_STATE_MASTER: state_str = "Master"; break;
            default: state_str = "Unknown";
        }

        printf("Group %u (%s):\n", g->vrid, g->iface_name);
        printf("  State:    %s\n", state_str);
        printf("  Priority: %u (effective: %u)\n", g->priority, g->effective_priority);
        printf("  Preempt:  %s\n", g->preempt ? "yes" : "no");
        printf("  Virtual MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               g->virtual_mac[0], g->virtual_mac[1], g->virtual_mac[2],
               g->virtual_mac[3], g->virtual_mac[4], g->virtual_mac[5]);
        printf("  Virtual IPs:\n");
        for (int v = 0; v < g->vip_count; v++) {
            char ip_str[32];
            struct in_addr a = {.s_addr = htonl(g->virtual_ip[v])};
            inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
            printf("    %s\n", ip_str);
        }
        printf("  Adverts TX: %lu, RX: %lu\n", g->adverts_tx, g->adverts_rx);
        printf("\n");
    }
}

/**
 * @brief Cleanup VRRP
 */
void vrrp_cleanup(void)
{
    memset(&g_vrrp, 0, sizeof(g_vrrp));
    YLOG_INFO("VRRP cleanup complete");
}
