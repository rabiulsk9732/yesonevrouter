/**
 * @file ipv6_mld.c
 * @brief MLD (Multicast Listener Discovery) Implementation
 * @details RFC 2710 (MLDv1), RFC 3810 (MLDv2)
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "interface.h"
#include "log.h"

/*============================================================================
 * MLD Constants
 *============================================================================*/

#define ICMPV6_MLD_QUERY        130
#define ICMPV6_MLD_REPORT       131
#define ICMPV6_MLD_DONE         132
#define ICMPV6_MLD2_REPORT      143

#define MAX_MLD_GROUPS          1024
#define MLD_QUERY_INTERVAL      125     /* seconds */
#define MLD_QUERY_RESPONSE_INT  10000   /* milliseconds */

/*============================================================================
 * MLD Structures
 *============================================================================*/

struct mld_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t max_response_delay;
    uint16_t reserved;
    uint8_t  multicast_addr[16];
} __attribute__((packed));

struct mld_group {
    uint8_t  group_addr[16];
    uint32_t ifindex;
    uint64_t last_report;
    int      listener_count;
    bool     active;
};

static struct {
    struct mld_group groups[MAX_MLD_GROUPS];
    int group_count;
    bool enabled;
    uint64_t queries_tx;
    uint64_t reports_rx;
} g_mld = {0};

/*============================================================================
 * MLD Functions
 *============================================================================*/

int mld_init(void)
{
    memset(&g_mld, 0, sizeof(g_mld));
    g_mld.enabled = true;
    YLOG_INFO("MLD subsystem initialized");
    return 0;
}

int mld_process_packet(const uint8_t *pkt, uint16_t len, uint32_t ifindex)
{
    if (len < sizeof(struct mld_hdr)) return -1;

    const struct mld_hdr *hdr = (const struct mld_hdr *)pkt;

    switch (hdr->type) {
        case ICMPV6_MLD_REPORT:
        case ICMPV6_MLD2_REPORT:
            g_mld.reports_rx++;
            /* Add/update group membership */
            for (int i = 0; i < g_mld.group_count; i++) {
                if (memcmp(g_mld.groups[i].group_addr, hdr->multicast_addr, 16) == 0 &&
                    g_mld.groups[i].ifindex == ifindex) {
                    g_mld.groups[i].last_report = time(NULL);
                    g_mld.groups[i].listener_count++;
                    return 0;
                }
            }
            /* New group */
            if (g_mld.group_count < MAX_MLD_GROUPS) {
                struct mld_group *g = &g_mld.groups[g_mld.group_count++];
                memcpy(g->group_addr, hdr->multicast_addr, 16);
                g->ifindex = ifindex;
                g->last_report = time(NULL);
                g->listener_count = 1;
                g->active = true;
                YLOG_DEBUG("MLD: Group joined on interface %u", ifindex);
            }
            break;

        case ICMPV6_MLD_DONE:
            /* Remove group membership */
            for (int i = 0; i < g_mld.group_count; i++) {
                if (memcmp(g_mld.groups[i].group_addr, hdr->multicast_addr, 16) == 0 &&
                    g_mld.groups[i].ifindex == ifindex) {
                    g_mld.groups[i].listener_count--;
                    if (g_mld.groups[i].listener_count <= 0) {
                        g_mld.groups[i].active = false;
                        YLOG_DEBUG("MLD: Group left on interface %u", ifindex);
                    }
                    break;
                }
            }
            break;
    }

    return 0;
}

int mld_send_query(uint32_t ifindex, const uint8_t *group_addr)
{
    /* Send MLD query */
    (void)ifindex;
    (void)group_addr;
    g_mld.queries_tx++;
    return 0;
}

void mld_periodic(void)
{
    /* Age out stale groups */
    uint64_t now = time(NULL);
    for (int i = 0; i < g_mld.group_count; i++) {
        struct mld_group *g = &g_mld.groups[i];
        if (g->active && (now - g->last_report) > MLD_QUERY_INTERVAL * 3) {
            g->active = false;
            YLOG_DEBUG("MLD: Group timed out");
        }
    }
}

void mld_print(void)
{
    printf("MLD Status\n");
    printf("==========\n");
    printf("Queries TX: %lu, Reports RX: %lu\n\n", g_mld.queries_tx, g_mld.reports_rx);

    int active = 0;
    for (int i = 0; i < g_mld.group_count; i++) {
        if (g_mld.groups[i].active) active++;
    }
    printf("Active groups: %d\n", active);
}

void mld_cleanup(void)
{
    memset(&g_mld, 0, sizeof(g_mld));
    YLOG_INFO("MLD cleanup complete");
}
