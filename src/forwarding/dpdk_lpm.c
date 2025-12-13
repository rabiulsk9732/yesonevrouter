/**
 * @file dpdk_lpm.c
 * @brief DPDK Longest Prefix Match (LPM) Routing
 * Uses rte_lpm for high-performance IPv4 route lookups
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_lpm.h>
#include <rte_malloc.h>
#endif

#include "dpdk_lpm.h"
#include "log.h"

#ifdef HAVE_DPDK

#define LPM_MAX_RULES       65536
#define LPM_NUMBER_TBL8S    256

static struct rte_lpm *g_lpm = NULL;

/* Next-hop table (index -> next-hop info) */
#define MAX_NEXT_HOPS 256

struct next_hop_entry {
    uint32_t gateway;       /* Gateway IP (host order) */
    uint32_t ifindex;       /* Egress interface index */
    bool valid;
};

static struct next_hop_entry g_next_hops[MAX_NEXT_HOPS];
static uint16_t g_next_hop_count = 1; /* 0 is reserved for "no route" */

int dpdk_lpm_init(void)
{
    struct rte_lpm_config config = {
        .max_rules = LPM_MAX_RULES,
        .number_tbl8s = LPM_NUMBER_TBL8S,
        .flags = 0
    };

    g_lpm = rte_lpm_create("pppoe_lpm", SOCKET_ID_ANY, &config);
    if (!g_lpm) {
        YLOG_ERROR("DPDK LPM: Failed to create LPM table");
        return -1;
    }

    memset(g_next_hops, 0, sizeof(g_next_hops));
    g_next_hop_count = 1;

    YLOG_INFO("DPDK LPM: Initialized with max %d rules", LPM_MAX_RULES);
    return 0;
}

static uint32_t find_or_create_next_hop(uint32_t gateway, uint32_t ifindex)
{
    /* Search existing */
    for (uint16_t i = 1; i < g_next_hop_count; i++) {
        if (g_next_hops[i].valid &&
            g_next_hops[i].gateway == gateway &&
            g_next_hops[i].ifindex == ifindex) {
            return i;
        }
    }

    /* Create new */
    if (g_next_hop_count >= MAX_NEXT_HOPS) {
        YLOG_ERROR("DPDK LPM: Max next-hops reached");
        return 0;
    }

    uint16_t idx = g_next_hop_count++;
    g_next_hops[idx].gateway = gateway;
    g_next_hops[idx].ifindex = ifindex;
    g_next_hops[idx].valid = true;

    return idx;
}

int dpdk_lpm_add_route(uint32_t network, uint8_t prefix_len, uint32_t gateway, uint32_t ifindex)
{
    if (!g_lpm) return -1;
    if (prefix_len > 32) return -1;

    uint8_t next_hop_id = find_or_create_next_hop(gateway, ifindex);
    if (next_hop_id == 0) return -1;

    int ret = rte_lpm_add(g_lpm, network, prefix_len, next_hop_id);
    if (ret < 0) {
        YLOG_ERROR("DPDK LPM: Failed to add route %u.%u.%u.%u/%u -> %u.%u.%u.%u",
                   (network >> 24) & 0xFF, (network >> 16) & 0xFF,
                   (network >> 8) & 0xFF, network & 0xFF, prefix_len,
                   (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF,
                   (gateway >> 8) & 0xFF, gateway & 0xFF);
        return -1;
    }

    YLOG_DEBUG("DPDK LPM: Added route %u.%u.%u.%u/%u via %u.%u.%u.%u (nh=%u)",
               (network >> 24) & 0xFF, (network >> 16) & 0xFF,
               (network >> 8) & 0xFF, network & 0xFF, prefix_len,
               (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF,
               (gateway >> 8) & 0xFF, gateway & 0xFF, next_hop_id);
    return 0;
}

int dpdk_lpm_del_route(uint32_t network, uint8_t prefix_len)
{
    if (!g_lpm) return -1;

    int ret = rte_lpm_delete(g_lpm, network, prefix_len);
    if (ret < 0) {
        YLOG_WARNING("DPDK LPM: Route not found for deletion");
        return -1;
    }

    return 0;
}

int dpdk_lpm_lookup(uint32_t ip, uint32_t *gateway, uint32_t *ifindex)
{
    if (!g_lpm) return -1;

    uint32_t next_hop_id;
    int ret = rte_lpm_lookup(g_lpm, ip, &next_hop_id);

    if (ret != 0) {
        return -1; /* No route */
    }

    if (next_hop_id == 0 || next_hop_id >= MAX_NEXT_HOPS || !g_next_hops[next_hop_id].valid) {
        return -1;
    }

    if (gateway) *gateway = g_next_hops[next_hop_id].gateway;
    if (ifindex) *ifindex = g_next_hops[next_hop_id].ifindex;

    return 0;
}

int dpdk_lpm_lookup_bulk(const uint32_t *ips, uint32_t *next_hops, int count)
{
    if (!g_lpm || count <= 0) return -1;

    /* Bulk lookup for high performance */
    return rte_lpm_lookup_bulk(g_lpm, ips, next_hops, count);
}

void dpdk_lpm_add_host_route(uint32_t host_ip, uint32_t ifindex)
{
    /* /32 host route for PPPoE session */
    dpdk_lpm_add_route(host_ip, 32, 0, ifindex);

    YLOG_DEBUG("DPDK LPM: Added host route %u.%u.%u.%u/32 via if%u",
               (host_ip >> 24) & 0xFF, (host_ip >> 16) & 0xFF,
               (host_ip >> 8) & 0xFF, host_ip & 0xFF, ifindex);
}

void dpdk_lpm_del_host_route(uint32_t host_ip)
{
    dpdk_lpm_del_route(host_ip, 32);
}

void dpdk_lpm_cleanup(void)
{
    if (g_lpm) {
        rte_lpm_free(g_lpm);
        g_lpm = NULL;
    }
    memset(g_next_hops, 0, sizeof(g_next_hops));
    g_next_hop_count = 1;
    YLOG_INFO("DPDK LPM: Cleanup complete");
}

#else /* !HAVE_DPDK */

/* Stub implementations when DPDK is not available */
int dpdk_lpm_init(void) { return 0; }
void dpdk_lpm_cleanup(void) {}
int dpdk_lpm_add_route(uint32_t network, uint8_t prefix_len, uint32_t gateway, uint32_t ifindex) {
    (void)network; (void)prefix_len; (void)gateway; (void)ifindex;
    return 0;
}
int dpdk_lpm_del_route(uint32_t network, uint8_t prefix_len) {
    (void)network; (void)prefix_len;
    return 0;
}
int dpdk_lpm_lookup(uint32_t ip, uint32_t *gateway, uint32_t *ifindex) {
    (void)ip; (void)gateway; (void)ifindex;
    return -1;
}
int dpdk_lpm_lookup_bulk(const uint32_t *ips, uint32_t *next_hops, int count) {
    (void)ips; (void)next_hops; (void)count;
    return -1;
}
void dpdk_lpm_add_host_route(uint32_t host_ip, uint32_t ifindex) {
    (void)host_ip; (void)ifindex;
}
void dpdk_lpm_del_host_route(uint32_t host_ip) {
    (void)host_ip;
}

#endif /* HAVE_DPDK */
