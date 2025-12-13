/**
 * @file proxy_arp.c
 * @brief Proxy ARP Implementation
 * @details Responds to ARP requests on behalf of other hosts
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "arp.h"
#include "interface.h"
#include "routing_table.h"
#include "log.h"

/*============================================================================
 * Configuration
 *============================================================================*/

#define MAX_PROXY_ARP_ENTRIES 1024

struct proxy_arp_entry {
    uint32_t network;       /* Network address */
    uint32_t mask;          /* Network mask */
    uint32_t ifindex;       /* Interface to proxy for */
    bool     enabled;
};

static struct {
    struct proxy_arp_entry entries[MAX_PROXY_ARP_ENTRIES];
    int count;
    bool global_enabled;
} g_proxy_arp = {
    .count = 0,
    .global_enabled = false
};

/*============================================================================
 * Proxy ARP Functions
 *============================================================================*/

/**
 * @brief Enable proxy ARP globally
 */
void proxy_arp_enable(bool enable)
{
    g_proxy_arp.global_enabled = enable;
    YLOG_INFO("Proxy ARP %s", enable ? "enabled" : "disabled");
}

/**
 * @brief Add network to proxy ARP
 */
int proxy_arp_add_network(uint32_t network, uint32_t mask, uint32_t ifindex)
{
    if (g_proxy_arp.count >= MAX_PROXY_ARP_ENTRIES) {
        YLOG_ERROR("Proxy ARP table full");
        return -1;
    }

    struct proxy_arp_entry *e = &g_proxy_arp.entries[g_proxy_arp.count++];
    e->network = network;
    e->mask = mask;
    e->ifindex = ifindex;
    e->enabled = true;

    char net_str[32], mask_str[32];
    struct in_addr n = {.s_addr = htonl(network)};
    struct in_addr m = {.s_addr = htonl(mask)};
    inet_ntop(AF_INET, &n, net_str, sizeof(net_str));
    inet_ntop(AF_INET, &m, mask_str, sizeof(mask_str));

    YLOG_INFO("Proxy ARP: Added network %s/%s", net_str, mask_str);
    return 0;
}

/**
 * @brief Check if we should proxy for this IP
 */
bool proxy_arp_should_respond(uint32_t target_ip, uint32_t recv_ifindex)
{
    if (!g_proxy_arp.global_enabled) return false;

    /* Check explicit entries */
    for (int i = 0; i < g_proxy_arp.count; i++) {
        struct proxy_arp_entry *e = &g_proxy_arp.entries[i];
        if (!e->enabled) continue;

        if ((target_ip & e->mask) == e->network) {
            /* Don't proxy on the same interface */
            if (e->ifindex != recv_ifindex) {
                return true;
            }
        }
    }

    /* Check routing table - proxy if we have a route */
    struct in_addr ip = {.s_addr = htonl(target_ip)};
    struct route_entry *route = routing_table_lookup(routing_table_get_instance(), &ip);
    if (route && route->egress_ifindex != recv_ifindex) {
        return true;
    }

    return false;
}

/**
 * @brief Handle proxy ARP request
 */
int proxy_arp_handle_request(uint32_t sender_ip, const uint8_t *sender_mac,
                             uint32_t target_ip, struct interface *iface)
{
    if (!proxy_arp_should_respond(target_ip, iface->ifindex)) {
        return 0;  /* Don't proxy */
    }

    /* Send ARP reply with our MAC as the answer */
    int ret = arp_send_reply_on_interface(sender_ip, sender_mac, target_ip, iface);

    if (ret == 0) {
        char sip[32], tip[32];
        struct in_addr s = {.s_addr = htonl(sender_ip)};
        struct in_addr t = {.s_addr = htonl(target_ip)};
        inet_ntop(AF_INET, &s, sip, sizeof(sip));
        inet_ntop(AF_INET, &t, tip, sizeof(tip));
        YLOG_DEBUG("Proxy ARP: Replied for %s to %s", tip, sip);
    }

    return ret;
}

/**
 * @brief Print proxy ARP configuration
 */
void proxy_arp_print(void)
{
    printf("Proxy ARP: %s\n", g_proxy_arp.global_enabled ? "enabled" : "disabled");
    printf("Entries: %d\n\n", g_proxy_arp.count);

    for (int i = 0; i < g_proxy_arp.count; i++) {
        struct proxy_arp_entry *e = &g_proxy_arp.entries[i];
        char net_str[32];
        struct in_addr n = {.s_addr = htonl(e->network)};
        inet_ntop(AF_INET, &n, net_str, sizeof(net_str));

        /* Count prefix bits */
        int prefix = 0;
        uint32_t m = e->mask;
        while (m & 0x80000000) { prefix++; m <<= 1; }

        printf("  %s/%d (iface %u) %s\n", net_str, prefix, e->ifindex,
               e->enabled ? "enabled" : "disabled");
    }
}
