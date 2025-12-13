/**
 * @file ipv6_dhcpv6_relay.c
 * @brief DHCPv6 Relay Agent Implementation
 * @details RFC 3315
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "interface.h"
#include "log.h"
#include "packet.h"

/*============================================================================
 * DHCPv6 Constants
 *============================================================================*/

#define DHCPV6_SERVER_PORT      547
#define DHCPV6_CLIENT_PORT      546

#define DHCPV6_RELAY_FORW       12
#define DHCPV6_RELAY_REPL       13

#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_RELAY_MSG    9

#define MAX_DHCPV6_SERVERS      8

/*============================================================================
 * DHCPv6 Relay Structures
 *============================================================================*/

struct dhcpv6_relay_hdr {
    uint8_t  msg_type;
    uint8_t  hop_count;
    uint8_t  link_addr[16];
    uint8_t  peer_addr[16];
    uint8_t  options[];
} __attribute__((packed));

static struct {
    uint8_t  servers[MAX_DHCPV6_SERVERS][16];
    int      server_count;
    bool     enabled;
    uint64_t relayed_requests;
    uint64_t relayed_replies;
} g_dhcpv6_relay = {0};

/*============================================================================
 * DHCPv6 Relay Functions
 *============================================================================*/

int dhcpv6_relay_init(void)
{
    memset(&g_dhcpv6_relay, 0, sizeof(g_dhcpv6_relay));
    YLOG_INFO("DHCPv6 Relay initialized");
    return 0;
}

void dhcpv6_relay_enable(bool enable)
{
    g_dhcpv6_relay.enabled = enable;
    YLOG_INFO("DHCPv6 Relay %s", enable ? "enabled" : "disabled");
}

int dhcpv6_relay_add_server(const uint8_t *server_addr)
{
    if (g_dhcpv6_relay.server_count >= MAX_DHCPV6_SERVERS) {
        YLOG_ERROR("DHCPv6 Relay: Maximum servers reached");
        return -1;
    }

    memcpy(g_dhcpv6_relay.servers[g_dhcpv6_relay.server_count++], server_addr, 16);

    char addr_str[64];
    inet_ntop(AF_INET6, server_addr, addr_str, sizeof(addr_str));
    YLOG_INFO("DHCPv6 Relay: Added server %s", addr_str);

    return 0;
}

int dhcpv6_relay_process(const uint8_t *pkt, uint16_t len,
                         const uint8_t *src_addr, struct interface *iface)
{
    if (!g_dhcpv6_relay.enabled) return 0;
    if (len < 1) return -1;

    uint8_t msg_type = pkt[0];

    if (msg_type == DHCPV6_RELAY_REPL) {
        /* Server -> Client */
        g_dhcpv6_relay.relayed_replies++;
        YLOG_DEBUG("DHCPv6 Relay: Forwarding reply to client");
        /* TODO: Unwrap and forward to client */
    } else if (msg_type >= 1 && msg_type <= 11) {
        /* Client -> Server */
        g_dhcpv6_relay.relayed_requests++;

        /* Build Relay-Forward message */
        uint8_t relay_msg[1500];
        struct dhcpv6_relay_hdr *hdr = (struct dhcpv6_relay_hdr *)relay_msg;

        hdr->msg_type = DHCPV6_RELAY_FORW;
        hdr->hop_count = 0;

        /* Set link-address to interface address */
        memcpy(hdr->link_addr, iface->ipv6_addr, 16);

        /* Set peer-address to client address */
        memcpy(hdr->peer_addr, src_addr, 16);

        /* Add Interface-ID option */
        uint8_t *opts = hdr->options;
        *(uint16_t *)opts = htons(DHCPV6_OPT_INTERFACE_ID);
        opts += 2;
        *(uint16_t *)opts = htons(4);
        opts += 2;
        *(uint32_t *)opts = htonl(iface->ifindex);
        opts += 4;

        /* Add Relay-Message option */
        *(uint16_t *)opts = htons(DHCPV6_OPT_RELAY_MSG);
        opts += 2;
        *(uint16_t *)opts = htons(len);
        opts += 2;
        memcpy(opts, pkt, len);
        opts += len;

        size_t relay_len = opts - relay_msg;

        /* Forward to all servers */
        for (int i = 0; i < g_dhcpv6_relay.server_count; i++) {
            /* TODO: Send to server via UDP */
            (void)relay_len;
        }

        YLOG_DEBUG("DHCPv6 Relay: Forwarding request to server");
    }

    return 0;
}

void dhcpv6_relay_print(void)
{
    printf("DHCPv6 Relay: %s\n", g_dhcpv6_relay.enabled ? "enabled" : "disabled");
    printf("Servers: %d\n", g_dhcpv6_relay.server_count);

    for (int i = 0; i < g_dhcpv6_relay.server_count; i++) {
        char addr_str[64];
        inet_ntop(AF_INET6, g_dhcpv6_relay.servers[i], addr_str, sizeof(addr_str));
        printf("  %s\n", addr_str);
    }

    printf("\nStatistics:\n");
    printf("  Relayed Requests: %lu\n", g_dhcpv6_relay.relayed_requests);
    printf("  Relayed Replies:  %lu\n", g_dhcpv6_relay.relayed_replies);
}

void dhcpv6_relay_cleanup(void)
{
    memset(&g_dhcpv6_relay, 0, sizeof(g_dhcpv6_relay));
    YLOG_INFO("DHCPv6 Relay cleanup complete");
}
