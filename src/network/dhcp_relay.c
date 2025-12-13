/**
 * @file dhcp_relay.c
 * @brief DHCP Relay Agent Implementation (RFC 3046)
 * @details Relays DHCP messages between clients and servers
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "interface.h"
#include "log.h"
#include "packet.h"

/*============================================================================
 * DHCP Constants
 *============================================================================*/

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_BOOTREQUEST    1
#define DHCP_BOOTREPLY      2

#define DHCP_OPT_PAD        0
#define DHCP_OPT_END        255
#define DHCP_OPT_RELAY_INFO 82  /* Option 82 - Relay Agent Information */

#define MAX_DHCP_SERVERS    8
#define MAX_GIADDR          8

/*============================================================================
 * DHCP Header
 *============================================================================*/

struct dhcp_hdr {
    uint8_t  op;            /* Message type */
    uint8_t  htype;         /* Hardware type */
    uint8_t  hlen;          /* Hardware address length */
    uint8_t  hops;          /* Hops */
    uint32_t xid;           /* Transaction ID */
    uint16_t secs;          /* Seconds elapsed */
    uint16_t flags;         /* Flags */
    uint32_t ciaddr;        /* Client IP address */
    uint32_t yiaddr;        /* Your IP address */
    uint32_t siaddr;        /* Server IP address */
    uint32_t giaddr;        /* Gateway IP address */
    uint8_t  chaddr[16];    /* Client hardware address */
    uint8_t  sname[64];     /* Server name */
    uint8_t  file[128];     /* Boot filename */
    uint32_t magic;         /* Magic cookie */
    uint8_t  options[];     /* Options */
} __attribute__((packed));

#define DHCP_MAGIC_COOKIE   0x63825363

/*============================================================================
 * Configuration
 *============================================================================*/

static struct {
    uint32_t servers[MAX_DHCP_SERVERS];
    int      server_count;
    uint32_t giaddr[MAX_GIADDR];
    int      giaddr_count;
    bool     enabled;
    bool     add_option82;
    uint64_t relayed_requests;
    uint64_t relayed_replies;
    uint64_t dropped;
} g_dhcp_relay = {
    .server_count = 0,
    .giaddr_count = 0,
    .enabled = false,
    .add_option82 = true,
    .relayed_requests = 0,
    .relayed_replies = 0,
    .dropped = 0
};

/*============================================================================
 * DHCP Relay Functions
 *============================================================================*/

/**
 * @brief Enable DHCP relay
 */
void dhcp_relay_enable(bool enable)
{
    g_dhcp_relay.enabled = enable;
    YLOG_INFO("DHCP Relay %s", enable ? "enabled" : "disabled");
}

/**
 * @brief Add DHCP server (helper-address)
 */
int dhcp_relay_add_server(uint32_t server_ip)
{
    if (g_dhcp_relay.server_count >= MAX_DHCP_SERVERS) {
        YLOG_ERROR("DHCP Relay: Maximum servers reached");
        return -1;
    }

    g_dhcp_relay.servers[g_dhcp_relay.server_count++] = server_ip;

    char ip_str[32];
    struct in_addr a = {.s_addr = htonl(server_ip)};
    inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
    YLOG_INFO("DHCP Relay: Added server %s", ip_str);

    return 0;
}

/**
 * @brief Set giaddr (gateway address for relay)
 */
int dhcp_relay_set_giaddr(uint32_t giaddr)
{
    if (g_dhcp_relay.giaddr_count >= MAX_GIADDR) {
        YLOG_ERROR("DHCP Relay: Maximum giaddr reached");
        return -1;
    }

    g_dhcp_relay.giaddr[g_dhcp_relay.giaddr_count++] = giaddr;

    char ip_str[32];
    struct in_addr a = {.s_addr = htonl(giaddr)};
    inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
    YLOG_INFO("DHCP Relay: Set giaddr %s", ip_str);

    return 0;
}

/**
 * @brief Add Option 82 to DHCP packet
 */
static int dhcp_relay_add_option82(uint8_t *options, int *len, int max_len,
                                   struct interface *iface, uint16_t vlan_id)
{
    if (*len + 20 > max_len) return -1;

    uint8_t *p = options + *len - 1;  /* Before END option */

    /* Option 82 header */
    *p++ = DHCP_OPT_RELAY_INFO;
    uint8_t *opt82_len = p++;
    *opt82_len = 0;

    /* Sub-option 1: Circuit ID (interface + VLAN) */
    *p++ = 1;  /* Circuit ID */
    *p++ = 6;  /* Length */
    *opt82_len += 8;

    /* Circuit ID format: iface_id (4) + vlan_id (2) */
    *(uint32_t *)p = htonl(iface->ifindex);
    p += 4;
    *(uint16_t *)p = htons(vlan_id);
    p += 2;

    /* Sub-option 2: Remote ID (MAC address) */
    *p++ = 2;  /* Remote ID */
    *p++ = 6;  /* Length */
    *opt82_len += 8;
    memcpy(p, iface->mac_addr, 6);
    p += 6;

    /* END */
    *p++ = DHCP_OPT_END;

    *len = p - options;
    return 0;
}

/**
 * @brief Process DHCP packet for relay
 */
int dhcp_relay_process(struct pkt_buf *pkt, struct interface *iface)
{
    if (!g_dhcp_relay.enabled) return 0;
    if (g_dhcp_relay.server_count == 0) return 0;

    /* Get DHCP header */
    struct dhcp_hdr *dhcp = (struct dhcp_hdr *)(pkt->data + 28);  /* Skip IP+UDP */

    if (dhcp->op == DHCP_BOOTREQUEST) {
        /* Client -> Server: Add giaddr and relay to server(s) */
        if (dhcp->giaddr == 0 && g_dhcp_relay.giaddr_count > 0) {
            dhcp->giaddr = htonl(g_dhcp_relay.giaddr[0]);
        }
        dhcp->hops++;

        /* Forward to all configured servers */
        for (int i = 0; i < g_dhcp_relay.server_count; i++) {
            /* TODO: Send to server via UDP socket */
            (void)g_dhcp_relay.servers[i];
            g_dhcp_relay.relayed_requests++;
        }

        YLOG_DEBUG("DHCP Relay: Request from %02x:%02x:%02x:%02x:%02x:%02x",
                   dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2],
                   dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]);

    } else if (dhcp->op == DHCP_BOOTREPLY) {
        /* Server -> Client: Forward reply to client */
        g_dhcp_relay.relayed_replies++;

        YLOG_DEBUG("DHCP Relay: Reply for %02x:%02x:%02x:%02x:%02x:%02x",
                   dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2],
                   dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]);
    }

    return 0;
}

/**
 * @brief Print DHCP relay status
 */
void dhcp_relay_print(void)
{
    printf("DHCP Relay: %s\n", g_dhcp_relay.enabled ? "enabled" : "disabled");
    printf("Option 82:  %s\n", g_dhcp_relay.add_option82 ? "enabled" : "disabled");
    printf("\n");

    printf("Servers (%d):\n", g_dhcp_relay.server_count);
    for (int i = 0; i < g_dhcp_relay.server_count; i++) {
        char ip_str[32];
        struct in_addr a = {.s_addr = htonl(g_dhcp_relay.servers[i])};
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        printf("  %s\n", ip_str);
    }

    printf("\nStatistics:\n");
    printf("  Relayed Requests: %lu\n", g_dhcp_relay.relayed_requests);
    printf("  Relayed Replies:  %lu\n", g_dhcp_relay.relayed_replies);
    printf("  Dropped:          %lu\n", g_dhcp_relay.dropped);
}
