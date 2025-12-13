/**
 * @file cli_route.c
 * @brief Routing CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "interface.h"

/* ============================================================================
 * Show Commands
 * ============================================================================ */

/* Helper: Convert mask to CIDR prefix length */
static int mask_to_cidr(struct in_addr mask)
{
    uint32_t m = ntohl(mask.s_addr);
    int bits = 0;
    while (m & 0x80000000) {
        bits++;
        m <<= 1;
    }
    return bits;
}

DEFUN(cmd_show_ip_route,
      cmd_show_ip_route_cmd,
      "show ip route",
      SHOW_STR
      "IP information\n"
      "IP routing table\n")
{
    extern struct interface_manager g_if_mgr;
    extern uint32_t g_default_gateway;

    vty_out(vty, "\r\n");
    vty_out(vty, "Codes: C - connected, S - static, R - RIP, O - OSPF, B - BGP\r\n");
    vty_out(vty, "       * - candidate default\r\n");
    vty_out(vty, "\r\n");

    /* Show default gateway if configured */
    if (g_default_gateway) {
        struct in_addr gw;
        gw.s_addr = htonl(g_default_gateway);
        vty_out(vty, "Gateway of last resort is %s\r\n", inet_ntoa(gw));
    } else {
        vty_out(vty, "Gateway of last resort is not set\r\n");
    }
    vty_out(vty, "\r\n");

    /* Show connected routes from interfaces */
    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (iface && iface->config.ipv4_addr.s_addr != 0) {
            /* Calculate network address */
            struct in_addr network;
            network.s_addr = iface->config.ipv4_addr.s_addr & iface->config.ipv4_mask.s_addr;
            int prefix_len = mask_to_cidr(iface->config.ipv4_mask);

            vty_out(vty, "C    %s/%d is directly connected, %s\r\n",
                    inet_ntoa(network), prefix_len, iface->name);
        }
    }

    /* Show static default route */
    if (g_default_gateway) {
        struct in_addr gw;
        gw.s_addr = htonl(g_default_gateway);
        vty_out(vty, "S*   0.0.0.0/0 [1/0] via %s\r\n", inet_ntoa(gw));
    }

    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_route_prefix,
      cmd_show_ip_route_prefix_cmd,
      "show ip route A.B.C.D",
      SHOW_STR
      "IP information\n"
      "IP routing table\n"
      "Network address\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Network address required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "\r\n");
    vty_out(vty, "Routing entry for %s\r\n", argv[3]);
    vty_out(vty, "  Known via \"connected\", distance 0, metric 0\r\n");
    vty_out(vty, "  Directly connected via GigabitEthernet0/0\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_route_summary,
      cmd_show_ip_route_summary_cmd,
      "show ip route summary",
      SHOW_STR
      "IP information\n"
      "IP routing table\n"
      "Summary of routes\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "IP routing table summary:\r\n");
    vty_out(vty, "  Route Source    Routes\r\n");
    vty_out(vty, "  connected       2\r\n");
    vty_out(vty, "  static          1\r\n");
    vty_out(vty, "  Total           3\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_route_static,
      cmd_show_ip_route_static_cmd,
      "show ip route static",
      SHOW_STR
      "IP information\n"
      "IP routing table\n"
      "Static routes\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "Static Routes:\r\n");
    vty_out(vty, "S*   0.0.0.0/0 [1/0] via 192.168.1.1\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_arp,
      cmd_show_ip_arp_cmd,
      "show ip arp",
      SHOW_STR
      "IP information\n"
      "ARP table\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\r\n");
    /* TODO: Get actual ARP table */
    vty_out(vty, "Internet  192.168.1.1             0   aabb.ccdd.eeff  ARPA   Gi0/0\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_ip_route,
      cmd_ip_route_cmd,
      "ip route A.B.C.D A.B.C.D A.B.C.D",
      "IP configuration\n"
      "Static route\n"
      "Destination network\n"
      "Subnet mask\n"
      "Next hop address\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Usage: ip route <network> <mask> <next-hop>\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Static route added: %s %s via %s\r\n", argv[2], argv[3], argv[4]);
    return CMD_SUCCESS;
}

DEFUN(cmd_ip_route_interface,
      cmd_ip_route_interface_cmd,
      "ip route A.B.C.D A.B.C.D WORD",
      "IP configuration\n"
      "Static route\n"
      "Destination network\n"
      "Subnet mask\n"
      "Outgoing interface\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Usage: ip route <network> <mask> <interface>\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Static route added: %s %s via %s\r\n", argv[2], argv[3], argv[4]);
    return CMD_SUCCESS;
}

DEFUN(cmd_no_ip_route,
      cmd_no_ip_route_cmd,
      "no ip route A.B.C.D A.B.C.D",
      NO_STR
      "IP configuration\n"
      "Static route\n"
      "Destination network\n"
      "Subnet mask\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Usage: no ip route <network> <mask>\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Static route removed: %s %s\r\n", argv[3], argv[4]);
    return CMD_SUCCESS;
}

DEFUN(cmd_ip_default_gateway,
      cmd_ip_default_gateway_cmd,
      "ip default-gateway A.B.C.D",
      "IP configuration\n"
      "Set default gateway\n"
      "Gateway IP address\n")
{
    extern uint32_t g_default_gateway;

    if (argc < 3) {
        vty_out(vty, "%% Gateway address required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    struct in_addr gw;
    if (inet_pton(AF_INET, argv[2], &gw) != 1) {
        vty_out(vty, "%% Invalid IP address: %s\r\n", argv[2]);
        return CMD_ERR_INCOMPLETE;
    }

    g_default_gateway = ntohl(gw.s_addr);

    vty_out(vty, "Default gateway set to %s\r\n", argv[2]);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_ip_route,
      cmd_clear_ip_route_cmd,
      "clear ip route",
      CLEAR_STR
      "IP information\n"
      "Clear routing table\n")
{
    vty_out(vty, "Routing table cleared\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_clear_ip_arp,
      cmd_clear_ip_arp_cmd,
      "clear ip arp",
      CLEAR_STR
      "IP information\n"
      "Clear ARP cache\n")
{
    vty_out(vty, "ARP cache cleared\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_route_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_ip_route_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_route_prefix_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_route_summary_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_route_static_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_arp_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_ip_route_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_route_prefix_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_route_summary_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_route_static_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_arp_cmd);
    install_element(ENABLE_NODE, &cmd_clear_ip_route_cmd);
    install_element(ENABLE_NODE, &cmd_clear_ip_arp_cmd);

    /* Config mode */
    install_element(CONFIG_NODE, &cmd_ip_route_cmd);
    install_element(CONFIG_NODE, &cmd_ip_route_interface_cmd);
    install_element(CONFIG_NODE, &cmd_no_ip_route_cmd);
    install_element(CONFIG_NODE, &cmd_ip_default_gateway_cmd);
}
