/**
 * @file cli_interface.c
 * @brief Interface CLI Commands (Cisco IOS Style)
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

/* Helper: Convert mask to CIDR */
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

DEFUN(cmd_show_interfaces,
      cmd_show_interfaces_cmd,
      "show interfaces",
      SHOW_STR
      "Interface status and configuration\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "Interface Status\r\n");
    vty_out(vty, "================\r\n");
    vty_out(vty, "\r\n");

    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (!iface) continue;

        const char *state = (iface->state == IF_STATE_UP) ? "up" : "down";
        const char *link = (iface->link == LINK_STATE_UP) ? "up" : "down";

        vty_out(vty, "%s is %s, line protocol is %s\r\n", iface->name, state, link);
        vty_out(vty, "  Hardware is %s, address is %02x:%02x:%02x:%02x:%02x:%02x\r\n",
                interface_type_to_str(iface->type),
                iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
                iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5]);

        if (iface->config.ipv4_addr.s_addr) {
            int prefix = mask_to_cidr(iface->config.ipv4_mask);
            vty_out(vty, "  Internet address is %s/%d\r\n",
                    inet_ntoa(iface->config.ipv4_addr), prefix);
        } else {
            vty_out(vty, "  Internet address is unassigned\r\n");
        }

        vty_out(vty, "  MTU %u bytes\r\n", iface->config.mtu ? iface->config.mtu : 1500);
        if (iface->config.nat_inside)
            vty_out(vty, "  NAT inside\r\n");
        if (iface->config.nat_outside)
            vty_out(vty, "  NAT outside\r\n");
        vty_out(vty, "\r\n");
    }

    return CMD_SUCCESS;
}

DEFUN(cmd_show_interfaces_brief,
      cmd_show_interfaces_brief_cmd,
      "show interfaces brief",
      SHOW_STR
      "Interface status and configuration\n"
      "Brief summary\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "%-24s %-16s %-10s %-10s\r\n",
            "Interface", "IP Address", "Status", "Protocol");
    vty_out(vty, "%-24s %-16s %-10s %-10s\r\n",
            "-----------------------", "---------------", "---------", "---------");

    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (!iface) continue;

        char ip_str[32];
        if (iface->config.ipv4_addr.s_addr) {
            snprintf(ip_str, sizeof(ip_str), "%s", inet_ntoa(iface->config.ipv4_addr));
        } else {
            snprintf(ip_str, sizeof(ip_str), "unassigned");
        }

        const char *state = (iface->state == IF_STATE_UP) ? "up" : "down";
        const char *link = (iface->link == LINK_STATE_UP) ? "up" : "down";

        vty_out(vty, "%-24s %-16s %-10s %-10s\r\n",
                iface->name, ip_str, state, link);
    }

    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_interface,
      cmd_show_interface_cmd,
      "show interface WORD",
      SHOW_STR
      "Interface status\n"
      "Interface name\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Interface name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    const char *ifname = argv[2];
    struct interface *iface = interface_find_by_name(ifname);

    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    const char *state = (iface->state == IF_STATE_UP) ? "up" : "down";
    const char *link = (iface->link == LINK_STATE_UP) ? "up" : "down";

    vty_out(vty, "\r\n");
    vty_out(vty, "%s is %s, line protocol is %s\r\n", iface->name, state, link);
    vty_out(vty, "  Hardware is %s\r\n", interface_type_to_str(iface->type));
    vty_out(vty, "  MAC address: %02x:%02x:%02x:%02x:%02x:%02x\r\n",
            iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
            iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5]);

    if (iface->config.ipv4_addr.s_addr) {
        int prefix = mask_to_cidr(iface->config.ipv4_mask);
        vty_out(vty, "  Internet address is %s/%d\r\n",
                inet_ntoa(iface->config.ipv4_addr), prefix);
    } else {
        vty_out(vty, "  Internet address is unassigned\r\n");
    }

    vty_out(vty, "  MTU %u bytes\r\n", iface->config.mtu ? iface->config.mtu : 1500);
    vty_out(vty, "  Input packets: %lu, bytes: %lu\r\n",
            iface->stats.rx_packets, iface->stats.rx_bytes);
    vty_out(vty, "  Output packets: %lu, bytes: %lu\r\n",
            iface->stats.tx_packets, iface->stats.tx_bytes);
    if (iface->config.nat_inside)
        vty_out(vty, "  NAT inside\r\n");
    if (iface->config.nat_outside)
        vty_out(vty, "  NAT outside\r\n");
    vty_out(vty, "\r\n");

    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_interface,
      cmd_interface_cmd,
      "interface WORD",
      "Select an interface to configure\n"
      "Interface name\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Interface name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    strncpy(vty->context, argv[1], sizeof(vty->context) - 1);
    vty->node = INTERFACE_NODE;

    return CMD_SUCCESS;
}

DEFUN(cmd_if_description,
      cmd_if_description_cmd,
      "description LINE",
      "Interface description\n"
      "Description text\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Description required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Description set for %s\r\n", vty->context);
    /* TODO: Set interface description */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_ip_address,
      cmd_if_ip_address_cmd,
      "ip address A.B.C.D A.B.C.D",
      "IP configuration\n"
      "Set IP address\n"
      "IP address\n"
      "Subnet mask\n")
{
    if (argc < 4) {
        vty_out(vty, "%% IP address and mask required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    const char *ifname = vty->context;
    struct interface *iface = interface_find_by_name(ifname);

    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    struct in_addr addr, mask;
    if (inet_pton(AF_INET, argv[2], &addr) != 1) {
        vty_out(vty, "%% Invalid IP address: %s\r\n", argv[2]);
        return CMD_ERR_INCOMPLETE;
    }
    if (inet_pton(AF_INET, argv[3], &mask) != 1) {
        vty_out(vty, "%% Invalid subnet mask: %s\r\n", argv[3]);
        return CMD_ERR_INCOMPLETE;
    }

    /* Apply to running config */
    iface->config.ipv4_addr = addr;
    iface->config.ipv4_mask = mask;

    vty_out(vty, "IP address %s %s configured on %s\r\n", argv[2], argv[3], ifname);
    return CMD_SUCCESS;
}

DEFUN(cmd_if_no_ip_address,
      cmd_if_no_ip_address_cmd,
      "no ip address",
      NO_STR
      "IP configuration\n"
      "Remove IP address\n")
{
    const char *ifname = vty->context;
    struct interface *iface = interface_find_by_name(ifname);

    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    iface->config.ipv4_addr.s_addr = 0;
    iface->config.ipv4_mask.s_addr = 0;

    vty_out(vty, "IP address removed from %s\r\n", ifname);
    return CMD_SUCCESS;
}

DEFUN(cmd_if_shutdown,
      cmd_if_shutdown_cmd,
      "shutdown",
      "Shutdown the interface\n")
{
    const char *ifname = vty->context;
    struct interface *iface = interface_find_by_name(ifname);

    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    iface->state = IF_STATE_ADMIN_DOWN;

    vty_out(vty, "Interface %s administratively down\r\n", ifname);
    return CMD_SUCCESS;
}

DEFUN(cmd_if_no_shutdown,
      cmd_if_no_shutdown_cmd,
      "no shutdown",
      NO_STR
      "Bring up the interface\n")
{
    const char *ifname = vty->context;
    struct interface *iface = interface_find_by_name(ifname);

    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    iface->state = IF_STATE_UP;

    vty_out(vty, "Interface %s enabled\r\n", ifname);
    return CMD_SUCCESS;
}

DEFUN(cmd_if_mtu,
      cmd_if_mtu_cmd,
      "mtu <64-9216>",
      "Set MTU size\n"
      "MTU value\n")
{
    if (argc < 2) {
        vty_out(vty, "%% MTU value required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    int mtu = atoi(argv[1]);
    vty_out(vty, "MTU set to %d on %s\r\n", mtu, vty->context);
    /* TODO: Set MTU on interface */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_pppoe_enable,
      cmd_if_pppoe_enable_cmd,
      "pppoe enable",
      "PPPoE configuration\n"
      "Enable PPPoE on interface\n")
{
    vty_out(vty, "PPPoE enabled on %s\r\n", vty->context);
    /* TODO: Enable PPPoE on interface */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_no_pppoe_enable,
      cmd_if_no_pppoe_enable_cmd,
      "no pppoe enable",
      NO_STR
      "PPPoE configuration\n"
      "Disable PPPoE on interface\n")
{
    vty_out(vty, "PPPoE disabled on %s\r\n", vty->context);
    /* TODO: Disable PPPoE on interface */
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_interface_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_interfaces_cmd);
    install_element(VIEW_NODE, &cmd_show_interfaces_brief_cmd);
    install_element(VIEW_NODE, &cmd_show_interface_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_interfaces_cmd);
    install_element(ENABLE_NODE, &cmd_show_interfaces_brief_cmd);
    install_element(ENABLE_NODE, &cmd_show_interface_cmd);

    /* Config mode */
    install_element(CONFIG_NODE, &cmd_interface_cmd);

    /* Interface config mode */
    install_element(INTERFACE_NODE, &cmd_if_description_cmd);
    install_element(INTERFACE_NODE, &cmd_if_ip_address_cmd);
    install_element(INTERFACE_NODE, &cmd_if_no_ip_address_cmd);
    install_element(INTERFACE_NODE, &cmd_if_shutdown_cmd);
    install_element(INTERFACE_NODE, &cmd_if_no_shutdown_cmd);
    install_element(INTERFACE_NODE, &cmd_if_mtu_cmd);
    install_element(INTERFACE_NODE, &cmd_if_pppoe_enable_cmd);
    install_element(INTERFACE_NODE, &cmd_if_no_pppoe_enable_cmd);
}
