/**
 * @file cli_interface.c
 * @brief Interface CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"
#include "vty.h"

/* ============================================================================
 * Show Commands
 * ============================================================================ */

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

    /* TODO: Get interface list from interface module */
    vty_out(vty, "GigabitEthernet0/0 is up, line protocol is up\r\n");
    vty_out(vty, "  Hardware is DPDK virtio, address is 00:00:00:00:00:01\r\n");
    vty_out(vty, "  Internet address is 192.168.1.1/24\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "GigabitEthernet0/1 is up, line protocol is up\r\n");
    vty_out(vty, "  Hardware is DPDK virtio, address is 00:00:00:00:00:02\r\n");
    vty_out(vty, "  PPPoE enabled\r\n");
    vty_out(vty, "\r\n");

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

    /* TODO: Get interface list from interface module */
    vty_out(vty, "%-24s %-16s %-10s %-10s\r\n",
            "GigabitEthernet0/0", "192.168.1.1", "up", "up");
    vty_out(vty, "%-24s %-16s %-10s %-10s\r\n",
            "GigabitEthernet0/1", "unassigned", "up", "up");

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

    vty_out(vty, "\r\n");
    vty_out(vty, "%s is up, line protocol is up\r\n", ifname);
    vty_out(vty, "  Hardware is DPDK virtio\r\n");
    vty_out(vty, "  Description: \r\n");
    vty_out(vty, "  Internet address is unassigned\r\n");
    vty_out(vty, "  MTU 1500 bytes\r\n");
    vty_out(vty, "  Input packets: 0, bytes: 0\r\n");
    vty_out(vty, "  Output packets: 0, bytes: 0\r\n");
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

    vty_out(vty, "IP address %s %s set on %s\r\n", argv[2], argv[3], vty->context);
    /* TODO: Set IP address on interface */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_no_ip_address,
      cmd_if_no_ip_address_cmd,
      "no ip address",
      NO_STR
      "IP configuration\n"
      "Remove IP address\n")
{
    vty_out(vty, "IP address removed from %s\r\n", vty->context);
    /* TODO: Remove IP address from interface */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_shutdown,
      cmd_if_shutdown_cmd,
      "shutdown",
      "Shutdown the interface\n")
{
    vty_out(vty, "Interface %s shutdown\r\n", vty->context);
    /* TODO: Shutdown interface */
    return CMD_SUCCESS;
}

DEFUN(cmd_if_no_shutdown,
      cmd_if_no_shutdown_cmd,
      "no shutdown",
      NO_STR
      "Bring up the interface\n")
{
    vty_out(vty, "Interface %s enabled\r\n", vty->context);
    /* TODO: Enable interface */
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
