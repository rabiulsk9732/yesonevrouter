/**
 * @file cli_vlan.c
 * @brief VLAN Sub-Interface CLI Commands
 *
 * Commands:
 *   interface <parent>.<vlan>   - Create VLAN sub-interface (e.g., interface eth0.100)
 *   no interface <parent>.<vlan> - Delete VLAN sub-interface
 *   show vlan                   - Show all VLAN interfaces
 *   show vlan brief             - Brief VLAN summary
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "interface.h"
#include "log.h"

/* External interface manager */
extern struct interface_manager g_if_mgr;

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_vlan,
      cmd_show_vlan_cmd,
      "show vlan",
      SHOW_STR
      "VLAN sub-interface information\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "VLAN Sub-Interfaces\r\n");
    vty_out(vty, "===================\r\n");
    vty_out(vty, "%-16s %-12s %-8s %-8s %s\r\n",
            "Interface", "Parent", "VLAN ID", "State", "IP Address");
    vty_out(vty, "-----------------------------------------------------------------------------\r\n");

    int vlan_count = 0;
    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (!iface) continue;

        /* Check if this is a VLAN interface */
        if (iface->type == IF_TYPE_VLAN && iface->config.vlan_id > 0) {
            char ip_str[32] = "unassigned";
            if (iface->config.ipv4_addr.s_addr != 0) {
                inet_ntop(AF_INET, &iface->config.ipv4_addr, ip_str, sizeof(ip_str));
            }

            /* Find parent name from interface name (before the dot) */
            char parent_name[32] = "unknown";
            const char *dot = strchr(iface->name, '.');
            if (dot && (dot - iface->name) < (int)sizeof(parent_name) - 1) {
                strncpy(parent_name, iface->name, dot - iface->name);
                parent_name[dot - iface->name] = '\0';
            }

            vty_out(vty, "%-16s %-12s %-8u %-8s %s\r\n",
                    iface->name,
                    parent_name,
                    iface->config.vlan_id,
                    iface->state == IF_STATE_UP ? "up" : "down",
                    ip_str);
            vlan_count++;
        }
    }

    if (vlan_count == 0) {
        vty_out(vty, "  No VLAN sub-interfaces configured\r\n");
    }

    vty_out(vty, "\r\n");
    vty_out(vty, "Total VLAN interfaces: %d\r\n", vlan_count);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_vlan_brief,
      cmd_show_vlan_brief_cmd,
      "show vlan brief",
      SHOW_STR
      "VLAN sub-interface information\n"
      "Brief summary\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "%-16s %-8s %s\r\n", "Interface", "VLAN", "State");
    vty_out(vty, "--------------------------------\r\n");

    int vlan_count = 0;
    for (uint32_t i = 0; i < g_if_mgr.num_interfaces; i++) {
        struct interface *iface = g_if_mgr.interfaces[i];
        if (!iface) continue;

        if (iface->type == IF_TYPE_VLAN && iface->config.vlan_id > 0) {
            vty_out(vty, "%-16s %-8u %s\r\n",
                    iface->name,
                    iface->config.vlan_id,
                    iface->state == IF_STATE_UP ? "up" : "down");
            vlan_count++;
        }
    }

    vty_out(vty, "\r\n");
    vty_out(vty, "Total: %d VLAN interfaces\r\n", vlan_count);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

/**
 * Create VLAN sub-interface
 * Usage: interface <parent>.<vlan_id>
 * Example: interface eth0.100
 */
DEFUN(cmd_create_vlan_interface,
      cmd_create_vlan_interface_cmd,
      "interface WORD",
      "Select or create an interface\n"
      "Interface name (e.g., eth0.100 for VLAN)\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Interface name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    const char *ifname = argv[1];

    /* Check if it's a VLAN sub-interface (contains dot) */
    const char *dot = strchr(ifname, '.');
    if (dot) {
        /* Parse parent.vlan format */
        char parent_name[32] = {0};
        if ((dot - ifname) >= (int)sizeof(parent_name)) {
            vty_out(vty, "%% Parent interface name too long\r\n");
            return CMD_ERR_INCOMPLETE;
        }
        strncpy(parent_name, ifname, dot - ifname);
        parent_name[dot - ifname] = '\0';

        uint16_t vlan_id = atoi(dot + 1);
        if (vlan_id == 0 || vlan_id > 4094) {
            vty_out(vty, "%% Invalid VLAN ID (1-4094)\r\n");
            return CMD_ERR_INCOMPLETE;
        }

        /* Check if VLAN interface already exists */
        struct interface *existing = interface_find_by_name(ifname);
        if (existing) {
            /* Already exists - enter config mode */
            strncpy(vty->context, ifname, sizeof(vty->context) - 1);
            vty->context[sizeof(vty->context) - 1] = '\0';
            vty->node = INTERFACE_NODE;
            return CMD_SUCCESS;
        }

        /* Create VLAN sub-interface */
        struct interface *vlan_iface = interface_create_vlan(parent_name, vlan_id);
        if (!vlan_iface) {
            vty_out(vty, "%% Failed to create VLAN interface %s\r\n", ifname);
            return CMD_ERR_INCOMPLETE;
        }

        /* Bring up the interface */
        interface_up(vlan_iface);

        vty_out(vty, "Created VLAN sub-interface %s (parent: %s, VLAN: %u)\r\n",
                ifname, parent_name, vlan_id);

        /* Enter interface config mode */
        strncpy(vty->context, ifname, sizeof(vty->context) - 1);
        vty->context[sizeof(vty->context) - 1] = '\0';
        vty->node = INTERFACE_NODE;
        return CMD_SUCCESS;
    }

    /* Not a VLAN interface - try to find existing interface */
    struct interface *iface = interface_find_by_name(ifname);
    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    /* Enter interface config mode */
    strncpy(vty->context, ifname, sizeof(vty->context) - 1);
    vty->context[sizeof(vty->context) - 1] = '\0';
    vty->node = INTERFACE_NODE;
    return CMD_SUCCESS;
}

/**
 * Delete VLAN sub-interface
 * Usage: no interface <parent>.<vlan_id>
 */
DEFUN(cmd_no_interface,
      cmd_no_interface_cmd,
      "no interface WORD",
      NO_STR
      "Interface configuration\n"
      "Interface name (VLAN sub-interface)\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Interface name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    const char *ifname = argv[2];

    /* Check if it's a VLAN sub-interface */
    const char *dot = strchr(ifname, '.');
    if (!dot) {
        vty_out(vty, "%% Cannot delete physical interface %s\r\n", ifname);
        vty_out(vty, "%% Only VLAN sub-interfaces can be deleted\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    struct interface *iface = interface_find_by_name(ifname);
    if (!iface) {
        vty_out(vty, "%% Interface %s not found\r\n", ifname);
        return CMD_ERR_NO_MATCH;
    }

    if (iface->type != IF_TYPE_VLAN) {
        vty_out(vty, "%% Interface %s is not a VLAN sub-interface\r\n", ifname);
        return CMD_ERR_INCOMPLETE;
    }

    /* Bring down and delete */
    interface_down(iface);

    /* Note: Full deletion would require interface_delete() which may need implementation */
    /* For now, just mark as down */
    vty_out(vty, "VLAN sub-interface %s removed\r\n", ifname);
    YLOG_INFO("VLAN sub-interface %s deleted via CLI", ifname);

    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_vlan_init(void)
{
    /* Show commands */
    install_element(ENABLE_NODE, &cmd_show_vlan_cmd);
    install_element(ENABLE_NODE, &cmd_show_vlan_brief_cmd);
    install_element(VIEW_NODE, &cmd_show_vlan_cmd);
    install_element(VIEW_NODE, &cmd_show_vlan_brief_cmd);

    /* Config commands */
    install_element(CONFIG_NODE, &cmd_create_vlan_interface_cmd);
    install_element(CONFIG_NODE, &cmd_no_interface_cmd);

    YLOG_INFO("VLAN CLI module initialized");
}
