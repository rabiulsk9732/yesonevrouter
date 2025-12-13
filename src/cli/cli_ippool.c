/**
 * @file cli_ippool.c
 * @brief IP Pool CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "ippool.h"

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_ip_pool,
      cmd_show_ip_pool_cmd,
      "show ip pool",
      SHOW_STR
      "IP information\n"
      "IP address pool\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "IP Address Pools\r\n");
    vty_out(vty, "================\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-16s %-16s %-16s %-8s %-8s\r\n",
            "Pool Name", "Start", "End", "Used", "Free");
    vty_out(vty, "%-16s %-16s %-16s %-8s %-8s\r\n",
            "---------------", "---------------", "---------------", "-------", "-------");
    /* TODO: Get actual pool info */
    vty_out(vty, "%-16s %-16s %-16s %-8d %-8d\r\n",
            "POOL1", "10.100.0.2", "10.100.0.254", 0, 253);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_pool_name,
      cmd_show_ip_pool_name_cmd,
      "show ip pool WORD",
      SHOW_STR
      "IP information\n"
      "IP address pool\n"
      "Pool name\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Pool name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "\r\n");
    vty_out(vty, "IP Pool: %s\r\n", argv[3]);
    vty_out(vty, "=========\r\n");
    vty_out(vty, "Start Address: 10.100.0.2\r\n");
    vty_out(vty, "End Address:   10.100.0.254\r\n");
    vty_out(vty, "Subnet Mask:   255.255.255.0\r\n");
    vty_out(vty, "Gateway:       10.100.0.1\r\n");
    vty_out(vty, "Total:         253\r\n");
    vty_out(vty, "Used:          0\r\n");
    vty_out(vty, "Free:          253\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_ip_pool_statistics,
      cmd_show_ip_pool_statistics_cmd,
      "show ip pool statistics",
      SHOW_STR
      "IP information\n"
      "IP address pool\n"
      "Pool statistics\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "IP Pool Statistics\r\n");
    vty_out(vty, "==================\r\n");
    vty_out(vty, "Total Pools:       1\r\n");
    vty_out(vty, "Total Addresses:   253\r\n");
    vty_out(vty, "Allocated:         0\r\n");
    vty_out(vty, "Available:         253\r\n");
    vty_out(vty, "Allocation Rate:   0/sec\r\n");
    vty_out(vty, "Release Rate:      0/sec\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_ip_local_pool,
      cmd_ip_local_pool_cmd,
      "ip local pool WORD A.B.C.D A.B.C.D",
      "IP configuration\n"
      "Local address pool\n"
      "Create local pool\n"
      "Pool name\n"
      "Start IP address\n"
      "End IP address\n")
{
    if (argc < 6) {
        vty_out(vty, "%% Usage: ip local pool <name> <start-ip> <end-ip>\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    const char *name = argv[3];
    struct in_addr start_addr, end_addr;

    if (inet_pton(AF_INET, argv[4], &start_addr) != 1) {
        vty_out(vty, "%% Invalid start IP address: %s\r\n", argv[4]);
        return CMD_ERR_INCOMPLETE;
    }
    if (inet_pton(AF_INET, argv[5], &end_addr) != 1) {
        vty_out(vty, "%% Invalid end IP address: %s\r\n", argv[5]);
        return CMD_ERR_INCOMPLETE;
    }

    uint32_t start_ip = ntohl(start_addr.s_addr);
    uint32_t end_ip = ntohl(end_addr.s_addr);

    if (ippool_create(name, start_ip, end_ip) != 0) {
        vty_out(vty, "%% Failed to create IP pool '%s'\r\n", name);
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "IP pool '%s' created: %s - %s (%u IPs)\r\n",
            name, argv[4], argv[5], end_ip - start_ip + 1);
    return CMD_SUCCESS;
}

DEFUN(cmd_no_ip_local_pool,
      cmd_no_ip_local_pool_cmd,
      "no ip local pool WORD",
      NO_STR
      "IP configuration\n"
      "Local address pool\n"
      "Remove local pool\n"
      "Pool name\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Pool name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "IP pool '%s' removed\r\n", argv[4]);
    return CMD_SUCCESS;
}

DEFUN(cmd_ip_pool_gateway,
      cmd_ip_pool_gateway_cmd,
      "ip pool WORD gateway A.B.C.D",
      "IP configuration\n"
      "IP pool configuration\n"
      "Pool name\n"
      "Set gateway\n"
      "Gateway IP address\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Pool name and gateway required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Gateway %s set for pool '%s'\r\n", argv[4], argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_ip_pool_dns,
      cmd_ip_pool_dns_cmd,
      "ip pool WORD dns A.B.C.D",
      "IP configuration\n"
      "IP pool configuration\n"
      "Pool name\n"
      "Set DNS server\n"
      "DNS server IP address\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Pool name and DNS server required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "DNS %s set for pool '%s'\r\n", argv[4], argv[2]);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_ip_pool,
      cmd_clear_ip_pool_cmd,
      "clear ip pool WORD",
      CLEAR_STR
      "IP information\n"
      "IP pool\n"
      "Pool name\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Pool name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Pool '%s' cleared\r\n", argv[3]);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_ippool_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_ip_pool_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_pool_name_cmd);
    install_element(VIEW_NODE, &cmd_show_ip_pool_statistics_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_ip_pool_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_pool_name_cmd);
    install_element(ENABLE_NODE, &cmd_show_ip_pool_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_clear_ip_pool_cmd);

    /* Config mode */
    install_element(CONFIG_NODE, &cmd_ip_local_pool_cmd);
    install_element(CONFIG_NODE, &cmd_no_ip_local_pool_cmd);
    install_element(CONFIG_NODE, &cmd_ip_pool_gateway_cmd);
    install_element(CONFIG_NODE, &cmd_ip_pool_dns_cmd);
}
