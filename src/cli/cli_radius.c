/**
 * @file cli_radius.c
 * @brief RADIUS CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"
#include "vty.h"

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_radius,
      cmd_show_radius_cmd,
      "show radius",
      SHOW_STR
      "RADIUS information\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Configuration\r\n");
    vty_out(vty, "====================\r\n");
    vty_out(vty, "Use 'show radius server' for server details\r\n");
    vty_out(vty, "Use 'show radius statistics' for statistics\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_radius_server,
      cmd_show_radius_server_cmd,
      "show radius server",
      SHOW_STR
      "RADIUS information\n"
      "RADIUS server configuration\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Servers\r\n");
    vty_out(vty, "==============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-20s %-10s %-10s %-10s\r\n",
            "Server", "Auth Port", "Acct Port", "Status");
    vty_out(vty, "%-20s %-10s %-10s %-10s\r\n",
            "-------------------", "---------", "---------", "---------");
    /* TODO: Get actual RADIUS server config */
    vty_out(vty, "%-20s %-10d %-10d %-10s\r\n",
            "127.0.0.1", 1812, 1813, "Active");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_radius_statistics,
      cmd_show_radius_statistics_cmd,
      "show radius statistics",
      SHOW_STR
      "RADIUS information\n"
      "RADIUS statistics\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Statistics\r\n");
    vty_out(vty, "=================\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "Authentication:\r\n");
    vty_out(vty, "  Access-Request sent:     0\r\n");
    vty_out(vty, "  Access-Accept received:  0\r\n");
    vty_out(vty, "  Access-Reject received:  0\r\n");
    vty_out(vty, "  Access-Challenge recv:   0\r\n");
    vty_out(vty, "  Timeouts:                0\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "Accounting:\r\n");
    vty_out(vty, "  Acct-Request sent:       0\r\n");
    vty_out(vty, "  Acct-Response received:  0\r\n");
    vty_out(vty, "  Timeouts:                0\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_radius_statistics,
      cmd_clear_radius_statistics_cmd,
      "clear radius statistics",
      CLEAR_STR
      "RADIUS information\n"
      "Clear RADIUS statistics\n")
{
    vty_out(vty, "RADIUS statistics cleared\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Debug Commands
 * ============================================================================ */

DEFUN(cmd_debug_radius,
      cmd_debug_radius_cmd,
      "debug radius",
      DEBUG_STR
      "RADIUS debugging\n")
{
    vty_out(vty, "RADIUS debugging enabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_debug_radius_auth,
      cmd_debug_radius_auth_cmd,
      "debug radius authentication",
      DEBUG_STR
      "RADIUS debugging\n"
      "Authentication debugging\n")
{
    vty_out(vty, "RADIUS authentication debugging enabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_debug_radius_acct,
      cmd_debug_radius_acct_cmd,
      "debug radius accounting",
      DEBUG_STR
      "RADIUS debugging\n"
      "Accounting debugging\n")
{
    vty_out(vty, "RADIUS accounting debugging enabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_no_debug_radius,
      cmd_no_debug_radius_cmd,
      "no debug radius",
      NO_STR
      DEBUG_STR
      "RADIUS debugging\n")
{
    vty_out(vty, "RADIUS debugging disabled\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_radius_server_host,
      cmd_radius_server_host_cmd,
      "radius-server host A.B.C.D",
      "RADIUS server configuration\n"
      "Specify a RADIUS server\n"
      "IP address of RADIUS server\n")
{
    if (argc < 3) {
        vty_out(vty, "%% IP address required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS server configured: %s\r\n", argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_radius_server_host_key,
      cmd_radius_server_host_key_cmd,
      "radius-server host A.B.C.D key WORD",
      "RADIUS server configuration\n"
      "Specify a RADIUS server\n"
      "IP address of RADIUS server\n"
      "Set RADIUS encryption key\n"
      "Shared secret\n")
{
    if (argc < 5) {
        vty_out(vty, "%% IP address and key required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS server %s configured with key\r\n", argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_radius_server_timeout,
      cmd_radius_server_timeout_cmd,
      "radius-server timeout <1-1000>",
      "RADIUS server configuration\n"
      "Time to wait for response\n"
      "Timeout in seconds\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Timeout value required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS timeout set to %s seconds\r\n", argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_radius_server_retransmit,
      cmd_radius_server_retransmit_cmd,
      "radius-server retransmit <1-100>",
      "RADIUS server configuration\n"
      "Number of retransmits\n"
      "Retransmit count\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Retransmit count required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS retransmit set to %s\r\n", argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_radius_server_key,
      cmd_radius_server_key_cmd,
      "radius-server key WORD",
      "RADIUS server configuration\n"
      "Set RADIUS encryption key\n"
      "Shared secret\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Key required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS key configured\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_no_radius_server_host,
      cmd_no_radius_server_host_cmd,
      "no radius-server host A.B.C.D",
      NO_STR
      "RADIUS server configuration\n"
      "Remove RADIUS server\n"
      "IP address\n")
{
    if (argc < 4) {
        vty_out(vty, "%% IP address required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "RADIUS server %s removed\r\n", argv[3]);
    return CMD_SUCCESS;
}

DEFUN(cmd_aaa_authentication,
      cmd_aaa_authentication_cmd,
      "aaa authentication ppp default radius",
      "AAA configuration\n"
      "Authentication configuration\n"
      "PPP authentication\n"
      "Default method list\n"
      "Use RADIUS\n")
{
    vty_out(vty, "AAA authentication configured for PPP using RADIUS\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_aaa_accounting,
      cmd_aaa_accounting_cmd,
      "aaa accounting network default start-stop radius",
      "AAA configuration\n"
      "Accounting configuration\n"
      "Network accounting\n"
      "Default method list\n"
      "Start-stop accounting\n"
      "Use RADIUS\n")
{
    vty_out(vty, "AAA accounting configured for network using RADIUS\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_radius_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_radius_cmd);
    install_element(VIEW_NODE, &cmd_show_radius_server_cmd);
    install_element(VIEW_NODE, &cmd_show_radius_statistics_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_radius_cmd);
    install_element(ENABLE_NODE, &cmd_show_radius_server_cmd);
    install_element(ENABLE_NODE, &cmd_show_radius_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_clear_radius_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_debug_radius_cmd);
    install_element(ENABLE_NODE, &cmd_debug_radius_auth_cmd);
    install_element(ENABLE_NODE, &cmd_debug_radius_acct_cmd);
    install_element(ENABLE_NODE, &cmd_no_debug_radius_cmd);

    /* Config mode */
    install_element(CONFIG_NODE, &cmd_radius_server_host_cmd);
    install_element(CONFIG_NODE, &cmd_radius_server_host_key_cmd);
    install_element(CONFIG_NODE, &cmd_radius_server_timeout_cmd);
    install_element(CONFIG_NODE, &cmd_radius_server_retransmit_cmd);
    install_element(CONFIG_NODE, &cmd_radius_server_key_cmd);
    install_element(CONFIG_NODE, &cmd_no_radius_server_host_cmd);
    install_element(CONFIG_NODE, &cmd_aaa_authentication_cmd);
    install_element(CONFIG_NODE, &cmd_aaa_accounting_cmd);
}
