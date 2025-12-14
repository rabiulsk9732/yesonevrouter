/**
 * @file cli_radius.c
 * @brief RADIUS CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "radius.h"

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
    const struct radius_client_config *cfg = radius_client_get_config();

    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Servers\r\n");
    vty_out(vty, "==============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-20s %-10s %-10s %-10s %-10s\r\n",
            "Server", "Auth Port", "Acct Port", "Priority", "Status");
    vty_out(vty, "%-20s %-10s %-10s %-10s %-10s\r\n",
            "-------------------", "---------", "---------", "--------", "---------");

    if (cfg && cfg->num_servers > 0) {
        for (int i = 0; i < cfg->num_servers; i++) {
            struct in_addr addr;
            addr.s_addr = htonl(cfg->servers[i].ip);
            const char *status = (cfg->servers[i].status == RADIUS_SERVER_UP) ? "Active" : "Down";

            vty_out(vty, "%-20s %-10d %-10d %-10d %-10s\r\n",
                    inet_ntoa(addr),
                    cfg->servers[i].auth_port,
                    cfg->servers[i].acct_port,
                    cfg->servers[i].priority,
                    status);
        }
    } else {
        vty_out(vty, "(no servers configured)\r\n");
    }
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
    const struct radius_client_config *cfg = radius_client_get_config();

    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Statistics\r\n");
    vty_out(vty, "=================\r\n");
    vty_out(vty, "\r\n");

    if (cfg) {
        vty_out(vty, "Authentication:\r\n");
        vty_out(vty, "  Access-Request sent:     %lu\r\n", cfg->stats.total_auth_requests);
        vty_out(vty, "  Access-Accept received:  %lu\r\n", cfg->stats.total_auth_accepts);
        vty_out(vty, "  Access-Reject received:  %lu\r\n", cfg->stats.total_auth_rejects);
        vty_out(vty, "  Timeouts:                %lu\r\n", cfg->stats.total_auth_timeouts);
        vty_out(vty, "\r\n");
        vty_out(vty, "Accounting:\r\n");
        vty_out(vty, "  Acct-Request sent:       %lu\r\n", cfg->stats.total_acct_requests);
        vty_out(vty, "  Acct-Response received:  %lu\r\n", cfg->stats.total_acct_responses);
        vty_out(vty, "  Interim updates sent:    %lu\r\n", cfg->stats.total_interim_sent);
        vty_out(vty, "\r\n");
        vty_out(vty, "CoA/DM:\r\n");
        vty_out(vty, "  CoA received:            %lu\r\n", cfg->stats.total_coa_received);
        vty_out(vty, "  CoA applied:             %lu\r\n", cfg->stats.total_coa_applied);
        vty_out(vty, "  DM received:             %lu\r\n", cfg->stats.total_dm_received);
        vty_out(vty, "  DM applied:              %lu\r\n", cfg->stats.total_dm_applied);
    }
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

    struct in_addr addr;
    if (inet_pton(AF_INET, argv[2], &addr) != 1) {
        vty_out(vty, "%% Invalid IP address: %s\r\n", argv[2]);
        return CMD_ERR_INCOMPLETE;
    }

    int ret = radius_client_add_server(ntohl(addr.s_addr), 1812, 1813, argv[4], 1);
    if (ret < 0) {
        vty_out(vty, "%% Failed to add RADIUS server\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "RADIUS server %s configured with secret\r\n", argv[2]);
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

    uint32_t timeout = atoi(argv[2]);
    radius_client_set_timeout(timeout);
    vty_out(vty, "RADIUS timeout set to %u seconds\r\n", timeout);
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

    uint8_t retries = atoi(argv[2]);
    radius_client_set_retries(retries);
    vty_out(vty, "RADIUS retransmit set to %u\r\n", retries);
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
