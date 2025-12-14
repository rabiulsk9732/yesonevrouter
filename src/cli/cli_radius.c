/**
 * @file cli_radius.c
 * @brief RADIUS CLI Commands (Lockless RADIUS)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "radius_lockless.h"

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
    vty_out(vty, "RADIUS Configuration (Lockless Mode)\r\n");
    vty_out(vty, "====================================\r\n");
    
    if (g_radius_ll_ctx) {
        vty_out(vty, "Status: %s\r\n", radius_lockless_is_healthy() ? "Healthy" : "Unhealthy");
        vty_out(vty, "Servers configured: %d\r\n", g_radius_ll_ctx->num_servers);
        
        for (int i = 0; i < g_radius_ll_ctx->num_servers; i++) {
            struct in_addr addr;
            addr.s_addr = htonl(g_radius_ll_ctx->servers[i].ip);
            vty_out(vty, "  Server %d: %s:%d (priority %d)\r\n",
                    i + 1, inet_ntoa(addr),
                    g_radius_ll_ctx->servers[i].auth_port,
                    g_radius_ll_ctx->servers[i].priority);
        }
    } else {
        vty_out(vty, "Status: Not initialized\r\n");
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
    uint64_t submitted, sent, received, accepts, rejects, timeouts, errors, drops;
    radius_lockless_get_stats(&submitted, &sent, &received, &accepts,
                               &rejects, &timeouts, &errors, &drops);

    vty_out(vty, "\r\n");
    vty_out(vty, "RADIUS Statistics (Lockless)\r\n");
    vty_out(vty, "============================\r\n");
    vty_out(vty, "  Requests submitted:  %lu\r\n", submitted);
    vty_out(vty, "  Requests sent:       %lu\r\n", sent);
    vty_out(vty, "  Responses received:  %lu\r\n", received);
    vty_out(vty, "  Access-Accept:       %lu\r\n", accepts);
    vty_out(vty, "  Access-Reject:       %lu\r\n", rejects);
    vty_out(vty, "  Timeouts:            %lu\r\n", timeouts);
    vty_out(vty, "  Errors:              %lu\r\n", errors);
    vty_out(vty, "  Ring full drops:     %lu\r\n", drops);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_radius_server,
      cmd_radius_server_cmd,
      "radius-server host WORD auth-port <1-65535> acct-port <1-65535> key WORD",
      "RADIUS server configuration\n"
      "RADIUS server address\n"
      "Server IP or hostname\n"
      "Authentication port\n"
      "Port number\n"
      "Accounting port\n"
      "Port number\n"
      "Shared secret\n"
      "Secret string\n")
{
    const char *host = argv[0];
    int auth_port = atoi(argv[1]);
    int acct_port = atoi(argv[2]);
    const char *secret = argv[3];

    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) {
        vty_out(vty, "%% Invalid IP address: %s\r\n", host);
        return CMD_WARNING;
    }

    int ret = radius_lockless_add_server(ntohl(addr.s_addr), auth_port, acct_port, secret, 1);
    if (ret >= 0) {
        vty_out(vty, "RADIUS server %s:%d added\r\n", host, auth_port);
    } else {
        vty_out(vty, "%% Failed to add RADIUS server\r\n");
        return CMD_WARNING;
    }
    return CMD_SUCCESS;
}

/* ============================================================================
 * Init
 * ============================================================================ */

void cli_radius_init(void)
{
    install_element(VIEW_NODE, &cmd_show_radius_cmd);
    install_element(ENABLE_NODE, &cmd_show_radius_cmd);
    install_element(VIEW_NODE, &cmd_show_radius_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_show_radius_statistics_cmd);
    install_element(CONFIG_NODE, &cmd_radius_server_cmd);
}
