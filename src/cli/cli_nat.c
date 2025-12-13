/**
 * @file cli_nat.c
 * @brief NAT CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "nat.h"

/* External NAT globals */
extern struct nat_session *g_session_slab;
extern uint32_t g_max_sessions;
extern struct nat_config g_nat_config;

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_nat,
      cmd_show_nat_cmd,
      "show nat",
      SHOW_STR
      "NAT information\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "NAT Status: %s\r\n", g_nat_config.enabled ? "Enabled" : "Disabled");
    vty_out(vty, "Hairpinning: %s\r\n", g_nat_config.hairpinning_enabled ? "Enabled" : "Disabled");
    vty_out(vty, "Pools configured: %d\r\n", g_nat_config.num_pools);
    vty_out(vty, "\r\n");
    vty_out(vty, "Use 'show nat sessions' for session details\r\n");
    vty_out(vty, "Use 'show nat statistics' for statistics\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_nat_sessions,
      cmd_show_nat_sessions_cmd,
      "show nat sessions",
      SHOW_STR
      "NAT information\n"
      "Display active NAT sessions\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "NAT Sessions\r\n");
    vty_out(vty, "============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-16s %-8s %-16s %-8s %-8s\r\n",
            "Inside IP", "Port", "Outside IP", "Port", "Proto");
    vty_out(vty, "%-16s %-8s %-16s %-8s %-8s\r\n",
            "---------------", "-------", "---------------", "-------", "-------");

    int session_count = 0;

    if (g_session_slab && g_max_sessions > 0) {
        /* Limit iteration to first 1000 to avoid long output */
        uint32_t max_show = (g_max_sessions < 1000) ? g_max_sessions : 1000;

        for (uint32_t i = 0; i < max_show; i++) {
            struct nat_session *sess = &g_session_slab[i];

            if (sess->inside_ip != 0 && sess->outside_ip != 0) {
                struct in_addr in_ip, out_ip;
                in_ip.s_addr = htonl(sess->inside_ip);
                out_ip.s_addr = htonl(sess->outside_ip);

                const char *proto = "OTHER";
                switch (sess->protocol) {
                    case 6: proto = "TCP"; break;
                    case 17: proto = "UDP"; break;
                    case 1: proto = "ICMP"; break;
                }

                vty_out(vty, "%-16s %-8u %-16s %-8u %-8s\r\n",
                        inet_ntoa(in_ip), sess->inside_port,
                        inet_ntoa(out_ip), sess->outside_port,
                        proto);
                session_count++;

                /* Limit displayed sessions */
                if (session_count >= 100) {
                    vty_out(vty, "... (showing first 100 of %lu active sessions)\r\n",
                            g_nat_config.stats.active_sessions);
                    break;
                }
            }
        }
    }

    if (session_count == 0) {
        vty_out(vty, "(no active sessions)\r\n");
    }

    vty_out(vty, "\r\nActive sessions: %lu\r\n", g_nat_config.stats.active_sessions);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_nat_statistics,
      cmd_show_nat_statistics_cmd,
      "show nat statistics",
      SHOW_STR
      "NAT information\n"
      "Display NAT statistics\n")
{
    struct nat_stats *stats = &g_nat_config.stats;

    vty_out(vty, "\r\n");
    vty_out(vty, "NAT Statistics\r\n");
    vty_out(vty, "==============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "Sessions:\r\n");
    vty_out(vty, "  Total created:   %lu\r\n", stats->sessions_created);
    vty_out(vty, "  Active:          %lu\r\n", stats->active_sessions);
    vty_out(vty, "  Deleted:         %lu\r\n", stats->sessions_deleted);
    vty_out(vty, "  Timed out:       %lu\r\n", stats->sessions_timeout);
    vty_out(vty, "\r\n");
    vty_out(vty, "Translations:\r\n");
    vty_out(vty, "  Packets:         %lu\r\n", stats->packets_translated);
    vty_out(vty, "  SNAT:            %lu\r\n", stats->snat_packets);
    vty_out(vty, "  DNAT:            %lu\r\n", stats->dnat_packets);
    vty_out(vty, "\r\n");
    vty_out(vty, "Errors:\r\n");
    vty_out(vty, "  No port:         %lu\r\n", stats->no_port_available);
    vty_out(vty, "  No IP:           %lu\r\n", stats->no_ip_available);
    vty_out(vty, "  Session miss:    %lu\r\n", stats->session_not_found);
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_nat_sessions,
      cmd_clear_nat_sessions_cmd,
      "clear nat sessions",
      CLEAR_STR
      "NAT information\n"
      "Clear all NAT sessions\n")
{
    nat_clear_sessions();
    vty_out(vty, "NAT sessions cleared\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_nat_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_nat_cmd);
    install_element(VIEW_NODE, &cmd_show_nat_sessions_cmd);
    install_element(VIEW_NODE, &cmd_show_nat_statistics_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_nat_cmd);
    install_element(ENABLE_NODE, &cmd_show_nat_sessions_cmd);
    install_element(ENABLE_NODE, &cmd_show_nat_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_clear_nat_sessions_cmd);
}
