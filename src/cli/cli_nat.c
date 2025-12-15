/**
 * @file cli_nat.c
 * @brief NAT CLI Commands (Cisco IOS Style)
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"
#include "nat.h"
#include "vty.h"

/* External NAT globals */
extern struct nat_session *g_session_slab;
extern uint32_t g_max_sessions;
extern struct nat_config g_nat_config;

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_nat, cmd_show_nat_cmd, "show nat", SHOW_STR "NAT information\n")
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

DEFUN(cmd_show_nat_sessions, cmd_show_nat_sessions_cmd, "show nat sessions",
      SHOW_STR "NAT information\n"
               "Display active NAT sessions\n")
{
    extern struct nat_worker_data g_nat_workers[];
    extern uint32_t g_num_workers;

    vty_out(vty, "\r\n");
    vty_out(vty, "NAT Sessions\r\n");
    vty_out(vty, "============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-16s %-8s %-16s %-8s %-8s %-8s\r\n", "Inside IP", "Port", "Outside IP", "Port",
            "Proto", "Worker");
    vty_out(vty, "%-16s %-8s %-16s %-8s %-8s %-8s\r\n", "---------------", "-------", "---------------",
            "-------", "-------", "------");

    int session_count = 0;

    /* Sessions are allocated from END of each worker's pool (stack pops from top)
     * Worker 0: indices 1 to sessions_per_worker (allocated from end: sessions_per_worker down to 1)
     * Worker 1: indices sessions_per_worker+1 to 2*sessions_per_worker
     * etc.
     * Scan from END of each worker's range to find recently allocated sessions
     */
    if (g_session_slab && g_max_sessions > 0 && g_num_workers > 0) {
        uint32_t sessions_per_worker = g_max_sessions / g_num_workers;

        for (uint32_t w = 0; w < g_num_workers && session_count < 100; w++) {
            uint32_t end_idx = (w + 1) * sessions_per_worker;  /* End of this worker's range */
            if (end_idx > g_max_sessions) end_idx = g_max_sessions;

            /* Scan backwards from end of worker's pool (where new sessions are allocated) */
            uint32_t scan_limit = (sessions_per_worker < 5000) ? sessions_per_worker : 5000;

            for (uint32_t i = 0; i < scan_limit && session_count < 100; i++) {
                uint32_t idx = end_idx - 1 - i;
                if (idx == 0) break;  /* Index 0 is reserved */

                struct nat_session *sess = &g_session_slab[idx];

                /* Check if session is active */
                if (sess->inside_ip == 0 || sess->outside_ip == 0)
                    continue;

                /* Display session */
                struct in_addr in_ip, out_ip;
                in_ip.s_addr = htonl(sess->inside_ip);
                out_ip.s_addr = htonl(sess->outside_ip);

                const char *proto = "OTHER";
                switch (sess->protocol) {
                case 6:
                    proto = "TCP";
                    break;
                case 17:
                    proto = "UDP";
                    break;
                case 1:
                    proto = "ICMP";
                    break;
                }

                /* inet_ntoa uses static buffer - copy first result before second call */
                char in_ip_str[INET_ADDRSTRLEN];
                char out_ip_str[INET_ADDRSTRLEN];
                strncpy(in_ip_str, inet_ntoa(in_ip), sizeof(in_ip_str) - 1);
                in_ip_str[sizeof(in_ip_str) - 1] = '\0';
                strncpy(out_ip_str, inet_ntoa(out_ip), sizeof(out_ip_str) - 1);
                out_ip_str[sizeof(out_ip_str) - 1] = '\0';

                vty_out(vty, "%-16s %-8u %-16s %-8u %-8s %-8u\r\n", in_ip_str, sess->inside_port,
                        out_ip_str, sess->outside_port, proto, w);
                session_count++;
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

DEFUN(cmd_show_nat_statistics, cmd_show_nat_statistics_cmd, "show nat statistics",
      SHOW_STR "NAT information\n"
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

DEFUN(cmd_show_nat_workers, cmd_show_nat_workers_cmd, "show nat workers",
      SHOW_STR "NAT information\n"
               "Display per-worker NAT statistics\n")
{
    extern struct nat_worker_data g_nat_workers[];
    extern uint32_t g_num_workers;

    vty_out(vty, "\r\n");
    vty_out(vty, "NAT Per-Worker Statistics (Multi-Core)\r\n");
    vty_out(vty, "======================================\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-8s %-12s %-12s %-12s %-12s %-12s\r\n",
            "Worker", "Sessions", "SNAT Pkts", "DNAT Pkts", "XWorker Hit", "XWorker Miss");
    vty_out(vty, "%-8s %-12s %-12s %-12s %-12s %-12s\r\n",
            "------", "--------", "---------", "---------", "-----------", "------------");

    uint64_t total_sessions = 0, total_snat = 0, total_dnat = 0;
    uint64_t total_xworker_hits = 0, total_xworker_miss = 0;

    for (uint32_t i = 0; i < g_num_workers; i++) {
        struct nat_worker_data *w = &g_nat_workers[i];
        vty_out(vty, "%-8u %-12lu %-12lu %-12lu %-12lu %-12lu\r\n",
                i, w->sessions_created, w->snat_packets, w->dnat_packets,
                w->cross_worker_hits, w->cross_worker_misses);

        total_sessions += w->sessions_created;
        total_snat += w->snat_packets;
        total_dnat += w->dnat_packets;
        total_xworker_hits += w->cross_worker_hits;
        total_xworker_miss += w->cross_worker_misses;
    }

    vty_out(vty, "%-8s %-12s %-12s %-12s %-12s %-12s\r\n",
            "------", "--------", "---------", "---------", "-----------", "------------");
    vty_out(vty, "%-8s %-12lu %-12lu %-12lu %-12lu %-12lu\r\n",
            "TOTAL", total_sessions, total_snat, total_dnat,
            total_xworker_hits, total_xworker_miss);

    vty_out(vty, "\r\n");
    vty_out(vty, "Notes:\r\n");
    vty_out(vty, "  - Sessions: Created by this worker (SNAT)\r\n");
    vty_out(vty, "  - XWorker Hit: DNAT found session on different worker (RSS asymmetry)\r\n");
    vty_out(vty, "  - XWorker Miss: DNAT searched all workers, no session found\r\n");
    vty_out(vty, "\r\n");

    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_nat_sessions, cmd_clear_nat_sessions_cmd, "clear nat sessions",
      CLEAR_STR "NAT information\n"
                "Clear all NAT sessions\n")
{
    nat_clear_sessions();
    vty_out(vty, "NAT sessions cleared\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Debug Commands
 * ============================================================================ */

DEFUN(cmd_debug_nat, cmd_debug_nat_cmd, "debug nat", DEBUG_STR "NAT debugging\n")
{
    vty_out(vty, "NAT debugging enabled\r\n");
    /* TODO: Enable NAT debugging */
    return CMD_SUCCESS;
}

DEFUN(cmd_no_debug_nat, cmd_no_debug_nat_cmd, "no debug nat", NO_STR DEBUG_STR "NAT debugging\n")
{
    vty_out(vty, "NAT debugging disabled\r\n");
    /* TODO: Disable NAT debugging */
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
    install_element(VIEW_NODE, &cmd_show_nat_workers_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_nat_cmd);
    install_element(ENABLE_NODE, &cmd_show_nat_sessions_cmd);
    install_element(ENABLE_NODE, &cmd_show_nat_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_show_nat_workers_cmd);
    install_element(ENABLE_NODE, &cmd_clear_nat_sessions_cmd);
    install_element(ENABLE_NODE, &cmd_debug_nat_cmd);
    install_element(ENABLE_NODE, &cmd_no_debug_nat_cmd);
}
