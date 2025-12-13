/**
 * @file cli_pppoe.c
 * @brief PPPoE CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "command.h"
#include "vty.h"
#include "pppoe.h"

/* External PPPoE session slab */
extern struct pppoe_session *g_pppoe_session_slab;

/* External functions */
extern void pppoe_print_statistics(void);

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_pppoe,
      cmd_show_pppoe_cmd,
      "show pppoe",
      SHOW_STR
      "PPPoE information\n")
{
    vty_out(vty, "PPPoE Status: Enabled\r\n");
    vty_out(vty, "Use 'show pppoe sessions' for session details\r\n");
    vty_out(vty, "Use 'show pppoe statistics' for statistics\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_pppoe_sessions,
      cmd_show_pppoe_sessions_cmd,
      "show pppoe sessions",
      SHOW_STR
      "PPPoE information\n"
      "Display active PPPoE sessions\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "PPPoE Sessions\r\n");
    vty_out(vty, "==============\r\n");
    vty_out(vty, "\r\n");
    vty_out(vty, "%-8s %-18s %-16s %-10s %-12s %-10s\r\n",
            "Session", "MAC Address", "IP Address", "State", "Username", "Uptime");
    vty_out(vty, "%-8s %-18s %-16s %-10s %-12s %-10s\r\n",
            "-------", "-----------------", "---------------", "---------", "-----------", "---------");

    int session_count = 0;

    if (g_pppoe_session_slab) {
        for (int i = 1; i < MAX_SESSIONS; i++) {
            struct pppoe_session *sess = &g_pppoe_session_slab[i];

            if (sess->state == PPPOE_STATE_SESSION_ESTABLISHED) {
                struct in_addr ip;
                ip.s_addr = htonl(sess->client_ip);

                /* Format MAC address */
                char mac_str[20];
                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                        sess->client_mac.addr_bytes[0], sess->client_mac.addr_bytes[1],
                        sess->client_mac.addr_bytes[2], sess->client_mac.addr_bytes[3],
                        sess->client_mac.addr_bytes[4], sess->client_mac.addr_bytes[5]);

                /* Calculate uptime */
                uint64_t now = time(NULL);
                uint64_t uptime_sec = now - (sess->created_ts / 1000000000ULL);
                char uptime_str[16];
                if (uptime_sec < 60) {
                    snprintf(uptime_str, sizeof(uptime_str), "%lus", (unsigned long)uptime_sec);
                } else if (uptime_sec < 3600) {
                    snprintf(uptime_str, sizeof(uptime_str), "%lum", (unsigned long)(uptime_sec / 60));
                } else {
                    snprintf(uptime_str, sizeof(uptime_str), "%luh%lum",
                            (unsigned long)(uptime_sec / 3600), (unsigned long)((uptime_sec % 3600) / 60));
                }

                const char *state = "ACTIVE";

                vty_out(vty, "%-8u %-18s %-16s %-10s %-12s %-10s\r\n",
                        sess->session_id,
                        mac_str,
                        inet_ntoa(ip),
                        state,
                        sess->username[0] ? sess->username : "-",
                        uptime_str);
                session_count++;
            }
        }
    }

    if (session_count == 0) {
        vty_out(vty, "(no active sessions)\r\n");
    } else {
        vty_out(vty, "\r\nTotal: %d active session(s)\r\n", session_count);
    }

    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_pppoe_statistics,
      cmd_show_pppoe_statistics_cmd,
      "show pppoe statistics",
      SHOW_STR
      "PPPoE information\n"
      "Display PPPoE statistics\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "PPPoE Statistics\r\n");
    vty_out(vty, "================\r\n");
    vty_out(vty, "\r\n");

    /* Call PPPoE module to print statistics */
    pppoe_print_statistics();

    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_pppoe_session_detail,
      cmd_show_pppoe_session_detail_cmd,
      "show pppoe session <1-65535>",
      SHOW_STR
      "PPPoE information\n"
      "Display specific session\n"
      "Session ID\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Session ID required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    uint16_t session_id = atoi(argv[3]);

    vty_out(vty, "\r\nPPPoE Session %u Details\r\n", session_id);
    vty_out(vty, "========================\r\n");

    /* TODO: Get session details from PPPoE module */
    vty_out(vty, "Session ID: %u\r\n", session_id);

    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_pppoe_sessions,
      cmd_clear_pppoe_sessions_cmd,
      "clear pppoe sessions",
      CLEAR_STR
      "PPPoE information\n"
      "Clear all PPPoE sessions\n")
{
    vty_out(vty, "Clearing all PPPoE sessions...\r\n");

    int cleared = 0;
    if (g_pppoe_session_slab) {
        for (int i = 1; i < MAX_SESSIONS; i++) {
            struct pppoe_session *sess = &g_pppoe_session_slab[i];
            if (sess->state == PPPOE_STATE_SESSION_ESTABLISHED) {
                pppoe_terminate_session(sess, "CLI Clear Command");
                cleared++;
            }
        }
    }

    vty_out(vty, "Cleared %d PPPoE sessions\r\n", cleared);
    return CMD_SUCCESS;
}

DEFUN(cmd_clear_pppoe_session,
      cmd_clear_pppoe_session_cmd,
      "clear pppoe session <1-65535>",
      CLEAR_STR
      "PPPoE information\n"
      "Clear specific session\n"
      "Session ID\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Session ID required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    uint16_t session_id = atoi(argv[3]);

    if (g_pppoe_session_slab && session_id > 0 && session_id < MAX_SESSIONS) {
        struct pppoe_session *sess = &g_pppoe_session_slab[session_id];
        if (sess->state == PPPOE_STATE_SESSION_ESTABLISHED) {
            pppoe_terminate_session(sess, "CLI Clear Command");
            vty_out(vty, "PPPoE session %u terminated\r\n", session_id);
        } else {
            vty_out(vty, "%% Session %u not found or not active\r\n", session_id);
        }
    } else {
        vty_out(vty, "%% Invalid session ID\r\n");
    }

    return CMD_SUCCESS;
}

/* ============================================================================
 * Debug Commands
 * ============================================================================ */

DEFUN(cmd_debug_pppoe,
      cmd_debug_pppoe_cmd,
      "debug pppoe",
      DEBUG_STR
      "PPPoE debugging\n")
{
    vty_out(vty, "PPPoE global debugging enabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_no_debug_pppoe,
      cmd_no_debug_pppoe_cmd,
      "no debug pppoe",
      NO_STR
      DEBUG_STR
      "PPPoE debugging\n")
{
    vty_out(vty, "PPPoE global debugging disabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_debug_pppoe_session,
      cmd_debug_pppoe_session_cmd,
      "debug pppoe session <1-65535>",
      DEBUG_STR
      "PPPoE debugging\n"
      "Debug specific session\n"
      "Session ID\n")
{
    if (argc < 4) {
        vty_out(vty, "%% Session ID required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    uint16_t session_id = atoi(argv[3]);
    pppoe_set_session_debug(session_id, true);
    vty_out(vty, "Debug enabled for session %u\r\n", session_id);
    return CMD_SUCCESS;
}

DEFUN(cmd_no_debug_pppoe_session,
      cmd_no_debug_pppoe_session_cmd,
      "no debug pppoe session <1-65535>",
      NO_STR
      DEBUG_STR
      "PPPoE debugging\n"
      "Debug specific session\n"
      "Session ID\n")
{
    if (argc < 5) {
        vty_out(vty, "%% Session ID required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    uint16_t session_id = atoi(argv[4]);
    pppoe_set_session_debug(session_id, false);
    vty_out(vty, "Debug disabled for session %u\r\n", session_id);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_pppoe_config,
      cmd_pppoe_config_cmd,
      "pppoe",
      "Enter PPPoE configuration mode\n")
{
    vty->node = PPPOE_NODE;
    return CMD_SUCCESS;
}

DEFUN(cmd_pppoe_enable,
      cmd_pppoe_enable_cmd,
      "enable",
      "Enable PPPoE server\n")
{
    vty_out(vty, "PPPoE server enabled\r\n");
    /* TODO: Enable PPPoE */
    return CMD_SUCCESS;
}

DEFUN(cmd_pppoe_ac_name,
      cmd_pppoe_ac_name_cmd,
      "ac-name WORD",
      "Set Access Concentrator name\n"
      "AC name string\n")
{
    if (argc < 2) {
        vty_out(vty, "%% AC name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "AC name set to: %s\r\n", argv[1]);
    /* TODO: Set AC name in PPPoE module */
    return CMD_SUCCESS;
}

DEFUN(cmd_pppoe_service_name,
      cmd_pppoe_service_name_cmd,
      "service-name WORD",
      "Set service name\n"
      "Service name string\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Service name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "Service name set to: %s\r\n", argv[1]);
    /* TODO: Set service name in PPPoE module */
    return CMD_SUCCESS;
}

DEFUN(cmd_pppoe_max_sessions,
      cmd_pppoe_max_sessions_cmd,
      "max-sessions <1-65535>",
      "Set maximum sessions\n"
      "Maximum number of sessions\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Max sessions value required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    int max = atoi(argv[1]);
    vty_out(vty, "Max sessions set to: %d\r\n", max);
    /* TODO: Set max sessions in PPPoE module */
    return CMD_SUCCESS;
}

DEFUN(cmd_pppoe_interface,
      cmd_pppoe_interface_cmd,
      "interface WORD",
      "Bind PPPoE to interface\n"
      "Interface name\n")
{
    if (argc < 2) {
        vty_out(vty, "%% Interface name required\r\n");
        return CMD_ERR_INCOMPLETE;
    }

    vty_out(vty, "PPPoE bound to interface: %s\r\n", argv[1]);
    /* TODO: Bind PPPoE to interface */
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_pppoe_init(void)
{
    /* View mode - show commands */
    install_element(VIEW_NODE, &cmd_show_pppoe_cmd);
    install_element(VIEW_NODE, &cmd_show_pppoe_sessions_cmd);
    install_element(VIEW_NODE, &cmd_show_pppoe_statistics_cmd);
    install_element(VIEW_NODE, &cmd_show_pppoe_session_detail_cmd);

    /* Enable mode - show + clear + debug commands */
    install_element(ENABLE_NODE, &cmd_show_pppoe_cmd);
    install_element(ENABLE_NODE, &cmd_show_pppoe_sessions_cmd);
    install_element(ENABLE_NODE, &cmd_show_pppoe_statistics_cmd);
    install_element(ENABLE_NODE, &cmd_show_pppoe_session_detail_cmd);
    install_element(ENABLE_NODE, &cmd_clear_pppoe_sessions_cmd);
    install_element(ENABLE_NODE, &cmd_clear_pppoe_session_cmd);
    install_element(ENABLE_NODE, &cmd_debug_pppoe_cmd);
    install_element(ENABLE_NODE, &cmd_no_debug_pppoe_cmd);
    install_element(ENABLE_NODE, &cmd_debug_pppoe_session_cmd);
    install_element(ENABLE_NODE, &cmd_no_debug_pppoe_session_cmd);

    /* Config mode - enter pppoe config */
    install_element(CONFIG_NODE, &cmd_pppoe_config_cmd);

    /* PPPoE config mode */
    install_element(PPPOE_NODE, &cmd_pppoe_enable_cmd);
    install_element(PPPOE_NODE, &cmd_pppoe_ac_name_cmd);
    install_element(PPPOE_NODE, &cmd_pppoe_service_name_cmd);
    install_element(PPPOE_NODE, &cmd_pppoe_max_sessions_cmd);
    install_element(PPPOE_NODE, &cmd_pppoe_interface_cmd);
}
