/**
 * @file cli_interface.c
 * @brief CLI commands for Interface management (Cisco-style)
 */

#include "cli.h"
#include "interface.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Current interface being configured (for config-if mode) */
static struct interface *g_config_interface = NULL;

/* Get current config interface */
struct interface *cli_get_config_interface(void)
{
    return g_config_interface;
}

/* Command: show interfaces */
int cmd_show_interfaces(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    interface_print_all();
    return 0;
}

/* Command: show interfaces brief (Cisco-style) */
int cmd_show_interfaces_brief(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("\n%-20s %-15s %-10s %-17s %s\n",
           "Interface", "IP-Address", "Status", "MAC-Address", "Protocol");
    printf("--------------------------------------------------------------------------------\n");

    for (uint32_t i = 1; i <= interface_count(); i++) {
        struct interface *iface = interface_find_by_index(i);
        if (!iface) continue;

        char ip_str[INET_ADDRSTRLEN] = "unassigned";
        if (iface->config.ipv4_addr.s_addr) {
            inet_ntop(AF_INET, &iface->config.ipv4_addr, ip_str, sizeof(ip_str));
        }

        printf("%-20s %-15s %-10s %02x:%02x:%02x:%02x:%02x:%02x %s\n",
               iface->name,
               ip_str,
               iface->state == IF_STATE_UP ? "up" : "down",
               iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
               iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5],
               iface->state == IF_STATE_UP ? "up" : "down");
    }
    printf("\n");
    return 0;
}

/* Command: interface (legacy single-line command) */
int cmd_interface(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: interface <name> <up|down|ip <addr/mask>>\n");
        return -1;
    }

    const char *ifname = argv[1];
    const char *action = argv[2];

    struct interface *iface = interface_find_by_name(ifname);
    if (!iface) {
        printf("Interface %s not found\n", ifname);
        return -1;
    }

    if (strcmp(action, "up") == 0) {
        if (interface_up(iface) == 0) {
            printf("Interface %s brought up\n", ifname);
        } else {
            printf("Failed to bring up interface %s\n", ifname);
        }
    } else if (strcmp(action, "down") == 0) {
        if (interface_down(iface) == 0) {
            printf("Interface %s brought down\n", ifname);
        } else {
            printf("Failed to bring down interface %s\n", ifname);
        }
    } else if (strcmp(action, "ip") == 0 && argc > 3) {
        char ip_copy[64];
        strncpy(ip_copy, argv[3], sizeof(ip_copy) - 1);
        char *ip_str = ip_copy;
        char *mask_str = strchr(ip_str, '/');
        struct in_addr ip, mask;
        int prefix_len = 32;

        if (mask_str) {
            *mask_str = '\0';
            mask_str++;
            prefix_len = atoi(mask_str);
            if (prefix_len < 0 || prefix_len > 32) {
                printf("Invalid prefix length: %d\n", prefix_len);
                return -1;
            }
        }

        if (inet_pton(AF_INET, ip_str, &ip) != 1) {
            printf("Invalid IP address: %s\n", ip_str);
            return -1;
        }

        /* Calculate mask from prefix length */
        if (prefix_len == 0) {
            mask.s_addr = 0;
        } else {
            mask.s_addr = htonl(~((1U << (32 - prefix_len)) - 1));
        }

        struct interface_config_data config = iface->config;
        config.ipv4_addr = ip;
        config.ipv4_mask = mask;

        if (interface_configure(iface, &config) == 0) {
            printf("Interface %s IP configured: %s/%d\n", ifname, ip_str, prefix_len);
        } else {
            printf("Failed to configure IP on interface %s\n", ifname);
        }
    } else {
        printf("Unknown interface command: %s\n", action);
        return -1;
    }

    return 0;
}

/*
 * Cisco-style config mode commands
 */

/* Enter interface config mode */
int cli_cmd_config_interface(int argc, char **argv)
{
    if (argc < 2) {
        printf("%% Incomplete command\n");
        return -1;
    }

    struct interface *iface = interface_find_by_name(argv[1]);
    if (!iface) {
        printf("%% Interface %s not found\n", argv[1]);
        return -1;
    }

    g_config_interface = iface;
    return 0;  /* Success - mode change handled by cli.c */
}

/* ip address command (in interface config mode) */
int cli_cmd_if_ip_address(int argc, char **argv)
{
    if (!g_config_interface) {
        printf("%% No interface selected\n");
        return -1;
    }

    if (argc < 3) {
        printf("Usage: ip address <ip> <mask> or ip address <ip/prefix>\n");
        return -1;
    }

    char ip_copy[64];
    strncpy(ip_copy, argv[2], sizeof(ip_copy) - 1);
    struct in_addr ip, mask;
    int prefix_len = 32;

    /* Check for CIDR notation */
    char *slash = strchr(ip_copy, '/');
    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            printf("%% Invalid prefix length\n");
            return -1;
        }
        mask.s_addr = htonl(prefix_len ? ~((1U << (32 - prefix_len)) - 1) : 0);
    } else if (argc >= 4) {
        /* Dotted decimal mask */
        if (inet_pton(AF_INET, argv[3], &mask) != 1) {
            printf("%% Invalid subnet mask\n");
            return -1;
        }
    } else {
        printf("Usage: ip address <ip> <mask>\n");
        return -1;
    }

    if (inet_pton(AF_INET, ip_copy, &ip) != 1) {
        printf("%% Invalid IP address\n");
        return -1;
    }

    struct interface_config_data config = g_config_interface->config;
    config.ipv4_addr = ip;
    config.ipv4_mask = mask;

    if (interface_configure(g_config_interface, &config) == 0) {
        char ip_buf[INET_ADDRSTRLEN], mask_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf));
        inet_ntop(AF_INET, &mask, mask_buf, sizeof(mask_buf));
        printf("%% IP address %s %s configured on %s\n", ip_buf, mask_buf, g_config_interface->name);
        return 0;
    }

    printf("%% Failed to configure IP address\n");
    return -1;
}

/* no shutdown command */
int cli_cmd_if_no_shutdown(void)
{
    if (!g_config_interface) {
        printf("%% No interface selected\n");
        return -1;
    }

    if (interface_up(g_config_interface) == 0) {
        printf("%% Interface %s is now UP\n", g_config_interface->name);
        return 0;
    }

    printf("%% Failed to bring up interface\n");
    return -1;
}

/* shutdown command */
int cli_cmd_if_shutdown(void)
{
    if (!g_config_interface) {
        printf("%% No interface selected\n");
        return -1;
    }

    if (interface_down(g_config_interface) == 0) {
        printf("%% Interface %s is now DOWN\n", g_config_interface->name);
        return 0;
    }

    printf("%% Failed to bring down interface\n");
    return -1;
}

/* Exit interface config mode */
void cli_exit_interface_config(void)
{
    g_config_interface = NULL;
}

/* Register interface CLI commands */
void cli_register_interface_commands(void)
{
    cli_register_command("interface", "Configure interface", cmd_interface);
}
