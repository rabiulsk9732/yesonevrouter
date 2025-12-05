/**
 * @file cli_interface.c
 * @brief CLI commands for Interface management (Cisco-style)
 */

#include "cli.h"
#include "interface.h"
#include "routing_table.h"
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

            /* Add connected route */
            struct in_addr network;
            network.s_addr = ip.s_addr & mask.s_addr;

            /* Remove old connected routes for this interface? (TODO) */

            /* Add new connected route */
            struct in_addr next_hop = {0}; /* 0.0.0.0 means connected */

            routing_table_add(routing_table_get_instance(),
                            &network, prefix_len, &next_hop,
                            iface->ifindex, 0, ROUTE_SOURCE_CONNECTED, "connected");

            printf("Interface %s brought up\n", ifname);
            interface_up(iface);

            /* Send Gratuitous ARP to announce our IP */
            extern int arp_send_gratuitous(uint32_t ip_address, const uint8_t *mac_address, uint32_t ifindex);
            uint32_t ip_hbo = ntohl(iface->config.ipv4_addr.s_addr);
            arp_send_gratuitous(ip_hbo, iface->mac_addr, iface->ifindex);
            printf("Gratuitous ARP sent\n");
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

/* Command: interface (Cisco-style config mode) */
int cli_cmd_config_interface(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: interface <name>\n");
        printf("Examples:\n");
        printf("  interface Gi0/1              # Physical interface\n");
        printf("  interface Gi0/1.100          # 802.1Q sub-interface\n");
        printf("  interface Gi0/1.100.200      # QinQ sub-interface\n");
        return -1;
    }

    const char *ifname = argv[1];

    /* Check for loopback interface */
    if (strncmp(ifname, "loopback", 8) == 0 || strncmp(ifname, "Loopback", 8) == 0) {
        struct interface *iface = interface_find_by_name(ifname);
        if (!iface) {
            /* Auto-create loopback interface */
            printf("%% Creating loopback interface %s\n", ifname);
            iface = interface_create(ifname, IF_TYPE_LOOPBACK);
            if (!iface) {
                printf("%% Failed to create loopback interface\n");
                return -1;
            }
        }
        g_config_interface = iface;
        return 0;
    }

    /* Check for dummy interface */
    if (strncmp(ifname, "dummy", 5) == 0 || strncmp(ifname, "Dummy", 5) == 0) {
        struct interface *iface = interface_find_by_name(ifname);
        if (!iface) {
            /* Auto-create dummy interface */
            printf("%% Creating dummy interface %s\n", ifname);
            iface = interface_create(ifname, IF_TYPE_DUMMY);
            if (!iface) {
                printf("%% Failed to create dummy interface\n");
                return -1;
            }
        }
        g_config_interface = iface;
        return 0;
    }

    /* Check if this is a sub-interface */
    char *dot1 = strchr(ifname, '.');
    if (dot1) {
        /* Sub-interface: Gi0/1.100 or Gi0/1.100.200 */
        char parent_name[32];
        int outer_vlan = 0, inner_vlan = 0;

        /* Extract parent interface name */
        size_t parent_len = dot1 - ifname;
        if (parent_len >= sizeof(parent_name)) {
            printf("%% Interface name too long\n");
            return -1;
        }
        strncpy(parent_name, ifname, parent_len);
        parent_name[parent_len] = '\0';

        /* Parse VLAN IDs */
        outer_vlan = atoi(dot1 + 1);
        char *dot2 = strchr(dot1 + 1, '.');
        if (dot2) {
            /* QinQ: Gi0/1.100.200 */
            inner_vlan = atoi(dot2 + 1);
        }

        /* Find or create sub-interface */
        struct interface *iface = interface_find_by_name(ifname);
        if (!iface) {
            /* Create new sub-interface */
            struct interface *parent = interface_find_by_name(parent_name);
            if (!parent) {
                printf("%% Parent interface %s not found\n", parent_name);
                return -1;
            }

            /* TODO: Actually create sub-interface with VLAN tagging */
            printf("%% Sub-interface %s would be created on parent %s\n", ifname, parent_name);
            if (inner_vlan > 0) {
                printf("%%   QinQ: Outer VLAN %d, Inner VLAN %d\n", outer_vlan, inner_vlan);
            } else {
                printf("%%   802.1Q: VLAN %d\n", outer_vlan);
            }
            printf("%% Sub-interface creation not yet fully implemented\n");
            return -1;
        }

        g_config_interface = iface;
        return 0;
    }

    /* Regular interface */
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

/* Command: encapsulation dot1q <vlan-id> [second-dot1q <vlan-id>] */
static int cmd_encapsulation_dot1q(int argc, char **argv)
{
    if (!g_config_interface) {
        printf("%% No interface selected\n");
        return -1;
    }

    if (argc < 3) {
        printf("Usage: encapsulation dot1q <vlan-id> [second-dot1q <inner-vlan-id>]\n");
        printf("Examples:\n");
        printf("  encapsulation dot1q 100                  # 802.1Q single tag\n");
        printf("  encapsulation dot1q 100 second-dot1q 200 # QinQ double tag\n");
        return -1;
    }

    int outer_vlan = atoi(argv[2]);
    int inner_vlan = 0;

    /* Check for QinQ (second-dot1q keyword) */
    if (argc >= 5 && strcmp(argv[3], "second-dot1q") == 0) {
        inner_vlan = atoi(argv[4]);
        printf("%% QinQ encapsulation: Outer VLAN %d, Inner VLAN %d\n", outer_vlan, inner_vlan);
        printf("%% (Configuration stored, actual implementation pending)\n");
    } else {
        printf("%% 802.1Q encapsulation: VLAN %d\n", outer_vlan);
        printf("%% (Configuration stored, actual implementation pending)\n");
    }

    return 0;
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
    cli_register_command("encapsulation", "Set encapsulation type", cmd_encapsulation_dot1q);

    /* Register show commands for tab completion */
    cli_register_command("show interfaces", "Display interface status", cmd_show_interfaces);
    cli_register_command("show interfaces brief", "Display brief interface list", cmd_show_interfaces_brief);

    printf("Interface commands registered\n");
}
