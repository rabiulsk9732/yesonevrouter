/**
 * @file cli_arp.c
 * @brief CLI commands for ARP
 */

#include "cli.h"
#include "arp.h"
#include "interface.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* Command: show arp */
int cmd_show_arp(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    arp_print_table();
    return 0;
}

/* Command: arp */
int cmd_arp(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: arp <add|delete|clear> [args...]\n");
        return -1;
    }

    if (strcmp(argv[1], "add") == 0 && argc >= 4) {
        /* TODO: Parse IP and MAC, add ARP entry */
        printf("ARP add %s -> %s (not fully implemented yet)\n", argv[2], argv[3]);
    } else if (strcmp(argv[1], "delete") == 0 && argc >= 3) {
        /* TODO: Parse IP and delete ARP entry */
        printf("ARP delete %s (not fully implemented yet)\n", argv[2]);
    } else if (strcmp(argv[1], "clear") == 0) {
        printf("ARP clear (not implemented yet)\n");
    } else if (strcmp(argv[1], "gratuitous") == 0 && argc >= 3) {
        /* arp gratuitous <interface> */
        const char *ifname = argv[2];
        struct interface *iface = interface_find_by_name(ifname);
        if (!iface) {
            printf("Interface %s not found\n", ifname);
            return -1;
        }

        if (iface->config.ipv4_addr.s_addr == 0) {
            printf("Interface %s has no IP address\n", ifname);
            return -1;
        }

        uint32_t ip = ntohl(iface->config.ipv4_addr.s_addr);
        if (arp_send_gratuitous(ip, iface->mac_addr, iface->ifindex) == 0) {
            printf("Gratuitous ARP sent on %s\n", ifname);
        } else {
            printf("Failed to send Gratuitous ARP\n");
        }
    } else {
        printf("Invalid arp command\n");
        return -1;
    }

    return 0;
}

void cli_register_arp_commands(void)
{
    cli_register_command("arp", "Manage ARP table", cmd_arp);

    /* Register show command for tab completion */
    cli_register_command("show arp", "Display ARP table", cmd_show_arp);

    printf("ARP commands registered\n");
}
