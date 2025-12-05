/**
 * @file cli_pppoe.c
 * @brief PPPoE, RADIUS, and IP Pool CLI Commands
 */

#include "cli.h"
#include "ippool.h"
#include "radius.h"
#include "pppoe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Command: ip local pool <name> <start> <end> */
int cmd_ip_local_pool(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: ip local pool <name> <start-ip> <end-ip>\n");
        return -1;
    }

    const char *name = argv[3];
    struct in_addr start, end;

    if (inet_pton(AF_INET, argv[4], &start) != 1) {
        printf("Invalid start IP: %s\n", argv[4]);
        return -1;
    }
    if (inet_pton(AF_INET, argv[5], &end) != 1) {
        printf("Invalid end IP: %s\n", argv[5]);
        return -1;
    }

    /* ippool_create expects host order */
    if (ippool_create(name, ntohl(start.s_addr), ntohl(end.s_addr)) == 0) {
        printf("%% IP Pool '%s' created\n", name);
        return 0;
    } else {
        printf("%% Failed to create IP pool (duplicate name or invalid range)\n");
        return -1;
    }
}

/* Command: radius-server host <ip> key <secret> */
int cmd_radius_server(int argc, char **argv)
{
    if (argc < 5 || strcmp(argv[1], "host") != 0 || strcmp(argv[3], "key") != 0) {
        printf("Usage: radius-server host <ip> key <secret>\n");
        return -1;
    }

    struct in_addr ip;
    if (inet_pton(AF_INET, argv[2], &ip) != 1) {
        printf("Invalid IP address: %s\n", argv[2]);
        return -1;
    }

    const char *secret = argv[4];

    /* radius_add_server expects host order */
    radius_add_server(ntohl(ip.s_addr), 1812, secret);
    printf("%% RADIUS server configured\n");
    return 0;
}

/* Command: show pppoe sessions */
int cmd_show_pppoe_sessions(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /* TODO: Implement pppoe_print_sessions() in pppoe.c */
    printf("PPPoE Sessions:\n");
    printf("ID      MAC                IP              State\n");
    printf("------------------------------------------------\n");
    /* Placeholder */
    return 0;
}

/* Command: show ip local pool */
int cmd_show_ip_pool(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    ippool_print_all();
    return 0;
}

void cli_register_pppoe_commands(void)
{
    /* Global Config Mode */
    cli_register_command("ip local pool", "Configure IP address pool", cmd_ip_local_pool);
    cli_register_command("radius-server", "Configure RADIUS server", cmd_radius_server);

    /* Exec Mode */
    cli_register_command("show pppoe sessions", "Show active PPPoE sessions", cmd_show_pppoe_sessions);
    cli_register_command("show ip local pool", "Show IP address pools", cmd_show_ip_pool);
}
