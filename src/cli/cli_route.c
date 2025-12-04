/**
 * @file cli_route.c
 * @brief CLI commands for Routing
 */

#include "cli.h"
#include "routing_table.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Command: show routes */
int cmd_show_routes(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    routing_table_print(routing_table_get_instance());
    return 0;
}

/* Command: route */
int cmd_route(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: route <add|delete> <dest/mask> via <gateway>\n");
        return -1;
    }

    if (strcmp(argv[1], "add") == 0) {
        if (argc < 5 || strcmp(argv[3], "via") != 0) {
            printf("Usage: route add <dest/mask> via <gateway>\n");
            return -1;
        }

        char *dest_str = argv[2];
        char *gw_str = argv[4];
        char *mask_str = strchr(dest_str, '/');
        struct in_addr dest, gw;
        int prefix_len = 32;

        if (mask_str) {
            *mask_str = '\0';
            mask_str++;
            prefix_len = atoi(mask_str);
        }

        if (inet_pton(AF_INET, dest_str, &dest) != 1) {
            printf("Invalid destination address: %s\n", dest_str);
            return -1;
        }

        if (inet_pton(AF_INET, gw_str, &gw) != 1) {
            printf("Invalid gateway address: %s\n", gw_str);
            return -1;
        }

        /* Add route to global table */
        /* Note: We assume egress_ifindex is 0 for now (recursive lookup or unspecified) */
        /* In a real implementation, we'd look up the egress interface for the gateway */
        if (routing_table_add(routing_table_get_instance(), &dest, prefix_len, &gw, 0, 1, ROUTE_SOURCE_STATIC, "static") == 0) {
            printf("Route added: %s/%d via %s\n", dest_str, prefix_len, gw_str);
        } else {
            printf("Failed to add route\n");
        }

    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            printf("Usage: route delete <dest/mask>\n");
            return -1;
        }

        char *dest_str = argv[2];
        char *mask_str = strchr(dest_str, '/');
        struct in_addr dest;
        int prefix_len = 32;

        if (mask_str) {
            *mask_str = '\0';
            mask_str++;
            prefix_len = atoi(mask_str);
        }

        if (inet_pton(AF_INET, dest_str, &dest) != 1) {
            printf("Invalid destination address: %s\n", dest_str);
            return -1;
        }

        if (routing_table_delete(routing_table_get_instance(), &dest, prefix_len, ROUTE_SOURCE_STATIC) == 0) {
            printf("Route deleted: %s/%d\n", dest_str, prefix_len);
        } else {
            printf("Failed to delete route\n");
        }

    } else {
        printf("Unknown route command: %s\n", argv[1]);
        return -1;
    }

    return 0;
}

void cli_register_route_commands(void)
{
    cli_register_command("route", "Manage routes", cmd_route);
}
