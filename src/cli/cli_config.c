/**
 * @file cli_config.c
 * @brief Configuration Save/Load Commands
 */

#include "cli.h"
#include "interface.h"
#include "routing_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define STARTUP_CONFIG_PATH  "/etc/yesrouter/startup-config"
#define RUNNING_CONFIG_PATH "/var/run/yesrouter/running-config"

/**
 * @brief Write running config to file
 */
static int write_running_config(const char *filename)
{
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("%% Failed to open %s for writing\n", filename);
        return -1;
    }

    time_t now = time(NULL);
    fprintf(fp, "!\n! yesrouter Running Configuration\n");
    fprintf(fp, "! Generated: %s!\n", ctime(&now));
    fprintf(fp, "version 1.0\n!\n");

    /* Hostname */
    fprintf(fp, "hostname yesrouter\n!\n");

    /* Interfaces */
    for (uint32_t i = 1; i <= interface_count(); i++) {
        struct interface *iface = interface_find_by_index(i);
        if (!iface) continue;

        fprintf(fp, "interface %s\n", iface->name);
        if (iface->config.ipv4_addr.s_addr) {
            char ip_buf[INET_ADDRSTRLEN], mask_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iface->config.ipv4_addr, ip_buf, sizeof(ip_buf));
            inet_ntop(AF_INET, &iface->config.ipv4_mask, mask_buf, sizeof(mask_buf));
            fprintf(fp, " ip address %s %s\n", ip_buf, mask_buf);
        }
        if (iface->config.mtu > 0) {
            fprintf(fp, " mtu %u\n", iface->config.mtu);
        }
        fprintf(fp, " %s\n!\n", iface->state == IF_STATE_UP ? "no shutdown" : "shutdown");
    }

    /* Static routes */
    extern struct routing_table *routing_table_get_instance(void);
    struct routing_table *rt = routing_table_get_instance();
    if (rt && rt->rib_root) {
        /* Helper to traverse and print static routes */
        void print_static_routes(struct radix_node *node, FILE *fp) {
            if (!node) return;

            if (node->route && node->route->source == ROUTE_SOURCE_STATIC) {
                char dest[INET_ADDRSTRLEN];
                char gw[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &node->route->prefix, dest, sizeof(dest));
                inet_ntop(AF_INET, &node->route->next_hop, gw, sizeof(gw));

                /* Calculate mask from prefix len */
                struct in_addr mask;
                if (node->route->prefix_len == 0) mask.s_addr = 0;
                else mask.s_addr = htonl(~((1U << (32 - node->route->prefix_len)) - 1));

                char mask_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &mask, mask_str, sizeof(mask_str));

                fprintf(fp, "ip route %s %s %s\n", dest, mask_str, gw);
            }

            print_static_routes(node->left, fp);
            print_static_routes(node->right, fp);
        }

        pthread_rwlock_rdlock((pthread_rwlock_t *)rt->lock);
        print_static_routes(rt->rib_root, fp);
        pthread_rwlock_unlock((pthread_rwlock_t *)rt->lock);
    }

    fprintf(fp, "!\nend\n");

    fclose(fp);
    return 0;
}

/**
 * Command: write memory
 */
static int cmd_write_memory(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Create directory if it doesn't exist */
    mkdir("/etc/yesrouter", 0755);

    if (write_running_config(STARTUP_CONFIG_PATH) == 0) {
        printf("Building configuration...\n[OK]\n");
        return 0;
    } else {
        return -1;
    }
}

/**
 * Command: write
 */
static int cmd_write(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "memory") == 0) {
        return cmd_write_memory(argc, argv);
    }

    /* Default: write memory */
    return cmd_write_memory(argc, argv);
}

/**
 * Command: copy running-config startup-config
 */
static int cmd_copy(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: copy running-config startup-config\n");
        return -1;
    }

    if (strcmp(argv[1], "running-config") == 0 &&
        strcmp(argv[2], "startup-config") == 0) {

        mkdir("/etc/yesrouter", 0755);

        if (write_running_config(STARTUP_CONFIG_PATH) == 0) {
            printf("Destination filename [startup-config]? \n");
            printf("Building configuration...\n[OK]\n");
            return 0;
        }
    }

    printf("%% Invalid copy command\n");
    return -1;
}

/**
 * Command: show startup-config
 */
static int cmd_show_startup_config(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    FILE *fp = fopen(STARTUP_CONFIG_PATH, "r");
    if (!fp) {
        printf("%% Startup configuration not found\n");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }

    fclose(fp);
    return 0;
}

/**
 * Register config save/load commands
 */
void cli_register_config_commands(void)
{
    cli_register_command("write", "Write configuration", cmd_write);
    cli_register_command("write memory", "Save configuration to NVRAM", cmd_write_memory);
    cli_register_command("copy", "Copy configuration", cmd_copy);
    cli_register_command("show startup-config", "Display startup configuration", cmd_show_startup_config);

    printf("Config save/load commands registered\n");
}
