/**
 * @file cli_nat.c
 * @brief NAT CLI Commands
 */

#include "cli.h"
#include "nat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Command: nat pool */
int cmd_nat_pool(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: nat pool <name> <start-ip> <end-ip> netmask <mask>\n");
        printf("Example: nat pool PUBLIC 1.2.3.0 1.2.3.255 netmask 255.255.255.0\n");
        return -1;
    }

    const char *name = argv[2];
    struct in_addr start_addr, end_addr, netmask_addr;

    if (inet_pton(AF_INET, argv[3], &start_addr) != 1) {
        printf("Invalid start IP address\n");
        return -1;
    }

    if (inet_pton(AF_INET, argv[4], &end_addr) != 1) {
        printf("Invalid end IP address\n");
        return -1;
    }

    if (argc >= 6 && strcmp(argv[5], "netmask") == 0 && argc >= 7) {
        if (inet_pton(AF_INET, argv[6], &netmask_addr) != 1) {
            printf("Invalid netmask\n");
            return -1;
        }
    } else {
        netmask_addr.s_addr = htonl(0xFFFFFF00);  /* Default /24 */
    }

    uint32_t start_ip = ntohl(start_addr.s_addr);
    uint32_t end_ip = ntohl(end_addr.s_addr);
    uint32_t netmask = ntohl(netmask_addr.s_addr);

    if (nat_pool_create(name, start_ip, end_ip, netmask) == 0) {
        printf("NAT pool '%s' created successfully\n", name);
    } else {
        printf("Failed to create NAT pool\n");
        return -1;
    }

    return 0;
}

/* Command: show nat */
int cmd_show_nat(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: show nat <statistics|translations|config|port-blocks>\n");
        return -1;
    }

    if (strcmp(argv[2], "statistics") == 0 || strcmp(argv[2], "stats") == 0) {
        nat_print_config();  /* Includes statistics */
    } else if (strcmp(argv[2], "translations") == 0) {
        nat_print_sessions();
    } else if (strcmp(argv[2], "config") == 0) {
        nat_print_config();
    } else if (strcmp(argv[2], "port-blocks") == 0) {
        nat_portblock_print_stats();
    } else {
        printf("Unknown option: %s\n", argv[2]);
        return -1;
    }

    return 0;
}

/* Command: clear nat */
int cmd_clear_nat(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: clear nat <translations|all>\n");
        return -1;
    }

    if (strcmp(argv[2], "translations") == 0 || strcmp(argv[2], "all") == 0) {
        nat_clear_sessions();
        printf("NAT translations cleared\n");
    } else {
        printf("Unknown option: %s\n", argv[2]);
        return -1;
    }

    return 0;
}

/* Command: nat enable/disable */
int cmd_nat_enable(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    extern struct nat_config g_nat_config;
    g_nat_config.enabled = true;
    printf("NAT enabled\n");
    return 0;
}

int cmd_nat_disable(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    extern struct nat_config g_nat_config;
    g_nat_config.enabled = false;
    printf("NAT disabled\n");
    return 0;
}

/* Register NAT commands */
void cli_register_nat_commands(void)
{
    cli_register_command("nat pool", "Configure NAT pool", cmd_nat_pool);
    cli_register_command("nat enable", "Enable NAT", cmd_nat_enable);
    cli_register_command("nat disable", "Disable NAT", cmd_nat_disable);
    cli_register_command("show nat statistics", "Display NAT statistics", cmd_show_nat);
    cli_register_command("show nat translations", "Display NAT translations", cmd_show_nat);
    cli_register_command("show nat config", "Display NAT configuration", cmd_show_nat);
    cli_register_command("show nat port-blocks", "Display port block allocation", cmd_show_nat);
    cli_register_command("clear nat translations", "Clear NAT translations", cmd_clear_nat);

    printf("NAT commands registered\n");
}
