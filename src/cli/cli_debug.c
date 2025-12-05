/**
 * @file cli_debug.c
 * @brief Debug Commands for Packet Tracing
 */

#include "cli.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

/* Global debug flags */
static bool debug_ip_packet = false;
static bool debug_arp = false;
static bool debug_icmp = false;

/**
 * Get debug flags
 */
bool cli_debug_ip_packet_enabled(void) { return debug_ip_packet; }
bool cli_debug_arp_enabled(void) { return debug_arp; }
bool cli_debug_icmp_enabled(void) { return debug_icmp; }

/**
 * Command: debug ip packet
 */
static int cmd_debug_ip_packet(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    debug_ip_packet = true;
    printf("%% IP packet debugging is on\n");
    YLOG_INFO("IP packet debugging enabled");
    return 0;
}

/**
 * Command: debug arp
 */
static int cmd_debug_arp(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    debug_arp = true;
    printf("%% ARP debugging is on\n");
    YLOG_INFO("ARP debugging enabled");
    return 0;
}

/**
 * Command: debug icmp
 */
static int cmd_debug_icmp(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    debug_icmp = true;
    printf("%% ICMP debugging is on\n");
    YLOG_INFO("ICMP debugging enabled");
    return 0;
}

/**
 * Command: no debug all
 */
static int cmd_no_debug_all(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    debug_ip_packet = false;
    debug_arp = false;
    debug_icmp = false;

    printf("%% All possible debugging has been turned off\n");
    YLOG_INFO("All debugging disabled");
    return 0;
}

/**
 * Command: show debugging
 */
static int cmd_show_debugging(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("\nActive debug flags:\n");
    printf("================================================================================\n");

    if (debug_ip_packet) {
        printf("  IP packet debugging is on\n");
    }
    if (debug_arp) {
        printf("  ARP debugging is on\n");
    }
    if (debug_icmp) {
        printf("  ICMP debugging is on\n");
    }

    if (!debug_ip_packet && !debug_arp && !debug_icmp) {
        printf("  No debugging is active\n");
    }

    printf("================================================================================\n\n");
    return 0;
}

/**
 * Register debug commands
 */
void cli_register_debug_commands(void)
{
    cli_register_command("debug ip packet", "Enable IP packet debugging", cmd_debug_ip_packet);
    cli_register_command("debug arp", "Enable ARP debugging", cmd_debug_arp);
    cli_register_command("debug icmp", "Enable ICMP debugging", cmd_debug_icmp);
    cli_register_command("no debug all", "Disable all debugging", cmd_no_debug_all);
    cli_register_command("show debugging", "Show active debug flags", cmd_show_debugging);

    printf("Debug commands registered\n");
}
