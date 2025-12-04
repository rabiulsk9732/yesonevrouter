/**
 * @file main.c
 * @brief YESRouter vBNG Main Entry Point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include "dpdk_init.h"
#include "cpu_scheduler.h"
#include "packet.h"
#include "interface.h"
#include "arp.h"
#include "dns.h"
#include "routing_table.h"
#include "user_db.h"
#include "auth.h"
#include "session.h"
#include "forwarding.h"
#include "cli.h"
#include "log.h"
#include "config.h"

static volatile bool g_running = true;

static void signal_handler(int signum)
{
    (void)signum;
    printf("\nShutdown signal received\n");
    g_running = false;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options] [command]\n", prog);
    printf("Options:\n");
    printf("  -c <file>  Configuration file\n");
    printf("  -d         Run as daemon\n");
    printf("  -h         Show this help\n");
    printf("\nCommands:\n");
    printf("  (none)     Start interactive CLI\n");
    printf("  <cmd>      Execute single command and exit\n");
}

int main(int argc, char *argv[])
{
    int ret;
    const char *config_file = NULL;
    bool daemon_mode = false;
    int opt;

    /* Parse command line options */
    while ((opt = getopt(argc, argv, "c:dh")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                daemon_mode = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    printf("========================================\n");
    printf("YESRouter vBNG - Starting\n");
    printf("========================================\n\n");
    fflush(stdout);

    /* Disable stdout buffering to ensure prompt appears immediately */
    setbuf(stdout, NULL);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize logging */
    struct log_config log_cfg = {
        .level = daemon_mode ? LOG_LEVEL_INFO : LOG_LEVEL_DEBUG,
        .log_file = "yesrouter.log", /* Default log file */
        .use_syslog = daemon_mode,
        /* Only log to file/syslog, NOT stdout/stderr to keep CLI clean */
        .destinations = LOG_DEST_FILE | (daemon_mode ? LOG_DEST_SYSLOG : 0)
    };
    if (log_init(&log_cfg) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return EXIT_FAILURE;
    }

    /* Initialize CPU scheduler */
    ret = cpu_scheduler_init();
    if (ret < 0) {
        YLOG_ERROR("Failed to initialize CPU scheduler");
        return EXIT_FAILURE;
    }

    /* Initialize DPDK (if available) */
    /* Initialize DPDK EAL first, it will strip EAL args from argc/argv */
    ret = dpdk_init(argc, argv);
    if (ret < 0) {
        YLOG_ERROR("Failed to initialize DPDK");
        return EXIT_FAILURE;
    }

    /* dpdk_init might have modified argc/argv, but for simplicity in this
     * hybrid setup, we'll reset optind to 1 to parse remaining app args */
    optind = 1;

    /* Initialize subsystems */
    if (config_init() != 0) {
        YLOG_ERROR("Failed to initialize configuration");
        goto cleanup;
    }

    if (interface_init() != 0) {
        YLOG_ERROR("Failed to initialize interface subsystem");
        goto cleanup;
    }

    /* Discover DPDK ports only - this is a DPDK-based application */
    interface_discover_dpdk_ports();

    if (arp_init() != 0) {
        YLOG_ERROR("Failed to initialize ARP subsystem");
        goto cleanup;
    }

    if (dns_init() != 0) {
        YLOG_ERROR("Failed to initialize DNS subsystem");
        goto cleanup;
    }

    if (routing_table_init() == NULL) {
        YLOG_ERROR("Failed to initialize routing table");
        goto cleanup;
    }

    if (user_db_init() != 0) {
        YLOG_ERROR("Failed to initialize user database");
        goto cleanup;
    }

    if (session_init() != 0) {
        YLOG_ERROR("Failed to initialize session management");
        goto cleanup;
    }

    if (cli_init() != 0) {
        YLOG_ERROR("Failed to initialize CLI");
        goto cleanup;
    }

    /* Load configuration if specified */
    if (config_file) {
        YLOG_INFO("Loading configuration from %s", config_file);
        if (config_load(config_file) != 0) {
            YLOG_WARNING("Failed to load configuration from %s", config_file);
        }
    }

    /* Start packet RX thread for all modes */
    if (packet_rx_start() != 0) {
        YLOG_ERROR("Failed to start packet RX thread");
        goto cleanup;
    }
    YLOG_INFO("Packet processing started");

    /* Check if command-line command was provided */
    if (optind < argc) {
        /* Build command string from remaining args */
        char cmdline[1024] = "";
        for (int i = optind; i < argc; i++) {
            if (i > optind) strcat(cmdline, " ");
            strcat(cmdline, argv[i]);
        }

        YLOG_DEBUG("Executing command: %s", cmdline);
        cli_execute(cmdline);

        if (daemon_mode) {
            /* Stay running in daemon mode */
            YLOG_INFO("Running in daemon mode, press Ctrl+C to stop");
            while (g_running) {
                sleep(1);
            }
        }
        /* else exit after command */
    } else {
        /* Interactive mode - CLI with packet processing */
        cli_interactive();
    }

cleanup:
    YLOG_INFO("Shutting down...");
    printf("\n========================================\n");
    printf("YESRouter vBNG - Shutting Down\n");
    printf("========================================\n\n");

    packet_rx_stop();
    cli_cleanup();
    routing_table_cleanup(routing_table_get_instance());
    session_cleanup();
    user_db_cleanup();
    dns_cleanup();
    arp_cleanup();
    interface_cleanup();
    config_cleanup();
    cpu_scheduler_cleanup();
    log_cleanup();

    return EXIT_SUCCESS;
}
