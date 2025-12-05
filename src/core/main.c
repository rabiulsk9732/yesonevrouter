/**
 * @file main.c
 * @brief YESRouter vBNG Main Entry Point
 */

#define _GNU_SOURCE

#include "arp.h"
#include "arp_queue.h"
#include "auth.h"
#include "cli.h"
#include "cli_socket.h"
#include "config.h"
#include "cpu_scheduler.h"
#include "dns.h"
#include "dpdk_init.h"
#include "forwarding.h"
#include "ha.h"
#include "interface.h"
#include "ippool.h"
#include "log.h"
#include "nat.h"
#include "packet.h"
#include "pppoe.h"
#include "qos.h"
#include "radius.h"
#include "routing_table.h"
#include "yesrouter_config.h"
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile bool g_running = true;
static pthread_t g_nat_timeout_tid;
static volatile bool g_nat_timeout_running = false;
static void *management_thread(void *arg);
static void *nat_timeout_thread(void *arg);

static void *management_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        ha_poll();
        ha_check_failover();
        radius_poll();
        pppoe_check_keepalives();
        pppoe_check_accounting();
        sleep(1); /* 1 second tick */
    }
    return NULL;
}

static void *nat_timeout_thread(void *arg)
{
    (void)arg;
    while (g_nat_timeout_running) {
        sleep(10); /* Check every 10 seconds */
        int deleted = nat_session_timeout_check();
        if (deleted > 0) {
            YLOG_INFO("NAT timeout: deleted %d sessions", deleted);
        }
    }
    return NULL;
}

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
    printf("  --daemon, -d     Run as daemon with Unix socket CLI\n");
    printf("  --interactive,-i Run in interactive mode (legacy)\n");
    printf("  -h, --help       Show this help\n");
    printf("\nDaemon Mode:\n");
    printf("  In daemon mode, use 'yesrouterctl' to connect to CLI\n");
    printf("  Example: sudo yesrouterctl show interfaces\n");
    printf("\nCommands:\n");
    printf("  (none)     Start router (daemon or interactive)\n");
    printf("  <cmd>      Execute single command and exit\n");
}

int main(int argc, char *argv[])
{

    const char *config_file = NULL;
    bool daemon_mode = false;
    bool interactive_mode = false;
    char *dpdk_argv[32];
    int dpdk_argc = 0;

    /* Initialize VPP config defaults */
    yesrouter_config_init_defaults();

    /* Check for yesrouter.conf */
    if (access("yesrouter.conf", F_OK) == 0) {
        yesrouter_config_parse("yesrouter.conf");
    } else if (access("/etc/yesrouter/yesrouter.conf", F_OK) == 0) {
        yesrouter_config_parse("/etc/yesrouter/yesrouter.conf");
    } else if (access("/etc/yesrouter/startup.conf", F_OK) == 0) {
        /* Fallback to startup.conf for backward compatibility */
        yesrouter_config_parse("/etc/yesrouter/startup.conf");
    }

    /* Check for --daemon, --interactive and -h before DPDK steals args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-d") == 0) {
            daemon_mode = true;
            /* Remove it from argv so DPDK doesn't see it */
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        } else if (strcmp(argv[i], "--interactive") == 0 || strcmp(argv[i], "-i") == 0) {
            interactive_mode = true;
            /* Remove it from argv so DPDK doesn't see it */
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        } else if (strncmp(argv[i], "-c", 2) == 0 || strncmp(argv[i], "--config", 8) == 0) {
            if (i + 1 < argc) {
                config_file = argv[i + 1];
            }
        }
    }

    /* Construct DPDK arguments from VPP config */
    if (g_yesrouter_hw_config.dpdk_config.enabled) {
        dpdk_argv[dpdk_argc++] = argv[0];

        /* Core mask/list */
        if (strlen(g_yesrouter_hw_config.cpu_config.corelist_workers) > 0) {
            dpdk_argv[dpdk_argc++] = "-l";
            char lcore_list[512];
            snprintf(lcore_list, sizeof(lcore_list), "%d,%s",
                     g_yesrouter_hw_config.cpu_config.main_core,
                     g_yesrouter_hw_config.cpu_config.corelist_workers);
            dpdk_argv[dpdk_argc++] = strdup(lcore_list);
        } else {
            /* Default to main core only */
            dpdk_argv[dpdk_argc++] = "-l";
            char lcore_list[32];
            snprintf(lcore_list, sizeof(lcore_list), "%d",
                     g_yesrouter_hw_config.cpu_config.main_core);
            dpdk_argv[dpdk_argc++] = strdup(lcore_list);
        }

        /* Memory channels */
        dpdk_argv[dpdk_argc++] = "-n";
        dpdk_argv[dpdk_argc++] = "4";

        /* Hugepage memory */
        if (g_yesrouter_hw_config.dpdk_config.socket_mem > 0) {
            dpdk_argv[dpdk_argc++] = "--socket-mem";
            char mem_str[32];
            snprintf(mem_str, sizeof(mem_str), "%d", g_yesrouter_hw_config.dpdk_config.socket_mem);
            dpdk_argv[dpdk_argc++] = strdup(mem_str);
        }

        /* PCI whitelist/blacklist */
        if (g_yesrouter_hw_config.dpdk_config.no_pci) {
            dpdk_argv[dpdk_argc++] = "--no-pci";
        } else if (g_yesrouter_hw_config.dpdk_config.num_devices > 0) {
            /* Add -a for each configured device */
            for (int i = 0; i < g_yesrouter_hw_config.dpdk_config.num_devices; i++) {
                dpdk_argv[dpdk_argc++] = "-a";
                dpdk_argv[dpdk_argc++] =
                    strdup(g_yesrouter_hw_config.dpdk_config.devices[i].pci_addr);
            }
        }

        /* Use constructed args for DPDK init */
        if (dpdk_init(dpdk_argc, dpdk_argv) != 0) {
            YLOG_ERROR("Failed to initialize DPDK");
            // goto cleanup; // Don't fail, fallback to non-DPDK
        }
    } else {
        /* DPDK disabled in config */
        char *no_dpdk_argv[] = {argv[0], "--no-huge", "--no-pci"};
        dpdk_init(3, no_dpdk_argv);
    }

    printf("========================================\n");
    printf("YESRouter vBNG - Starting\n");
    printf("========================================\n\n");
    fflush(stdout);

    /* Initialize CPU scheduler */
    if (cpu_scheduler_init() != 0) {
        YLOG_ERROR("Failed to initialize CPU scheduler");
        goto cleanup;
    }

    /* Pin main thread */
    cpu_scheduler_set_affinity(g_yesrouter_hw_config.cpu_config.main_core);

    /* dpdk_init might have modified argc/argv, but for simplicity in this
     * hybrid setup, we'll reset optind to 1 to parse remaining app args */
    optind = 1;

    /* Disable stdout buffering to ensure prompt appears immediately */
    setbuf(stdout, NULL);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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

    /* Fallback to system interfaces if no DPDK ports found */
    if (interface_count() == 0) {
        extern int interface_discover_system(void);
        interface_discover_system();
    }

    if (arp_init() != 0) {
        YLOG_ERROR("Failed to initialize ARP subsystem");
        goto cleanup;
    }

    if (arp_queue_init() != 0) {
        YLOG_ERROR("Failed to initialize ARP queue subsystem");
        goto cleanup;
    }

    if (dns_init() != 0) {
        YLOG_ERROR("Failed to initialize DNS subsystem");
        goto cleanup;
    }

    /* Initialize NAT subsystem */
    if (nat_init() != 0) {
        YLOG_ERROR("Failed to initialize NAT subsystem");
        goto cleanup;
    }

    /* Start NAT timeout timer thread */
    g_nat_timeout_running = true;
    if (pthread_create(&g_nat_timeout_tid, NULL, nat_timeout_thread, NULL) != 0) {
        YLOG_ERROR("Failed to create NAT timeout thread");
    }

    /* Initialize PPPoE */
    if (pppoe_init() != 0) {
        YLOG_ERROR("Failed to initialize PPPoE");
        return -1;
    }

    /* Initialize IP Pools */
    ippool_init();
    /* Create default pool: 100.64.0.10 - 100.64.0.250 */
    ippool_create("default", 0x6440000A, 0x644000FA); /* 100.64.0.10 - 250 */

    /* Initialize RADIUS */
    radius_init();
    /* radius_add_server(0x0A000064, 1812, "secret"); */ /* Example: 10.0.0.100 */

    /* Initialize QoS */
    qos_init();

    if (routing_table_init() == NULL) {
        YLOG_ERROR("Failed to initialize routing table");
        goto cleanup;
    }

    /* User DB, Session, and Telnet removed as per request */

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

    /* Execute startup script from VPP config */
    if (strlen(g_yesrouter_hw_config.unix_config.exec_script) > 0) {
        YLOG_INFO("Executing startup script: %s", g_yesrouter_hw_config.unix_config.exec_script);
        if (cli_execute_file(g_yesrouter_hw_config.unix_config.exec_script) != 0) {
            YLOG_WARNING("Failed to execute startup script: %s",
                         g_yesrouter_hw_config.unix_config.exec_script);
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
            if (i > optind)
                strcat(cmdline, " ");
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
    } else if (daemon_mode || !interactive_mode) {
        /* Daemon mode - run in background with Unix socket CLI */
        printf("Starting in daemon mode...\n");
        printf("Connect using: sudo yesrouterctl\n");

        /* Start management thread */
        pthread_t mgmt_tid;
        if (pthread_create(&mgmt_tid, NULL, management_thread, NULL) != 0) {
            YLOG_ERROR("Failed to create management thread");
        }

        /* Initialize and start CLI socket server */
        const char *socket_path = g_yesrouter_hw_config.unix_config.cli_listen;
        if (!socket_path || socket_path[0] == '\0') {
            socket_path = "/run/yesrouter/cli.sock";
        }

        if (cli_socket_server_init(socket_path) != 0) {
            YLOG_ERROR("Failed to initialize CLI socket server");
            goto cleanup;
        }

        if (cli_socket_server_start() != 0) {
            YLOG_ERROR("Failed to start CLI socket server");
            goto cleanup;
        }

        YLOG_INFO("Daemon started - CLI socket: %s", socket_path);
        printf("Router running. Use 'yesrouterctl' to connect.\n");

        /* Keep running */
        while (g_running) {
            sleep(1);
        }

        cli_socket_server_stop();
        g_running = false;
        pthread_join(mgmt_tid, NULL);
    } else {
        /* Interactive mode - CLI with packet processing (legacy) */

        /* Start management thread */
        pthread_t mgmt_tid;
        if (pthread_create(&mgmt_tid, NULL, management_thread, NULL) != 0) {
            YLOG_ERROR("Failed to create management thread");
        }

        cli_interactive();

        /* Wait for thread? No, cli_interactive returns on exit */
        g_running = false;
        pthread_join(mgmt_tid, NULL);
    }

cleanup:
    YLOG_INFO("Shutting down...");
    printf("\n========================================\n");
    printf("YESRouter vBNG - Shutting Down\n");
    printf("========================================\n\n");

    /* Stop packet RX threads first */
    packet_rx_stop();

    /* Stop NAT timeout timer with safety check */
    if (g_nat_timeout_running) {
        g_nat_timeout_running = false;
        /* Give thread time to exit before joining */
        usleep(100000); /* 100ms */
        pthread_join(g_nat_timeout_tid, NULL);
    }

    /* Cleanup subsystems - order matters (reverse of init) */
    nat_cleanup();
    pppoe_cleanup();
    routing_table_cleanup(routing_table_get_instance());
    dns_cleanup();
    arp_cleanup();
    interface_cleanup();
    config_cleanup();
    cpu_scheduler_cleanup();
    log_cleanup();

    return EXIT_SUCCESS;
}
