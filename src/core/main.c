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
#include "ipv6/ipv6.h"
#include "log.h"
#include "nat.h"
#include "packet.h"
#include "pppoe.h"
#include "pppoe.h"
#include "qos.h"
#include "hqos.h"
#include "radius.h"
#include "routing_table.h"
#include "env_config.h"
#include <ipoe.h>
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
static pthread_t g_exporter_tid;
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
        usleep(100000); /* Check every 100ms (incremental scan) */
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

    /* Initialize logging with defaults (stdout/stderr) */
    log_init(NULL);

    /* Load Bison-style .env configuration (DPDK/hardware params) */
    if (env_config_load("/etc/yesrouter/yesrouter.env") != 0) {
        fprintf(stderr, "FATAL: Failed to load /etc/yesrouter/yesrouter.env\n");
        return EXIT_FAILURE;
    }
    env_config_print();

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
            /* -c flag ignored - all config from .env now (Bison-style) */
            if (i + 1 < argc) {
                printf("[ENV] Note: -c flag ignored, using /etc/yesrouter/yesrouter.env\n");
                /* Remove -c and filename from argv */
                for (int j = i; j < argc - 2; j++) {
                    argv[j] = argv[j + 2];
                }
                argc -= 2;
                i--;
            }
        }
    }

    /* Construct DPDK arguments from .env config (Bison-style) */
    if (g_env_config.validated) {
        dpdk_argv[dpdk_argc++] = argv[0];

        /* Core mask/list from .env */
        dpdk_argv[dpdk_argc++] = "-l";
        char lcore_list[512];
        int pos = snprintf(lcore_list, sizeof(lcore_list), "%d",
                          g_env_config.dpdk.main_lcore);
        for (int i = 0; i < g_env_config.dpdk.num_workers && pos < (int)sizeof(lcore_list) - 10; i++) {
            pos += snprintf(lcore_list + pos, sizeof(lcore_list) - pos, ",%d",
                           g_env_config.dpdk.worker_lcores[i]);
        }
        dpdk_argv[dpdk_argc++] = strdup(lcore_list);
        printf("[ENV] DPDK lcores: %s\n", lcore_list);

        /* Memory channels */
        dpdk_argv[dpdk_argc++] = "-n";
        dpdk_argv[dpdk_argc++] = "4";

        /* Check if hugepages are available */
        FILE *hugepage_check = fopen("/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages", "r");
        int hugepages_available = 0;
        if (hugepage_check) {
            if (fscanf(hugepage_check, "%d", &hugepages_available) != 1) {
                hugepages_available = 0;
            }
            fclose(hugepage_check);
        }

        /* Check if vfio is in no-iommu mode */
        FILE *vfio_noiommu = fopen("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode", "r");
        bool vfio_noiommu_mode = false;
        if (vfio_noiommu) {
            char buf[8];
            if (fgets(buf, sizeof(buf), vfio_noiommu) != NULL) {
                vfio_noiommu_mode = (buf[0] == 'Y' || buf[0] == 'y' || buf[0] == '1');
            }
            fclose(vfio_noiommu);
        }

        if (hugepages_available == 0) {
            dpdk_argv[dpdk_argc++] = "--no-huge";
            printf("[ENV] No hugepages detected, using --no-huge\n");
        } else {
            /* Socket memory from .env */
            if (g_env_config.dpdk.socket_mem_mb > 0) {
                dpdk_argv[dpdk_argc++] = "--socket-mem";
                char mem_str[32];
                snprintf(mem_str, sizeof(mem_str), "%d", g_env_config.dpdk.socket_mem_mb);
                dpdk_argv[dpdk_argc++] = strdup(mem_str);
                printf("[ENV] DPDK socket-mem: %d MB\n", g_env_config.dpdk.socket_mem_mb);
            }
        }

        /* File prefix */
        dpdk_argv[dpdk_argc++] = "--file-prefix";
        dpdk_argv[dpdk_argc++] = "vbng";

        /* IOVA mode for virtio */
        if (vfio_noiommu_mode) {
            dpdk_argv[dpdk_argc++] = "--iova-mode=pa";
            printf("[ENV] vfio no-iommu mode, using --iova-mode=pa\n");
        }

        /* PCI devices from .env */
        if (g_env_config.dpdk.num_ports > 0) {
            printf("[ENV] Adding DPDK ports:\n");
            for (int i = 0; i < g_env_config.dpdk.num_ports; i++) {
                dpdk_argv[dpdk_argc++] = "-a";
                dpdk_argv[dpdk_argc++] = strdup(g_env_config.dpdk.ports[i]);
                printf("  -a %s\n", g_env_config.dpdk.ports[i]);
            }
        }

        /* Sync mbuf count to DPDK module */
        g_dpdk_config.num_mbufs = g_env_config.dpdk.mbuf_count;
        printf("[ENV] DPDK mbufs: %d\n", g_env_config.dpdk.mbuf_count);

        if (dpdk_init(dpdk_argc, dpdk_argv) != 0) {
            YLOG_ERROR("Failed to initialize DPDK");
        }
    } else {
        /* .env not validated - fatal error */
        fprintf(stderr, "FATAL: .env config not validated, cannot start DPDK\n");
        return EXIT_FAILURE;
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

    /* Pin main thread to main_lcore from .env */
    cpu_scheduler_set_affinity(g_env_config.dpdk.main_lcore);

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

    /* Initialize TX batching for DPDK ports */
#ifdef HAVE_DPDK
    extern int tx_batch_init(int num_ports);
    tx_batch_init(32); /* Initialize with sufficient ports (capped internally) */
#endif

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

    /* Set NAT workers BEFORE nat_init (fixes g_num_workers=1 bug) */
    extern void nat_set_num_workers(uint32_t num_workers);
    int nat_workers = g_env_config.workers.nat_count > 0 ? g_env_config.workers.nat_count : 4;
    YLOG_INFO("Setting NAT workers to %d before nat_init", nat_workers);
    nat_set_num_workers(nat_workers);

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

    /* Initialize IPoE subsystem */
    if (ipoe_init(NULL) != 0) {
        YLOG_WARNING("Failed to initialize IPoE subsystem");
        /* Non-fatal: continue without IPoE */
    } else {
        YLOG_INFO("IPoE subsystem initialized");
    }

    /* Initialize IP Pools */
    ippool_init();
    /* Create default pool: 100.64.0.10 - 100.64.0.250 */
    ippool_create("default", 0x6440000A, 0x644000FA); /* 100.64.0.10 - 250 */

    /* Initialize IPv6 subsystem */
    if (ipv6_init() != 0) {
        YLOG_ERROR("Failed to initialize IPv6 subsystem");
        goto cleanup;
    }

    /* Initialize RADIUS */
    radius_init();
    /* Add real RADIUS server */
    radius_add_server(0x9D0F6241, 1812, "radius"); /* 157.15.98.65 */
    YLOG_INFO("RADIUS: Added server 157.15.98.65:1812");

    /* Initialize QoS */
    qos_init();
    hqos_init();

    /* Initialize flow exporter subsystem */
    extern int exporter_init(void);
    if (exporter_init() != 0) {
        YLOG_WARNING("Failed to initialize flow exporter");
    } else {
        YLOG_INFO("IPFIX/NetFlow exporter initialized");

        /* Start exporter thread */
        extern void *exporter_thread_func(void *arg);
        if (pthread_create(&g_exporter_tid, NULL, exporter_thread_func, NULL) != 0) {
            YLOG_ERROR("Failed to create exporter thread");
        } else {
            pthread_detach(g_exporter_tid);
            YLOG_INFO("Exporter thread started");
        }
    }

    /* Initialize per-core flow cache */
    extern int flow_cache_init(unsigned int lcore_id);
    if (flow_cache_init(0) != 0) {
        YLOG_WARNING("Failed to initialize flow cache");
    } else {
        YLOG_INFO("Flow cache initialized");
    }

    if (routing_table_init() == NULL) {

        YLOG_ERROR("Failed to initialize routing table");
        goto cleanup;
    }

    /* User DB, Session, and Telnet removed    /* Parse arguments */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (cli_init() != 0) {
        YLOG_ERROR("Failed to initialize CLI");
        goto cleanup;
    }

    /* Execute startup config from JSON (Cisco-style runtime config) */
    extern int startup_json_load(const char *path);
    const char *startup_json_path = "/etc/yesrouter/startup.json";
    YLOG_INFO("Startup config: %s", startup_json_path);
    if (access(startup_json_path, F_OK) == 0) {
        startup_json_load(startup_json_path);
    }

    /* Start packet RX threads */
    YLOG_INFO("Starting packet RX threads...");
    if (packet_rx_start() != 0) {
        YLOG_ERROR("Failed to start packet RX threads");
        goto cleanup;
    }
    YLOG_INFO("Packet processing started");

    /* Send RADIUS Accounting-On (P2 #10) */
    radius_client_acct_on();

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
        const char *socket_path = "/run/yesrouter/cli.sock";

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
    radius_client_acct_off(); /* Send Accounting-Off (P2 #10) */
    nat_cleanup();
    ipoe_cleanup();  /* IPoE cleanup before PPPoE */
    pppoe_cleanup();
    routing_table_cleanup(routing_table_get_instance());
    dns_cleanup();
    arp_cleanup();
    ipv6_cleanup();
    interface_cleanup();
    config_cleanup();
    cpu_scheduler_cleanup();
    log_cleanup();
    hqos_cleanup();
    qos_cleanup();

    return EXIT_SUCCESS;
}
