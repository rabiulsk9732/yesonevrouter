/**
 * @file yesrouter_hw_config.c
 * @brief YESRouter Configuration Parser
 *
 * Parses yesrouter.conf for hardware/resource configuration.
 * Runtime config (NAT pools, interfaces) is handled by startup.gate CLI commands.
 */

#include "yesrouter_config.h"
#include "nat.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct yesrouter_hw_config g_yesrouter_hw_config;

/* Forward declaration */
extern void nat_set_num_workers(uint32_t num_workers);

/**
 * Parse corelist string (e.g., "1-15") and return worker count
 */
int yesrouter_config_parse_corelist(const char *corelist)
{
    if (!corelist || strlen(corelist) == 0)
        return 0;

    int start = 0, end = 0;
    if (sscanf(corelist, "%d-%d", &start, &end) == 2) {
        return end - start + 1;
    } else if (sscanf(corelist, "%d", &start) == 1) {
        return 1;
    }
    return 0;
}

void yesrouter_config_init_defaults(void)
{
    memset(&g_yesrouter_hw_config, 0, sizeof(g_yesrouter_hw_config));

    /* Unix defaults */
    g_yesrouter_hw_config.unix_config.interactive = false;
    strcpy(g_yesrouter_hw_config.unix_config.cli_listen, "/run/yesrouter/cli.sock");
    strcpy(g_yesrouter_hw_config.unix_config.exec_script, "/etc/yesrouter/startup.json");
    strcpy(g_yesrouter_hw_config.unix_config.log_file, "/var/log/yesrouter/yesrouter.log");

    /* DPDK defaults */
    g_yesrouter_hw_config.dpdk_config.enabled = true;
    g_yesrouter_hw_config.dpdk_config.socket_mem = 4096;
    g_yesrouter_hw_config.dpdk_config.num_mbufs = 262144;
    g_yesrouter_hw_config.dpdk_config.no_pci = false;

    /* CPU defaults */
    g_yesrouter_hw_config.cpu_config.main_core = 0;
    strcpy(g_yesrouter_hw_config.cpu_config.corelist_workers, "1-7");
    g_yesrouter_hw_config.cpu_config.num_workers = 7;

    /* NAT defaults (production-grade) */
    g_yesrouter_hw_config.nat_config.workers = 8;
    g_yesrouter_hw_config.nat_config.max_sessions = 2000000;
    g_yesrouter_hw_config.nat_config.session_cache_size = 256;
}

static char *trim_whitespace(char *str)
{
    char *end;

    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    *(end + 1) = 0;

    return str;
}

int yesrouter_config_parse(const char *filename)
{
    FILE *fp;
    char line[1024];
    char current_section[64] = "";
    bool inside_device_block = false;
    int current_device_idx = -1;

    fp = fopen(filename, "r");
    if (!fp) {
        printf("Config file %s not found, using defaults\n", filename);
        return 0; /* Not an error - use defaults */
    }

    printf("Loading configuration from %s\n", filename);

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim_whitespace(line);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#' || p[0] == '!')
            continue;

        /* Check for section start */
        char *brace = strchr(p, '{');
        if (brace) {
            *brace = '\0';
            p = trim_whitespace(p);

            if (inside_device_block) {
                /* Nested block */
            } else if (strcmp(current_section, "dpdk") == 0 && strncmp(p, "dev ", 4) == 0) {
                /* Start of device block: dev 0000:00:00.0 { ... */
                char *dev_id = trim_whitespace(p + 4);
                if (g_yesrouter_hw_config.dpdk_config.num_devices < 32) {
                    current_device_idx = g_yesrouter_hw_config.dpdk_config.num_devices++;
                    strncpy(g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].pci_addr,
                            dev_id, 31);
                    /* Set defaults */
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_rx_queues = 4;
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_tx_queues = 4;
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_rx_desc = 2048;
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_tx_desc = 2048;
                    inside_device_block = true;
                }
                continue;
            } else {
                snprintf(current_section, sizeof(current_section), "%s", p);
            }
            continue;
        }

        /* Check for section end */
        if (strchr(p, '}')) {
            if (inside_device_block) {
                inside_device_block = false;
                current_device_idx = -1;
            } else {
                current_section[0] = '\0';
            }
            continue;
        }

        /* Parse key-value pairs */
        char *key = p;
        char *value = NULL;

        /* Find space separator */
        char *space = strpbrk(p, " \t");
        if (space) {
            *space = '\0';
            value = trim_whitespace(space + 1);
        }

        if (strcmp(current_section, "unix") == 0) {
            if (strcmp(key, "interactive") == 0) {
                g_yesrouter_hw_config.unix_config.interactive = true;
            } else if (strcmp(key, "exec") == 0 && value) {
                strncpy(g_yesrouter_hw_config.unix_config.exec_script, value,
                        sizeof(g_yesrouter_hw_config.unix_config.exec_script) - 1);
            } else if (strcmp(key, "cli-listen") == 0 && value) {
                strncpy(g_yesrouter_hw_config.unix_config.cli_listen, value,
                        sizeof(g_yesrouter_hw_config.unix_config.cli_listen) - 1);
            } else if (strcmp(key, "log") == 0 && value) {
                strncpy(g_yesrouter_hw_config.unix_config.log_file, value,
                        sizeof(g_yesrouter_hw_config.unix_config.log_file) - 1);
            }
        } else if (strcmp(current_section, "dpdk") == 0) {
            if (inside_device_block && current_device_idx >= 0) {
                /* Device specific config */
                if (strcmp(key, "name") == 0 && value) {
                    strncpy(g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].name, value,
                            31);
                } else if (strcmp(key, "num-rx-queues") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_rx_queues =
                        atoi(value);
                } else if (strcmp(key, "num-tx-queues") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_tx_queues =
                        atoi(value);
                } else if (strcmp(key, "num-rx-desc") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_rx_desc =
                        atoi(value);
                } else if (strcmp(key, "num-tx-desc") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.devices[current_device_idx].num_tx_desc =
                        atoi(value);
                }
            } else {
                /* Global DPDK config */
                if (strcmp(key, "no-pci") == 0) {
                    g_yesrouter_hw_config.dpdk_config.no_pci = true;
                } else if (strcmp(key, "socket-mem") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.socket_mem = atoi(value);
                } else if (strcmp(key, "num-mbufs") == 0 && value) {
                    g_yesrouter_hw_config.dpdk_config.num_mbufs = atoi(value);
                } else if (strcmp(key, "vdev") == 0 && value) {
                    /* Virtual device (e.g., vdev net_tap0,iface=vbng_in) */
                    if (g_yesrouter_hw_config.dpdk_config.num_vdevs < 8) {
                        int idx = g_yesrouter_hw_config.dpdk_config.num_vdevs++;
                        strncpy(g_yesrouter_hw_config.dpdk_config.vdevs[idx].vdev_arg,
                                value, 127);
                        printf("  Added vdev: %s\n", value);
                    }
                }
            }
        } else if (strcmp(current_section, "cpu") == 0) {
            if (strcmp(key, "main-core") == 0 && value) {
                g_yesrouter_hw_config.cpu_config.main_core = atoi(value);
            } else if (strcmp(key, "corelist-workers") == 0 && value) {
                strncpy(g_yesrouter_hw_config.cpu_config.corelist_workers, value,
                        sizeof(g_yesrouter_hw_config.cpu_config.corelist_workers) - 1);
                g_yesrouter_hw_config.cpu_config.num_workers = yesrouter_config_parse_corelist(value);
            } else if (strcmp(key, "skip-cores") == 0 && value) {
                g_yesrouter_hw_config.cpu_config.skip_cores = atoi(value);
            }
        } else if (strcmp(current_section, "nat") == 0) {
            /* NAT Performance Tuning */
            if (strcmp(key, "workers") == 0 && value) {
                g_yesrouter_hw_config.nat_config.workers = atoi(value);
            } else if (strcmp(key, "max-sessions") == 0 && value) {
                g_yesrouter_hw_config.nat_config.max_sessions = atoi(value);
            } else if (strcmp(key, "session-cache-size") == 0 && value) {
                g_yesrouter_hw_config.nat_config.session_cache_size = atoi(value);
            }
        }
    }

    fclose(fp);
    return 0;
}

/**
 * Apply NAT configuration from yesrouter.conf to NAT module
 */
void yesrouter_config_apply_nat(void)
{
    printf("Applying NAT configuration:\n");
    printf("  Workers: %d\n", g_yesrouter_hw_config.nat_config.workers);
    printf("  Max Sessions: %d\n", g_yesrouter_hw_config.nat_config.max_sessions);
    printf("  Session Cache: %d\n", g_yesrouter_hw_config.nat_config.session_cache_size);

    /* Apply worker count to NAT module */
    nat_set_num_workers(g_yesrouter_hw_config.nat_config.workers);
}

void yesrouter_config_print(void)
{
    printf("\n========================================\n");
    printf("YESRouter Configuration\n");
    printf("========================================\n");

    printf("\nUnix:\n");
    printf("  Interactive: %s\n", g_yesrouter_hw_config.unix_config.interactive ? "yes" : "no");
    printf("  Exec Script: %s\n", g_yesrouter_hw_config.unix_config.exec_script);
    printf("  CLI Listen: %s\n", g_yesrouter_hw_config.unix_config.cli_listen);
    printf("  Log File: %s\n", g_yesrouter_hw_config.unix_config.log_file);

    printf("\nCPU:\n");
    printf("  Main Core: %d\n", g_yesrouter_hw_config.cpu_config.main_core);
    printf("  Workers: %s (%d cores)\n", g_yesrouter_hw_config.cpu_config.corelist_workers,
           g_yesrouter_hw_config.cpu_config.num_workers);

    printf("\nDPDK:\n");
    printf("  Socket Mem: %d MB\n", g_yesrouter_hw_config.dpdk_config.socket_mem);
    printf("  Num Mbufs: %d\n", g_yesrouter_hw_config.dpdk_config.num_mbufs);
    printf("  Devices: %d\n", g_yesrouter_hw_config.dpdk_config.num_devices);
    for (int i = 0; i < g_yesrouter_hw_config.dpdk_config.num_devices; i++) {
        printf("    %s (%s) RXQ:%d TXQ:%d\n", g_yesrouter_hw_config.dpdk_config.devices[i].pci_addr,
               g_yesrouter_hw_config.dpdk_config.devices[i].name,
               g_yesrouter_hw_config.dpdk_config.devices[i].num_rx_queues,
               g_yesrouter_hw_config.dpdk_config.devices[i].num_tx_queues);
    }

    printf("\nNAT (Performance Tuning):\n");
    printf("  Workers: %d\n", g_yesrouter_hw_config.nat_config.workers);
    printf("  Max Sessions: %d\n", g_yesrouter_hw_config.nat_config.max_sessions);
    printf("  Max Sessions: %d\n", g_yesrouter_hw_config.nat_config.max_sessions);
    printf("  Session Cache: %d\n", g_yesrouter_hw_config.nat_config.session_cache_size);
    printf("========================================\n\n");
}
