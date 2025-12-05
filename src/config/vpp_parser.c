/**
 * @file vpp_parser.c
 * @brief VPP-style Configuration Parser
 */

#include "vpp_parser.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct vpp_config g_vpp_config;

void vpp_config_init_defaults(void)
{
    memset(&g_vpp_config, 0, sizeof(g_vpp_config));

    /* Unix defaults */
    g_vpp_config.unix_config.interactive = false;
    strcpy(g_vpp_config.unix_config.cli_listen, "");
    strcpy(g_vpp_config.unix_config.exec_script, "");
    strcpy(g_vpp_config.unix_config.log_file, "/var/log/yesrouter.log");

    /* DPDK defaults */
    g_vpp_config.dpdk_config.enabled = true;
    g_vpp_config.dpdk_config.socket_mem = 1024;
    g_vpp_config.dpdk_config.num_mbufs = 16384;
    g_vpp_config.dpdk_config.no_pci = false;

    /* CPU defaults */
    g_vpp_config.cpu_config.main_core = 0;
    strcpy(g_vpp_config.cpu_config.corelist_workers, "");
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

int vpp_config_parse(const char *filename)
{
    FILE *fp;
    char line[1024];
    char current_section[64] = "";
    bool inside_device_block = false;
    int current_device_idx = -1;

    fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open config file");
        return -1;
    }

    printf("Loading configuration from %s\n", filename);

    while (fgets(line, sizeof(line), fp)) {
        char *p = trim_whitespace(line);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#')
            continue;

        /* Check for section start */
        char *brace = strchr(p, '{');
        if (brace) {
            *brace = '\0';
            p = trim_whitespace(p);

            if (inside_device_block) {
                /* Nested block? Should not happen in this simple parser unless it's dev block start
                 * on same line */
            } else if (strcmp(current_section, "dpdk") == 0 && strncmp(p, "dev ", 4) == 0) {
                /* Start of device block: dev 0000:00:00.0 { ... */
                char *dev_id = trim_whitespace(p + 4);
                if (g_vpp_config.dpdk_config.num_devices < 32) {
                    current_device_idx = g_vpp_config.dpdk_config.num_devices++;
                    strncpy(g_vpp_config.dpdk_config.devices[current_device_idx].pci_addr, dev_id,
                            31);
                    /* Set defaults */
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_rx_queues = 1;
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_tx_queues = 1;
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_rx_desc = 1024;
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_tx_desc = 1024;
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
                g_vpp_config.unix_config.interactive = true;
            } else if (strcmp(key, "exec") == 0 && value) {
                strncpy(g_vpp_config.unix_config.exec_script, value,
                        sizeof(g_vpp_config.unix_config.exec_script) - 1);
            } else if (strcmp(key, "cli-listen") == 0 && value) {
                strncpy(g_vpp_config.unix_config.cli_listen, value,
                        sizeof(g_vpp_config.unix_config.cli_listen) - 1);
            } else if (strcmp(key, "log") == 0 && value) {
                strncpy(g_vpp_config.unix_config.log_file, value,
                        sizeof(g_vpp_config.unix_config.log_file) - 1);
            }
        } else if (strcmp(current_section, "dpdk") == 0) {
            if (inside_device_block && current_device_idx >= 0) {
                /* Device specific config */
                if (strcmp(key, "name") == 0 && value) {
                    strncpy(g_vpp_config.dpdk_config.devices[current_device_idx].name, value, 31);
                } else if (strcmp(key, "num-rx-queues") == 0 && value) {
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_rx_queues =
                        atoi(value);
                } else if (strcmp(key, "num-tx-queues") == 0 && value) {
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_tx_queues =
                        atoi(value);
                } else if (strcmp(key, "num-rx-desc") == 0 && value) {
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_rx_desc = atoi(value);
                } else if (strcmp(key, "num-tx-desc") == 0 && value) {
                    g_vpp_config.dpdk_config.devices[current_device_idx].num_tx_desc = atoi(value);
                }
            } else {
                /* Global DPDK config */
                if (strcmp(key, "dev") == 0 && value) {
                    /* Handle one-line dev config: dev 0000:00:00.0 */
                    /* Note: This simple parser doesn't handle one-line blocks like dev X { ... }
                       well if split across lines logic isn't robust. But assuming standard VPP
                       format where { is usually on same line or next. We handled the { case above.
                       This is for simple 'dev X' without block. */
                    if (g_vpp_config.dpdk_config.num_devices < 32) {
                        int idx = g_vpp_config.dpdk_config.num_devices++;
                        strncpy(g_vpp_config.dpdk_config.devices[idx].pci_addr, value, 31);
                        /* Defaults */
                        g_vpp_config.dpdk_config.devices[idx].num_rx_queues = 1;
                        g_vpp_config.dpdk_config.devices[idx].num_tx_queues = 1;
                    }
                } else if (strcmp(key, "no-pci") == 0) {
                    g_vpp_config.dpdk_config.no_pci = true;
                } else if (strcmp(key, "socket-mem") == 0 && value) {
                    g_vpp_config.dpdk_config.socket_mem = atoi(value);
                } else if (strcmp(key, "num-mbufs") == 0 && value) {
                    g_vpp_config.dpdk_config.num_mbufs = atoi(value);
                }
            }
        } else if (strcmp(current_section, "cpu") == 0) {
            if (strcmp(key, "main-core") == 0 && value) {
                g_vpp_config.cpu_config.main_core = atoi(value);
            } else if (strcmp(key, "corelist-workers") == 0 && value) {
                strncpy(g_vpp_config.cpu_config.corelist_workers, value,
                        sizeof(g_vpp_config.cpu_config.corelist_workers) - 1);
            } else if (strcmp(key, "skip-cores") == 0 && value) {
                g_vpp_config.cpu_config.skip_cores = atoi(value);
            }
        }
    }

    fclose(fp);
    return 0;
}

void vpp_config_print(void)
{
    printf("VPP Configuration:\n");
    printf("  Unix:\n");
    printf("    Interactive: %s\n", g_vpp_config.unix_config.interactive ? "yes" : "no");
    printf("    Exec Script: %s\n", g_vpp_config.unix_config.exec_script);
    printf("    CLI Listen: %s\n", g_vpp_config.unix_config.cli_listen);
    printf("    Log File: %s\n", g_vpp_config.unix_config.log_file);

    printf("  DPDK:\n");
    printf("    Enabled: %s\n", g_vpp_config.dpdk_config.enabled ? "yes" : "no");
    printf("    No PCI: %s\n", g_vpp_config.dpdk_config.no_pci ? "yes" : "no");
    printf("    Socket Mem: %d MB\n", g_vpp_config.dpdk_config.socket_mem);
    printf("    Devices:\n");
    for (int i = 0; i < g_vpp_config.dpdk_config.num_devices; i++) {
        printf("      %s (Name: %s, RXQ: %d, TXQ: %d)\n",
               g_vpp_config.dpdk_config.devices[i].pci_addr,
               g_vpp_config.dpdk_config.devices[i].name,
               g_vpp_config.dpdk_config.devices[i].num_rx_queues,
               g_vpp_config.dpdk_config.devices[i].num_tx_queues);
    }

    printf("  CPU:\n");
    printf("    Main Core: %d\n", g_vpp_config.cpu_config.main_core);
    printf("    Workers: %s\n", g_vpp_config.cpu_config.corelist_workers);
}
