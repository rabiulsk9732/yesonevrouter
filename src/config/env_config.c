/**
 * @file env_config.c
 * @brief Bison-Style Environment Configuration Parser
 *
 * Minimal .env file for essential DPDK infrastructure parameters.
 * Sensible defaults applied for optional parameters.
 */

#include "env_config.h"
#include "log.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global config instance */
struct env_config g_env_config;

/* Parse helpers */
static char *trim(char *str)
{
    while (isspace(*str))
        str++;
    if (*str == 0)
        return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    *(end + 1) = '\0';
    return str;
}

static int parse_int(const char *str, int *out, int min, int max)
{
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    if (errno || *endptr != '\0' || val < min || val > max) {
        return -1;
    }
    *out = (int)val;
    return 0;
}

static int parse_bool(const char *str, bool *out)
{
    if (strcasecmp(str, "true") == 0 || strcmp(str, "1") == 0) {
        *out = true;
        return 0;
    }
    if (strcasecmp(str, "false") == 0 || strcmp(str, "0") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

static int parse_lcores(const char *str, int *lcores, int *count)
{
    char buf[256];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Remove quotes */
    char *p = buf;
    if (*p == '"')
        p++;
    char *end = p + strlen(p) - 1;
    if (*end == '"')
        *end = '\0';

    *count = 0;
    char *token = strtok(p, ",");
    while (token && *count < ENV_MAX_LCORES) {
        int val;
        if (parse_int(trim(token), &val, 0, 127) == 0) {
            lcores[(*count)++] = val;
        }
        token = strtok(NULL, ",");
    }
    return (*count > 0) ? 0 : -1;
}

static int parse_ports(const char *str, char ports[][32], int *count)
{
    char buf[256];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Remove quotes */
    char *p = buf;
    if (*p == '"')
        p++;
    char *end = p + strlen(p) - 1;
    if (*end == '"')
        *end = '\0';

    *count = 0;
    char *token = strtok(p, " ,");
    while (token && *count < ENV_MAX_PORTS) {
        strncpy(ports[*count], trim(token), 31);
        ports[*count][31] = '\0';
        (*count)++;
        token = strtok(NULL, " ,");
    }
    return (*count > 0) ? 0 : -1;
}

int env_config_load(const char *path)
{
    FILE *f;
    char line[512];
    int errors = 0;

    /* Initialize to zero */
    memset(&g_env_config, 0, sizeof(g_env_config));

    const char *env_path = path ? path : "/etc/yesrouter/yesrouter.env";
    strncpy(g_env_config.env_path, env_path, ENV_MAX_PATH - 1);

    f = fopen(env_path, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open .env file: %s\n", env_path);
        return -1;
    }

    printf("Loading Bison-style config from: %s\n", env_path);

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);

        /* Skip comments and empty lines */
        if (*p == '\0' || *p == '#')
            continue;

        /* Parse KEY=VALUE */
        char *eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = trim(p);
        char *value = trim(eq + 1);

        /* Strip inline comments (everything after # in the value) */
        char *comment_start = strchr(value, '#');
        if (comment_start) {
            *comment_start = '\0';
            value = trim(value); /* Re-trim after removing comment */
        }

        /* Remove quotes from value */
        if (*value == '"') {
            value++;
            char *vend = value + strlen(value) - 1;
            if (*vend == '"')
                *vend = '\0';
        }

        /* Core Configuration */
        if (strcmp(key, "MAIN_LCORE") == 0) {
            parse_int(value, &g_env_config.dpdk.main_lcore, 0, 127);
        } else if (strcmp(key, "WORKER_LCORES") == 0) {
            parse_lcores(value, g_env_config.dpdk.worker_lcores, &g_env_config.dpdk.num_workers);
        } else if (strcmp(key, "NUMA_NODE") == 0) {
            parse_int(value, &g_env_config.dpdk.numa_node, 0, 7);
        }
        /* Memory */
        else if (strcmp(key, "MEMORY_MB") == 0) {
            parse_int(value, &g_env_config.dpdk.socket_mem_mb, 256, 65536);
        } else if (strcmp(key, "MBUF_COUNT") == 0) {
            parse_int(value, &g_env_config.dpdk.mbuf_count, 8192, 16777216);
        } else if (strcmp(key, "MBUF_CACHE_SIZE") == 0) {
            parse_int(value, &g_env_config.dpdk.mbuf_cache_size, 0, 1024);
        } else if (strcmp(key, "HUGEPAGES") == 0) {
            parse_int(value, &g_env_config.dpdk.hugepages, 64, 65536);
        }
        /* Port Configuration */
        else if (strcmp(key, "PORTS") == 0) {
            parse_ports(value, g_env_config.dpdk.ports, &g_env_config.dpdk.num_ports);
        } else if (strcmp(key, "DRIVER") == 0) {
            strncpy(g_env_config.dpdk.driver, value, 63);
        } else if (strcmp(key, "PORT_MTU") == 0) {
            parse_int(value, &g_env_config.dpdk.port_mtu, 64, 9216);
        }
        /* Queue Configuration */
        else if (strcmp(key, "RX_QUEUES") == 0) {
            parse_int(value, &g_env_config.dpdk.rx_queues, 1, 64);
        } else if (strcmp(key, "TX_QUEUES") == 0) {
            parse_int(value, &g_env_config.dpdk.tx_queues, 1, 64);
        } else if (strcmp(key, "RX_DESC") == 0) {
            parse_int(value, &g_env_config.dpdk.rx_desc, 64, 8192);
        } else if (strcmp(key, "TX_DESC") == 0) {
            parse_int(value, &g_env_config.dpdk.tx_desc, 64, 8192);
        } else if (strcmp(key, "RX_BURST_SIZE") == 0) {
            parse_int(value, &g_env_config.dpdk.rx_burst_size, 1, 256);
        } else if (strcmp(key, "TX_BURST_SIZE") == 0) {
            parse_int(value, &g_env_config.dpdk.tx_burst_size, 1, 256);
        }
        /* RSS */
        else if (strcmp(key, "RSS_ENABLE") == 0) {
            parse_bool(value, &g_env_config.dpdk.rss_enable);
        }

        /* Logging - accept string or int */
        else if (strcmp(key, "LOG_LEVEL") == 0) {
            if (strcmp(value, "debug") == 0)
                g_env_config.log.level = 7;
            else if (strcmp(value, "info") == 0)
                g_env_config.log.level = 6;
            else if (strcmp(value, "warn") == 0)
                g_env_config.log.level = 4;
            else if (strcmp(value, "error") == 0)
                g_env_config.log.level = 3;
            else
                parse_int(value, &g_env_config.log.level, 0, 7);
        }
    }

    fclose(f);

    /* Apply defaults for missing values (Bison-style - minimal config) */
    if (g_env_config.dpdk.num_workers == 0) {
        g_env_config.dpdk.num_workers = 1;
        g_env_config.dpdk.worker_lcores[0] = 1;
    }
    if (g_env_config.dpdk.rx_queues == 0) {
        g_env_config.dpdk.rx_queues = 1;
    }
    if (g_env_config.dpdk.tx_queues == 0) {
        g_env_config.dpdk.tx_queues = 1;
    }
    if (g_env_config.dpdk.rx_burst_size == 0) {
        g_env_config.dpdk.rx_burst_size = 128;
    }
    if (g_env_config.dpdk.tx_burst_size == 0) {
        g_env_config.dpdk.tx_burst_size = 128;
    }
    if (g_env_config.dpdk.rx_desc == 0) {
        g_env_config.dpdk.rx_desc = 2048;
    }
    if (g_env_config.dpdk.tx_desc == 0) {
        g_env_config.dpdk.tx_desc = 2048;
    }
    if (g_env_config.dpdk.mbuf_count == 0) {
        g_env_config.dpdk.mbuf_count = 262144;
    }
    if (g_env_config.dpdk.socket_mem_mb == 0) {
        g_env_config.dpdk.socket_mem_mb = 2048;
    }

    g_env_config.validated = true;
    printf("Configuration validated successfully\n");
    return 0;
}

void env_config_print(void)
{
    printf("=== YESRouter Configuration ===\n");
    printf("DPDK:\n");
    printf("  main_lcore: %d\n", g_env_config.dpdk.main_lcore);
    printf("  num_workers: %d\n", g_env_config.dpdk.num_workers);
    printf("  numa_node: %d\n", g_env_config.dpdk.numa_node);
    printf("  socket_mem_mb: %d\n", g_env_config.dpdk.socket_mem_mb);
    printf("  mbuf_count: %d\n", g_env_config.dpdk.mbuf_count);
    printf("  rx_queues: %d\n", g_env_config.dpdk.rx_queues);
    printf("  tx_queues: %d\n", g_env_config.dpdk.tx_queues);
    printf("  rx_burst_size: %d\n", g_env_config.dpdk.rx_burst_size);
    printf("  rss_enable: %s\n", g_env_config.dpdk.rss_enable ? "true" : "false");
    printf("================================\n");
}

/* Getters */
int env_get_rx_queues(void)
{
    return g_env_config.dpdk.rx_queues;
}
int env_get_tx_queues(void)
{
    return g_env_config.dpdk.tx_queues;
}
int env_get_rx_burst_size(void)
{
    return g_env_config.dpdk.rx_burst_size;
}
int env_get_tx_burst_size(void)
{
    return g_env_config.dpdk.tx_burst_size;
}
int env_get_rx_desc(void)
{
    return g_env_config.dpdk.rx_desc;
}
int env_get_tx_desc(void)
{
    return g_env_config.dpdk.tx_desc;
}
int env_get_num_workers(void)
{
    return g_env_config.dpdk.num_workers;
}
int env_get_numa_node(void)
{
    return g_env_config.dpdk.numa_node;
}
bool env_get_rss_enable(void)
{
    return g_env_config.dpdk.rss_enable;
}
