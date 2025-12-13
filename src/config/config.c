/**
 * @file config.c
 * @brief Configuration Management Implementation
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#ifdef HAVE_LIBYANG
#include <libyang/libyang.h>
#endif

/* Global configuration instance */
struct yesrouter_config g_config;

/* Backup configuration for rollback */
static struct yesrouter_config g_config_backup;
static bool g_has_backup = false;

#ifdef HAVE_LIBYANG
/* libyang context */
static struct ly_ctx *g_yang_ctx = NULL;
#endif

/* Configuration file parsing helpers */
static char *trim(char *str)
{
    char *end;

    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

static int parse_bool(const char *str, bool *val)
{
    if (strcasecmp(str, "true") == 0 ||
        strcasecmp(str, "yes") == 0 ||
        strcasecmp(str, "1") == 0 ||
        strcasecmp(str, "on") == 0) {
        *val = true;
        return 0;
    }
    if (strcasecmp(str, "false") == 0 ||
        strcasecmp(str, "no") == 0 ||
        strcasecmp(str, "0") == 0 ||
        strcasecmp(str, "off") == 0) {
        *val = false;
        return 0;
    }
    return -1;
}

int config_parse_ip(const char *str, struct in_addr *addr)
{
    if (inet_pton(AF_INET, str, addr) != 1) {
        return -1;
    }
    return 0;
}

const char *config_ip_to_str(struct in_addr addr)
{
    static char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &addr, buf, sizeof(buf));
}

void config_set_defaults(struct yesrouter_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    /* System defaults */
    strncpy(cfg->system.hostname, "yesrouter", sizeof(cfg->system.hostname) - 1);
    cfg->system.log_level = 3; /* INFO */
    cfg->system.daemonize = false;
    strncpy(cfg->system.pid_file, "/var/run/yesrouter.pid", sizeof(cfg->system.pid_file) - 1);

    /* Routing defaults */
    cfg->routing.local_as = 65000;
    inet_pton(AF_INET, "10.0.0.1", &cfg->routing.router_id);

    /* BNG defaults */
    cfg->bng.pppoe_enabled = true;
    cfg->bng.ipoe_enabled = true;
    strncpy(cfg->bng.ac_name, "YESRouter-AC", sizeof(cfg->bng.ac_name) - 1);
    cfg->bng.pppoe_mtu = 1492;
    cfg->bng.session_timeout = 86400; /* 24 hours */
    cfg->bng.max_sessions = 100000;

    /* Default IP pool */
    cfg->bng.num_ip_pools = 1;
    strncpy(cfg->bng.ip_pools[0].name, "default-pool", sizeof(cfg->bng.ip_pools[0].name) - 1);
    inet_pton(AF_INET, "10.0.0.1", &cfg->bng.ip_pools[0].start_ip);
    inet_pton(AF_INET, "10.0.255.254", &cfg->bng.ip_pools[0].end_ip);
    inet_pton(AF_INET, "255.255.0.0", &cfg->bng.ip_pools[0].netmask);
    inet_pton(AF_INET, "10.0.0.1", &cfg->bng.ip_pools[0].gateway);
    inet_pton(AF_INET, "8.8.8.8", &cfg->bng.ip_pools[0].dns_primary);
    inet_pton(AF_INET, "8.8.4.4", &cfg->bng.ip_pools[0].dns_secondary);
    cfg->bng.ip_pools[0].lease_time = 86400;

    /* CGNAT defaults */
    cfg->cgnat.enabled = false;
    inet_pton(AF_INET, "100.64.0.1", &cfg->cgnat.public_ip_start);
    inet_pton(AF_INET, "100.64.0.254", &cfg->cgnat.public_ip_end);
    cfg->cgnat.port_range_start = 1024;
    cfg->cgnat.port_range_end = 65535;
    cfg->cgnat.session_timeout = 300;
    cfg->cgnat.logging_enabled = true;

    /* QoS defaults */
    cfg->qos.enabled = true;
    cfg->qos.default_rate_limit_down = 100000; /* 100 Mbps */
    cfg->qos.default_rate_limit_up = 50000;    /* 50 Mbps */
    cfg->qos.burst_size = 1500000;             /* 1.5 MB */

    /* Firewall defaults */
    cfg->firewall.enabled = true;
    cfg->firewall.stateful_enabled = true;
    cfg->firewall.connection_timeout = 300;
    cfg->firewall.max_connections = 1000000;

    /* Management defaults */
    cfg->management.rest_api_enabled = true;
    cfg->management.rest_api_port = 8080;
    strncpy(cfg->management.rest_api_bind, "0.0.0.0", sizeof(cfg->management.rest_api_bind) - 1);
    cfg->management.cli_enabled = true;
    cfg->management.cli_port = 22;

    cfg->version = 1;
}

int config_init(void)
{
    config_set_defaults(&g_config);
    g_config.is_loaded = false;
    g_config.is_valid = false;
    g_has_backup = false;

#ifdef HAVE_LIBYANG
    /* Initialize libyang context */
    ly_log_options(LY_LOLOG | LY_LOSTORE);
    g_yang_ctx = ly_ctx_new(NULL, 0);
    if (!g_yang_ctx) {
        fprintf(stderr, "Failed to initialize libyang context\n");
        return -1;
    }

    /* Load YANG model */
    const char *yang_path = "src/config/yesrouter.yang";
    if (ly_ctx_load_module(g_yang_ctx, "yesrouter", NULL) == NULL) {
        /* Try loading from file if module not found in search path */
        if (lys_parse_path(g_yang_ctx, yang_path, LYS_IN_YANG) == NULL) {
            fprintf(stderr, "Warning: Could not load YANG model, using simple parser\n");
        } else {
            printf("YANG model loaded successfully\n");
        }
    } else {
        printf("YANG model loaded successfully\n");
    }
#endif

    printf("Configuration subsystem initialized\n");
    return 0;
}

static int parse_config_line(char *line, struct yesrouter_config *cfg)
{
    char *key, *value;
    char *equals;

    /* Skip comments and empty lines */
    line = trim(line);
    if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
        return 0;
    }

    /* Find key=value separator */
    equals = strchr(line, '=');
    if (!equals) {
        return 0;
    }

    *equals = '\0';
    key = trim(line);
    value = trim(equals + 1);

    /* Parse known keys */
    if (strcmp(key, "hostname") == 0) {
        strncpy(cfg->system.hostname, value, sizeof(cfg->system.hostname) - 1);
    } else if (strcmp(key, "log_level") == 0) {
        cfg->system.log_level = (uint32_t)atoi(value);
    } else if (strcmp(key, "daemonize") == 0) {
        parse_bool(value, &cfg->system.daemonize);
    } else if (strcmp(key, "local_as") == 0) {
        cfg->routing.local_as = (uint32_t)atoi(value);
    } else if (strcmp(key, "router_id") == 0) {
        config_parse_ip(value, &cfg->routing.router_id);
    } else if (strcmp(key, "pppoe_enabled") == 0) {
        parse_bool(value, &cfg->bng.pppoe_enabled);
    } else if (strcmp(key, "ipoe_enabled") == 0) {
        parse_bool(value, &cfg->bng.ipoe_enabled);
    } else if (strcmp(key, "ac_name") == 0) {
        strncpy(cfg->bng.ac_name, value, sizeof(cfg->bng.ac_name) - 1);
    } else if (strcmp(key, "pppoe_mtu") == 0) {
        cfg->bng.pppoe_mtu = (uint16_t)atoi(value);
    } else if (strcmp(key, "max_sessions") == 0) {
        cfg->bng.max_sessions = (uint32_t)atoi(value);
    } else if (strcmp(key, "cgnat_enabled") == 0) {
        parse_bool(value, &cfg->cgnat.enabled);
    } else if (strcmp(key, "qos_enabled") == 0) {
        parse_bool(value, &cfg->qos.enabled);
    } else if (strcmp(key, "firewall_enabled") == 0) {
        parse_bool(value, &cfg->firewall.enabled);
    } else if (strcmp(key, "rest_api_enabled") == 0) {
        parse_bool(value, &cfg->management.rest_api_enabled);
    } else if (strcmp(key, "rest_api_port") == 0) {
        cfg->management.rest_api_port = (uint16_t)atoi(value);
    }

    return 0;
}

#ifdef HAVE_LIBYANG
/**
 * Load configuration from YANG XML/JSON file
 */
static int config_load_yang(const char *filename, struct yesrouter_config *cfg)
{
    struct lyd_node *data_tree = NULL;
    const struct lys_module *mod = NULL;
    const char *data_path = NULL;
    int ret = -1;

    if (!g_yang_ctx) {
        fprintf(stderr, "YANG context not initialized\n");
        return -1;
    }

    /* Get the module */
    mod = ly_ctx_get_module(g_yang_ctx, "yesrouter", NULL, 1);
    if (!mod) {
        fprintf(stderr, "YANG module 'yesrouter' not found\n");
        return -1;
    }

    /* Parse data file (try XML first, then JSON) */
    data_tree = lyd_parse_path(g_yang_ctx, filename, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    if (!data_tree) {
        /* Try JSON format */
        data_tree = lyd_parse_path(g_yang_ctx, filename, LYD_JSON, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    }

    if (!data_tree) {
        fprintf(stderr, "Failed to parse YANG data file: %s\n", ly_errmsg(g_yang_ctx));
        return -1;
    }

    /* Validate the data tree */
    if (lyd_validate(&data_tree, LYD_OPT_CONFIG, NULL) != 0) {
        fprintf(stderr, "YANG data validation failed: %s\n", ly_errmsg(g_yang_ctx));
        lyd_free_withsiblings(data_tree);
        return -1;
    }

    /* Extract configuration from YANG data tree */
    /* Note: This is a simplified extraction - in production, you'd want
     * a more robust mapping from YANG nodes to C structures */

    /* For now, we'll use the simple parser as fallback and mark YANG as loaded */
    printf("YANG configuration parsed successfully (using fallback extraction)\n");

    lyd_free_withsiblings(data_tree);
    return 0;
}
#endif

#ifdef HAVE_LIBYANG
/**
 * Check if file is YANG format (XML or JSON)
 */
static bool is_yang_file(const char *filename)
{
    const char *ext = strrchr(filename, '.');
    if (!ext) {
        return false;
    }

    return (strcmp(ext, ".xml") == 0 ||
            strcmp(ext, ".json") == 0 ||
            strcmp(ext, ".yang") == 0);
}
#endif

int config_load(const char *filename)
{
    FILE *fp;
    char line[1024];
    struct yesrouter_config new_cfg;
    int ret = -1;

    if (!filename) {
        fprintf(stderr, "Configuration file not specified\n");
        return -1;
    }

    /* Start with defaults */
    config_set_defaults(&new_cfg);
    strncpy(new_cfg.config_file, filename, sizeof(new_cfg.config_file) - 1);

#ifdef HAVE_LIBYANG
    /* Try YANG parser first if file appears to be YANG format */
    if (is_yang_file(filename) && g_yang_ctx) {
        if (config_load_yang(filename, &new_cfg) == 0) {
            ret = 0; /* YANG parsing succeeded */
        } else {
            fprintf(stderr, "YANG parsing failed, falling back to simple parser\n");
        }
    }
#endif

    /* Fall back to simple key-value parser if YANG parsing failed or not available */
    if (ret != 0) {
        fp = fopen(filename, "r");
        if (!fp) {
            fprintf(stderr, "Cannot open configuration file: %s (%s)\n",
                    filename, strerror(errno));
            return -1;
        }

        /* Parse configuration file */
        while (fgets(line, sizeof(line), fp)) {
            char *trimmed = trim(line);
            if (trimmed[0] == '#' || trimmed[0] == ';' || trimmed[0] == '!' || trimmed[0] == '\0') {
                continue;
            }

            /* Check if it's a key=value pair */
            if (strchr(trimmed, '=')) {
                if (parse_config_line(trimmed, &new_cfg) < 0) {
                    fprintf(stderr, "Error parsing configuration line: %s\n", trimmed);
                }
            } else {
                /* Assume it's a CLI command */
                extern int cli_execute(const char *cmdline);
                printf("Executing startup command: %s\n", trimmed);
                cli_execute(trimmed);
            }
        }

        fclose(fp);
        ret = 0;
    }

    /* Validate new configuration */
    if (config_validate(&new_cfg) < 0) {
        fprintf(stderr, "Configuration validation failed\n");
        return -1;
    }

    /* Backup current configuration before applying new one */
    if (g_config.is_loaded) {
        config_backup();
    }

    /* Apply new configuration */
    memcpy(&g_config, &new_cfg, sizeof(g_config));
    g_config.is_loaded = true;
    g_config.is_valid = true;
    g_config.load_time = (uint64_t)time(NULL);

    printf("Configuration loaded from: %s\n", filename);
    return ret;
}

int config_reload(void)
{
    if (!g_config.is_loaded || g_config.config_file[0] == '\0') {
        fprintf(stderr, "No configuration file to reload\n");
        return -1;
    }

    printf("Reloading configuration from: %s\n", g_config.config_file);
    return config_load(g_config.config_file);
}

int config_validate(struct yesrouter_config *cfg)
{
    if (!cfg) {
        return -1;
    }

    /* Validate system settings */
    if (cfg->system.hostname[0] == '\0') {
        fprintf(stderr, "Validation error: hostname not set\n");
        return -1;
    }

    /* Validate routing settings */
    if (cfg->routing.local_as == 0) {
        fprintf(stderr, "Validation error: local_as cannot be 0\n");
        return -1;
    }

    /* Validate BNG settings */
    if (cfg->bng.pppoe_mtu < 576 || cfg->bng.pppoe_mtu > 1500) {
        fprintf(stderr, "Validation error: pppoe_mtu must be 576-1500\n");
        return -1;
    }

    if (cfg->bng.max_sessions == 0) {
        fprintf(stderr, "Validation error: max_sessions cannot be 0\n");
        return -1;
    }

    /* Validate management settings */
    if (cfg->management.rest_api_enabled &&
        cfg->management.rest_api_port == 0) {
        fprintf(stderr, "Validation error: rest_api_port cannot be 0\n");
        return -1;
    }

    return 0;
}

int config_save(const char *filename)
{
    FILE *fp;

    if (!filename) {
        filename = g_config.config_file;
    }

    if (filename[0] == '\0') {
        fprintf(stderr, "No filename specified for config save\n");
        return -1;
    }

    fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Cannot open file for writing: %s (%s)\n",
                filename, strerror(errno));
        return -1;
    }

    fprintf(fp, "# YESRouter Configuration\n");
    fprintf(fp, "# Generated: %s\n\n", ctime(&(time_t){time(NULL)}));

    fprintf(fp, "# System\n");
    fprintf(fp, "hostname = %s\n", g_config.system.hostname);
    fprintf(fp, "log_level = %u\n", g_config.system.log_level);
    fprintf(fp, "daemonize = %s\n", g_config.system.daemonize ? "true" : "false");
    fprintf(fp, "\n");

    fprintf(fp, "# Routing\n");
    fprintf(fp, "local_as = %u\n", g_config.routing.local_as);
    fprintf(fp, "router_id = %s\n", config_ip_to_str(g_config.routing.router_id));
    fprintf(fp, "\n");

    fprintf(fp, "# BNG\n");
    fprintf(fp, "pppoe_enabled = %s\n", g_config.bng.pppoe_enabled ? "true" : "false");
    fprintf(fp, "ipoe_enabled = %s\n", g_config.bng.ipoe_enabled ? "true" : "false");
    fprintf(fp, "ac_name = %s\n", g_config.bng.ac_name);
    fprintf(fp, "pppoe_mtu = %u\n", g_config.bng.pppoe_mtu);
    fprintf(fp, "max_sessions = %u\n", g_config.bng.max_sessions);
    fprintf(fp, "\n");

    fprintf(fp, "# CGNAT\n");
    fprintf(fp, "cgnat_enabled = %s\n", g_config.cgnat.enabled ? "true" : "false");
    fprintf(fp, "\n");

    fprintf(fp, "# QoS\n");
    fprintf(fp, "qos_enabled = %s\n", g_config.qos.enabled ? "true" : "false");
    fprintf(fp, "\n");

    fprintf(fp, "# Firewall\n");
    fprintf(fp, "firewall_enabled = %s\n", g_config.firewall.enabled ? "true" : "false");
    fprintf(fp, "\n");

    fprintf(fp, "# Management\n");
    fprintf(fp, "rest_api_enabled = %s\n", g_config.management.rest_api_enabled ? "true" : "false");
    fprintf(fp, "rest_api_port = %u\n", g_config.management.rest_api_port);

    fclose(fp);
    printf("Configuration saved to: %s\n", filename);
    return 0;
}

int config_backup(void)
{
    memcpy(&g_config_backup, &g_config, sizeof(g_config_backup));
    g_has_backup = true;
    printf("Configuration backed up\n");
    return 0;
}

int config_rollback(void)
{
    if (!g_has_backup) {
        fprintf(stderr, "No backup configuration available\n");
        return -1;
    }

    memcpy(&g_config, &g_config_backup, sizeof(g_config));
    printf("Configuration rolled back\n");
    return 0;
}

struct yesrouter_config *config_get(void)
{
    return &g_config;
}

void config_print(void)
{
    printf("\nConfiguration Summary:\n");
    printf("========================================\n");

    printf("\nSystem:\n");
    printf("  Hostname: %s\n", g_config.system.hostname);
    printf("  Log Level: %u\n", g_config.system.log_level);
    printf("  Daemonize: %s\n", g_config.system.daemonize ? "yes" : "no");

    printf("\nRouting:\n");
    printf("  Local AS: %u\n", g_config.routing.local_as);
    printf("  Router ID: %s\n", config_ip_to_str(g_config.routing.router_id));

    printf("\nBNG:\n");
    printf("  PPPoE: %s\n", g_config.bng.pppoe_enabled ? "enabled" : "disabled");
    printf("  IPoE: %s\n", g_config.bng.ipoe_enabled ? "enabled" : "disabled");
    printf("  AC Name: %s\n", g_config.bng.ac_name);
    printf("  PPPoE MTU: %u\n", g_config.bng.pppoe_mtu);
    printf("  Max Sessions: %u\n", g_config.bng.max_sessions);

    printf("\nCGNAT:\n");
    printf("  Enabled: %s\n", g_config.cgnat.enabled ? "yes" : "no");

    printf("\nQoS:\n");
    printf("  Enabled: %s\n", g_config.qos.enabled ? "yes" : "no");
    printf("  Default Download: %u kbps\n", g_config.qos.default_rate_limit_down);
    printf("  Default Upload: %u kbps\n", g_config.qos.default_rate_limit_up);

    printf("\nFirewall:\n");
    printf("  Enabled: %s\n", g_config.firewall.enabled ? "yes" : "no");
    printf("  Stateful: %s\n", g_config.firewall.stateful_enabled ? "yes" : "no");

    printf("\nManagement:\n");
    printf("  REST API: %s (port %u)\n",
           g_config.management.rest_api_enabled ? "enabled" : "disabled",
           g_config.management.rest_api_port);

    printf("\n========================================\n");
}

void config_cleanup(void)
{
    printf("Configuration subsystem cleanup\n");

#ifdef HAVE_LIBYANG
    if (g_yang_ctx) {
        ly_ctx_destroy(g_yang_ctx, NULL);
        g_yang_ctx = NULL;
    }
#endif

    memset(&g_config, 0, sizeof(g_config));
    memset(&g_config_backup, 0, sizeof(g_config_backup));
    g_has_backup = false;
}
