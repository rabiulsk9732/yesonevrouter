/**
 * @file startup_json.c
 * @brief Startup JSON Loader (Cisco-style runtime config)
 *
 * Loads NAT pools, interfaces, routing from startup.json
 */

#include "nat.h"
#include "interface.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Simple JSON value extractor */
static char *json_get_string(const char *json, const char *key, char *out, int max) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return NULL;
    p = strchr(p, ':');
    if (!p) return NULL;
    p++;
    while (*p && (*p == ' ' || *p == '"')) p++;
    int i = 0;
    while (*p && *p != '"' && *p != ',' && *p != '}' && i < max - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return out;
}

int startup_json_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        YLOG_WARNING("Cannot open startup.json: %s", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json = malloc(size + 1);
    if (!json) {
        fclose(f);
        return -1;
    }
    fread(json, 1, size, f);
    json[size] = '\0';
    fclose(f);

    YLOG_INFO("[STARTUP] Loading runtime config from %s", path);

    /* Parse interface configurations dynamically */
    char *iface_section = strstr(json, "\"interfaces\"");
    if (iface_section) {
        /* Iterate through all interfaces */
        char *search_pos = iface_section;
        while ((search_pos = strstr(search_pos, "\"Gi")) != NULL) {
            /* Extract interface name */
            char iface_name[32] = {0};
            const char *name_start = search_pos + 1;
            const char *name_end = strchr(name_start, '"');
            if (name_end && (name_end - name_start) < (int)sizeof(iface_name)) {
                strncpy(iface_name, name_start, name_end - name_start);
                iface_name[name_end - name_start] = '\0';

                /* Find ipv4 for this interface */
                char ipv4[32] = {0};
                json_get_string(search_pos, "ipv4", ipv4, sizeof(ipv4));
                if (ipv4[0]) {
                    struct interface *iface = interface_find_by_name(iface_name);
                    if (iface) {
                        char *slash = strchr(ipv4, '/');
                        int prefix = 24;
                        if (slash) {
                            *slash = '\0';
                            prefix = atoi(slash + 1);
                        }
                        struct in_addr addr;
                        if (inet_pton(AF_INET, ipv4, &addr) == 1) {
                            iface->config.ipv4_addr = addr;
                            iface->config.ipv4_mask.s_addr = htonl(0xFFFFFFFF << (32 - prefix));
                            YLOG_INFO("[STARTUP] %s configured with IP %s/%d", iface_name, ipv4, prefix);
                        }
                    }
                }
            }
            search_pos++;
        }
    }

    /* Find NAT44 section and create pool */
    char *nat_section = strstr(json, "\"nat44\"");
    if (nat_section) {
        char *pools = strstr(nat_section, "\"pools\"");
        if (pools) {
            char start_ip[32] = {0}, end_ip[32] = {0};
            json_get_string(pools, "start_ip", start_ip, sizeof(start_ip));
            json_get_string(pools, "end_ip", end_ip, sizeof(end_ip));

            if (start_ip[0] && end_ip[0]) {
                struct in_addr start, end;
                if (inet_pton(AF_INET, start_ip, &start) == 1 &&
                    inet_pton(AF_INET, end_ip, &end) == 1) {

                    /* Create NAT pool */
                    int ret = nat_pool_create("CGNAT", ntohl(start.s_addr),
                                             ntohl(end.s_addr), 0xFFFFFF00);
                    if (ret == 0) {
                        YLOG_INFO("[STARTUP] NAT pool created: %s - %s", start_ip, end_ip);
                    } else {
                        YLOG_ERROR("[STARTUP] Failed to create NAT pool");
                    }
                }
            }
        }

        /* Enable NAT if configured */
        extern void nat_enable(bool enable);
        extern struct nat_config g_nat_config;

        if (strstr(nat_section, "\"enabled\": true") || strstr(nat_section, "\"enabled\":true")) {
            nat_enable(true);
            YLOG_INFO("[STARTUP] NAT44 enabled");
        }
        if (strstr(nat_section, "\"hairpin\": true") || strstr(nat_section, "\"hairpin\":true")) {
            g_nat_config.hairpinning_enabled = true;
            YLOG_INFO("[STARTUP] NAT44 hairpin enabled");
        }
    }

    free(json);
    return 0;
}
