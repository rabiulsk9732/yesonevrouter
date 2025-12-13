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

/* Global default gateway - used by NAT for next-hop routing */
uint32_t g_default_gateway = 0;

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

                struct interface *iface = interface_find_by_name(iface_name);
                if (iface) {
                    /* Find ipv4_address for this interface */
                    char ipv4[32] = {0};
                    json_get_string(search_pos, "ipv4_address", ipv4, sizeof(ipv4));
                    if (ipv4[0]) {
                        char mask_str[32] = {0};
                        json_get_string(search_pos, "ipv4_mask", mask_str, sizeof(mask_str));

                        struct in_addr addr, mask;
                        if (inet_pton(AF_INET, ipv4, &addr) == 1) {
                            iface->config.ipv4_addr = addr;
                            if (mask_str[0] && inet_pton(AF_INET, mask_str, &mask) == 1) {
                                iface->config.ipv4_mask = mask;
                            } else {
                                iface->config.ipv4_mask.s_addr = htonl(0xFFFFFF00); /* /24 default */
                            }
                            YLOG_INFO("[STARTUP] %s configured with IP %s", iface_name, ipv4);
                        }
                    }

                    /* Parse NAT inside/outside flags - DYNAMIC NAT direction */
                    /* Find the end of this interface's JSON block (next '}') */
                    char *block_end = strchr(search_pos, '}');
                    if (block_end) {
                        /* Check for nat_inside: true - look for "true" within 20 chars of key */
                        char *nat_in = strstr(search_pos, "\"nat_inside\"");
                        if (nat_in && nat_in < block_end) {
                            /* Check only the next 20 chars for "true" (avoids finding next field) */
                            char val_buf[24] = {0};
                            strncpy(val_buf, nat_in + 12, 20);
                            if (strstr(val_buf, "true")) {
                                iface->config.nat_inside = true;
                                YLOG_INFO("[STARTUP] %s: NAT inside (LAN)", iface_name);
                            }
                        }
                        /* Check for nat_outside: true */
                        char *nat_out = strstr(search_pos, "\"nat_outside\"");
                        if (nat_out && nat_out < block_end) {
                            char val_buf[24] = {0};
                            strncpy(val_buf, nat_out + 13, 20);
                            if (strstr(val_buf, "true")) {
                                iface->config.nat_outside = true;
                                YLOG_INFO("[STARTUP] %s: NAT outside (WAN)", iface_name);
                            }
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

    /* Parse routing section for default gateway */
    char *routing_section = strstr(json, "\"routing\"");
    if (routing_section) {
        char *static_routes = strstr(routing_section, "\"static_routes\"");
        if (static_routes) {
            /* Look for default route (0.0.0.0/0) */
            char *default_route = strstr(static_routes, "\"0.0.0.0/0\"");
            if (default_route) {
                char next_hop[32] = {0};
                json_get_string(default_route, "next_hop", next_hop, sizeof(next_hop));
                if (next_hop[0]) {
                    struct in_addr gw;
                    if (inet_pton(AF_INET, next_hop, &gw) == 1) {
                        g_default_gateway = ntohl(gw.s_addr);
                        YLOG_INFO("[STARTUP] Default gateway: %s (0x%08x)", next_hop, g_default_gateway);

                        /* Send ARP request to gateway to populate ARP table early */
                        struct interface *wan_iface = interface_find_by_name("Gi0/1");
                        if (wan_iface && wan_iface->config.ipv4_addr.s_addr != 0) {
                            extern int arp_send_request(uint32_t target_ip, uint32_t source_ip,
                                                       const uint8_t *source_mac, uint32_t ifindex);
                            uint32_t wan_ip = ntohl(wan_iface->config.ipv4_addr.s_addr);
                            arp_send_request(g_default_gateway, wan_ip, wan_iface->mac_addr, wan_iface->ifindex);
                            YLOG_INFO("[STARTUP] Sent ARP request to gateway %s", next_hop);
                        }
                    }
                }
            }
        }
    }

    free(json);
    return 0;
}
