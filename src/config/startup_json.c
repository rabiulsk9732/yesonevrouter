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

/* JSON array extractor - extracts first string from ["value"] format */
static char *json_get_array_first(const char *json, const char *key, char *out, int max) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *p = strstr(json, search);
    if (!p) return NULL;
    p = strchr(p, '[');  /* Find array start */
    if (!p) return NULL;
    p++;  /* Skip [ */
    while (*p && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;  /* Skip whitespace */
    if (*p != '"') return NULL;  /* Must start with quote */
    p++;  /* Skip opening quote */
    int i = 0;
    while (*p && *p != '"' && i < max - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (i > 0) ? out : NULL;
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

    /* Parse interface configurations dynamically using brace-depth tracking */
    char *iface_section = strstr(json, "\"interfaces\"");
    if (iface_section) {
        /* Find the opening brace of interfaces object */
        char *obj_start = strchr(iface_section, '{');
        if (obj_start) {
            int brace_depth = 1;  /* We're inside interfaces { */
            char *pos = obj_start + 1;

            while (*pos && brace_depth > 0) {
                /* Track braces */
                if (*pos == '{') {
                    brace_depth++;
                    pos++;
                    continue;
                }
                if (*pos == '}') {
                    brace_depth--;
                    pos++;
                    continue;
                }

                /* Look for quoted strings at depth 1 (interface names are direct children) */
                if (*pos == '"' && brace_depth == 1) {
                    /* Extract name */
                    const char *name_start = pos + 1;
                    const char *name_end = strchr(name_start, '"');
                    if (name_end && (name_end - name_start) < 32) {
                        char iface_name[32] = {0};
                        strncpy(iface_name, name_start, name_end - name_start);
                        iface_name[name_end - name_start] = '\0';

                        /* Check if followed by colon (it's a key, not a value) */
                        const char *after = name_end + 1;
                        while (*after == ' ' || *after == '\n' || *after == '\t' || *after == '\r') after++;

                        if (*after == ':') {
                            /* Validate interface name pattern */
                            int is_valid_iface = 0;
                            if (strncmp(iface_name, "eth", 3) == 0 && (iface_name[3] >= '0' && iface_name[3] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "gi", 2) == 0 && (iface_name[2] >= '0' && iface_name[2] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "10g", 3) == 0 && (iface_name[3] >= '0' && iface_name[3] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "25g", 3) == 0 && (iface_name[3] >= '0' && iface_name[3] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "40g", 3) == 0 && (iface_name[3] >= '0' && iface_name[3] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "100g", 4) == 0 && (iface_name[4] >= '0' && iface_name[4] <= '9')) {
                                is_valid_iface = 1;
                            } else if (strncmp(iface_name, "Gi", 2) == 0) {
                                is_valid_iface = 1;
                            }

                            if (is_valid_iface) {
                                YLOG_INFO("[STARTUP] Processing interface: %s", iface_name);

                                /* Check if this is a VLAN sub-interface (contains dot) */
                                char *dot = strchr(iface_name, '.');
                                if (dot) {
                                    /* Parse parent.vlan format: e.g., eth1.100 */
                                    char parent_name[32] = {0};
                                    uint16_t vlan_id = 0;

                                    strncpy(parent_name, iface_name, dot - iface_name);
                                    parent_name[dot - iface_name] = '\0';
                                    vlan_id = atoi(dot + 1);

                                    YLOG_INFO("[STARTUP] Detected VLAN interface %s (parent=%s, vlan=%u)",
                                             iface_name, parent_name, vlan_id);

                                    if (vlan_id > 0 && vlan_id <= 4094) {
                                        struct interface *existing = interface_find_by_name(iface_name);
                                        if (!existing) {
                                            extern struct interface *interface_create_vlan(const char *parent_name, uint16_t vlan_id);
                                            struct interface *vlan_iface = interface_create_vlan(parent_name, vlan_id);
                                            if (vlan_iface) {
                                                extern int interface_up(struct interface *iface);
                                                interface_up(vlan_iface);
                                                YLOG_INFO("[STARTUP] Created VLAN sub-interface %s", iface_name);
                                            } else {
                                                YLOG_WARNING("[STARTUP] Failed to create VLAN interface %s", iface_name);
                                            }
                                        }
                                    }
                                }

                                /* Configure the interface */
                                struct interface *iface = interface_find_by_name(iface_name);
                                if (iface) {
                                    /* Find ipv4_address for this interface */
                                    char ipv4[32] = {0};
                                    json_get_string(pos, "ipv4_address", ipv4, sizeof(ipv4));
                                    if (ipv4[0]) {
                                        char mask_str[32] = {0};
                                        json_get_string(pos, "ipv4_mask", mask_str, sizeof(mask_str));

                                        struct in_addr addr, mask;
                                        if (inet_pton(AF_INET, ipv4, &addr) == 1) {
                                            iface->config.ipv4_addr = addr;
                                            if (mask_str[0] && inet_pton(AF_INET, mask_str, &mask) == 1) {
                                                iface->config.ipv4_mask = mask;
                                            } else {
                                                iface->config.ipv4_mask.s_addr = htonl(0xFFFFFF00);
                                            }
                                            YLOG_INFO("[STARTUP] %s configured with IP %s", iface_name, ipv4);
                                        }
                                    }

                                    /* Parse NAT inside/outside flags */
                                    char *block_end = strchr(pos, '}');
                                    if (block_end) {
                                        char *nat_in = strstr(pos, "\"nat_inside\"");
                                        if (nat_in && nat_in < block_end) {
                                            char val_buf[24] = {0};
                                            strncpy(val_buf, nat_in + 12, 20);
                                            if (strstr(val_buf, "true")) {
                                                iface->config.nat_inside = true;
                                                YLOG_INFO("[STARTUP] %s: NAT inside (LAN)", iface_name);
                                            }
                                        }
                                        char *nat_out = strstr(pos, "\"nat_outside\"");
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
                        }
                        pos = (char *)name_end + 1;
                        continue;
                    }
                }
                pos++;
            }
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

                    YLOG_INFO("[STARTUP] Creating NAT pool: %s - %s", start_ip, end_ip);
                    int ret = nat_pool_create("CGNAT", ntohl(start.s_addr),
                                             ntohl(end.s_addr), 0xFFFFFF00);
                    if (ret == 0) {
                        YLOG_INFO("[STARTUP] NAT pool created: %s - %s (0x%08x - 0x%08x)",
                                 start_ip, end_ip, ntohl(start.s_addr), ntohl(end.s_addr));
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
            YLOG_INFO("[STARTUP] NAT44 enabled - num_pools=%d", g_nat_config.num_pools);
        } else {
            YLOG_WARNING("[STARTUP] NAT44 not enabled in config");
        }
        if (strstr(nat_section, "\"hairpin\": true") || strstr(nat_section, "\"hairpin\":true")) {
            g_nat_config.hairpinning_enabled = true;
            YLOG_INFO("[STARTUP] NAT44 hairpin enabled");
        }
    }

    /* ========== PPPoE IP Pools Section ========== */
    char *pools_section = strstr(json, "\"ip_pools\"");
    if (pools_section) {
        /* Find pool objects - look for "name" fields */
        char *pool_pos = pools_section;
        while ((pool_pos = strstr(pool_pos, "\"name\":")) != NULL) {
            char pool_name[32] = {0};
            char start_ip[32] = {0};
            char end_ip[32] = {0};

            json_get_string(pool_pos, "name", pool_name, sizeof(pool_name));
            json_get_string(pool_pos, "start", start_ip, sizeof(start_ip));
            json_get_string(pool_pos, "end", end_ip, sizeof(end_ip));

            if (pool_name[0] && start_ip[0] && end_ip[0]) {
                struct in_addr start_addr, end_addr;
                if (inet_pton(AF_INET, start_ip, &start_addr) == 1 &&
                    inet_pton(AF_INET, end_ip, &end_addr) == 1) {
                    extern int ippool_create(const char *name, uint32_t start_ip, uint32_t end_ip);
                    int ret = ippool_create(pool_name, ntohl(start_addr.s_addr), ntohl(end_addr.s_addr));
                    if (ret == 0) {
                        YLOG_INFO("[STARTUP] IP Pool '%s' created: %s - %s", pool_name, start_ip, end_ip);
                    }
                }
            }
            pool_pos++;
        }
    }

    /* ========== Service Profiles Section ========== */
    char *profiles_section = strstr(json, "\"service_profiles\"");
    if (profiles_section) {
        extern int service_profile_create(const char *name);
        extern int service_profile_set_interface(const char *profile, const char *iface, uint16_t vlan_id);
        extern int service_profile_set_pool(const char *profile, const char *pool_name);
        extern int service_profile_set_ac_name(const char *profile, const char *ac_name);
        extern int service_profile_add_service_name(const char *profile, const char *service_name);

        char *prof_pos = profiles_section;
        while ((prof_pos = strstr(prof_pos, "\"name\":")) != NULL) {
            char prof_name[32] = {0};
            char iface[32] = {0};
            char vlan_str[16] = {0};
            char pool_name[32] = {0};
            char ac_name[64] = {0};
            char svc_names[128] = {0};

            json_get_string(prof_pos, "name", prof_name, sizeof(prof_name));
            json_get_string(prof_pos, "interface", iface, sizeof(iface));
            json_get_string(prof_pos, "vlan_id", vlan_str, sizeof(vlan_str));
            json_get_string(prof_pos, "pool_name", pool_name, sizeof(pool_name));
            json_get_string(prof_pos, "ac_name", ac_name, sizeof(ac_name));
            json_get_array_first(prof_pos, "service_names", svc_names, sizeof(svc_names));

            if (prof_name[0]) {
                service_profile_create(prof_name);

                if (iface[0]) {
                    /* Parse VLAN from interface name (e.g., eth1.100 -> parent=eth1, vlan=100) */
                    char parent_iface[32] = {0};
                    uint16_t vlan_id = 0;
                    char *dot = strchr(iface, '.');
                    if (dot) {
                        /* Interface has VLAN suffix: eth1.100 */
                        strncpy(parent_iface, iface, dot - iface);
                        parent_iface[dot - iface] = '\0';
                        vlan_id = atoi(dot + 1);
                    } else {
                        /* No VLAN suffix, use explicit vlan_id field if present */
                        strncpy(parent_iface, iface, sizeof(parent_iface) - 1);
                        vlan_id = vlan_str[0] ? atoi(vlan_str) : 0;
                    }

                    /* Create VLAN sub-interface if vlan_id specified */
                    if (vlan_id > 0) {
                        extern struct interface *interface_create_vlan(const char *parent_name, uint16_t vlan_id);
                        struct interface *vlan_iface = interface_create_vlan(parent_iface, vlan_id);
                        if (vlan_iface) {
                            extern int interface_up(struct interface *iface);
                            interface_up(vlan_iface);
                            YLOG_INFO("[STARTUP] Created VLAN interface %s.%u", parent_iface, vlan_id);
                        }
                    }

                    service_profile_set_interface(prof_name, parent_iface, vlan_id);
                }

                if (pool_name[0]) {
                    service_profile_set_pool(prof_name, pool_name);
                }

                if (ac_name[0]) {
                    service_profile_set_ac_name(prof_name, ac_name);
                    /* Also set global PPPoE AC-Name for PADO transmission */
                    extern void pppoe_set_ac_name(const char *name);
                    pppoe_set_ac_name(ac_name);
                    YLOG_INFO("[STARTUP] PPPoE AC-Name set to '%s'", ac_name);
                }

                /* Parse service_names array (comma-separated in simple format) */
                if (svc_names[0]) {
                    char svc_copy[128];
                    strncpy(svc_copy, svc_names, sizeof(svc_copy) - 1);
                    svc_copy[sizeof(svc_copy) - 1] = '\0';

                    char *svc = strtok(svc_copy, ",\"[] ");
                    int first_svc = 1;
                    while (svc) {
                        if (svc[0]) {
                            service_profile_add_service_name(prof_name, svc);
                            /* Set first service name as global for PADO */
                            if (first_svc) {
                                extern void pppoe_set_service_name(const char *name);
                                pppoe_set_service_name(svc);
                                YLOG_INFO("[STARTUP] PPPoE Service-Name set to '%s'", svc);
                                first_svc = 0;
                            }
                        }
                        svc = strtok(NULL, ",\"[] ");
                    }
                }

                /* Register profile with PPPoE for session pool lookup */
                if (iface[0] && pool_name[0]) {
                    /* Re-parse VLAN from interface name for pppoe_add_profile */
                    char pppoe_parent[32] = {0};
                    uint16_t pppoe_vlan = 0;
                    char *pdot = strchr(iface, '.');
                    if (pdot) {
                        strncpy(pppoe_parent, iface, pdot - iface);
                        pppoe_parent[pdot - iface] = '\0';
                        pppoe_vlan = atoi(pdot + 1);
                    } else {
                        strncpy(pppoe_parent, iface, sizeof(pppoe_parent) - 1);
                        pppoe_vlan = vlan_str[0] ? atoi(vlan_str) : 0;
                    }
                    extern void pppoe_add_profile(const char *iface_name, uint16_t vlan_id, const char *pool_name);
                    pppoe_add_profile(pppoe_parent, pppoe_vlan, pool_name);
                    YLOG_INFO("[STARTUP] PPPoE Profile: %s vlan %u -> pool %s", pppoe_parent, pppoe_vlan, pool_name);
                }

                YLOG_INFO("[STARTUP] Service Profile '%s' -> iface=%s pool=%s",
                          prof_name, iface[0] ? iface : "*", pool_name);
            }
            prof_pos++;
        }
    }

    /* ========== RADIUS Section ========== */
    char *radius_section = strstr(json, "\"radius\"");
    if (radius_section) {
        extern int radius_client_add_server(uint32_t ip, uint16_t auth_port, uint16_t acct_port,
                                            const char *secret, int priority);
        extern void radius_client_set_timeout(uint32_t timeout_sec);
        extern void radius_client_set_retries(uint8_t retries);

        /* Parse servers array */
        char *server_pos = strstr(radius_section, "\"servers\"");
        if (server_pos) {
            char *srv = server_pos;
            while ((srv = strstr(srv, "\"host\":")) != NULL) {
                char host[32] = {0};
                char secret[64] = {0};
                char auth_port_str[8] = {0};
                char acct_port_str[8] = {0};
                char priority_str[8] = {0};

                json_get_string(srv, "host", host, sizeof(host));
                json_get_string(srv, "secret", secret, sizeof(secret));
                json_get_string(srv, "auth_port", auth_port_str, sizeof(auth_port_str));
                json_get_string(srv, "acct_port", acct_port_str, sizeof(acct_port_str));
                json_get_string(srv, "priority", priority_str, sizeof(priority_str));

                if (host[0] && secret[0]) {
                    struct in_addr addr;
                    if (inet_pton(AF_INET, host, &addr) == 1) {
                        uint16_t auth_port = auth_port_str[0] ? atoi(auth_port_str) : 1812;
                        uint16_t acct_port = acct_port_str[0] ? atoi(acct_port_str) : 1813;
                        int priority = priority_str[0] ? atoi(priority_str) : 1;

                        int ret = radius_client_add_server(ntohl(addr.s_addr), auth_port, acct_port, secret, priority);
                        if (ret >= 0) {
                            YLOG_INFO("[STARTUP] RADIUS server added: %s:%d/%d", host, auth_port, acct_port);
                        }
                    }
                }
                srv++;
            }
        }

        /* Parse timeout */
        char timeout_str[8] = {0};
        json_get_string(radius_section, "timeout", timeout_str, sizeof(timeout_str));
        if (timeout_str[0]) {
            radius_client_set_timeout(atoi(timeout_str));
            YLOG_INFO("[STARTUP] RADIUS timeout: %s sec", timeout_str);
        }

        /* Parse retries */
        char retries_str[8] = {0};
        json_get_string(radius_section, "retries", retries_str, sizeof(retries_str));
        if (retries_str[0]) {
            radius_client_set_retries(atoi(retries_str));
            YLOG_INFO("[STARTUP] RADIUS retries: %s", retries_str);
        }
    }

    /* ========== Routing Section ========== */
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
                        /* Try multiple possible WAN interface names */
                        struct interface *wan_iface = interface_find_by_name("eth0");
                        if (!wan_iface) wan_iface = interface_find_by_name("Gi0/1");
                        if (!wan_iface) wan_iface = interface_find_by_name("Gi0/0");
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
