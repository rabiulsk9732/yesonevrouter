/**
 * @file session_export.c
 * @brief Session Export and Lookup Tools
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "session_export.h"
#include "log.h"

/* Session export callback */
static session_iterator_fn g_iterator = NULL;
static void *g_iterator_ctx = NULL;

void session_export_set_iterator(session_iterator_fn fn, void *ctx)
{
    g_iterator = fn;
    g_iterator_ctx = ctx;
}

int session_export_json(char *buf, size_t buf_size)
{
    if (!g_iterator) {
        return snprintf(buf, buf_size, "{\"sessions\":[], \"error\":\"No iterator set\"}");
    }

    int n = snprintf(buf, buf_size, "{\"sessions\":[");
    int first = 1;

    /* Call iterator */
    struct session_info info;
    int idx = 0;
    while (g_iterator(g_iterator_ctx, idx++, &info) == 0) {
        if (!first) {
            n += snprintf(buf + n, buf_size - n, ",");
        }
        first = 0;

        n += snprintf(buf + n, buf_size - n,
            "{"
            "\"session_id\":%u,"
            "\"client_ip\":\"%u.%u.%u.%u\","
            "\"client_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
            "\"state\":\"%s\","
            "\"uptime\":%lu,"
            "\"bytes_in\":%lu,"
            "\"bytes_out\":%lu,"
            "\"packets_in\":%lu,"
            "\"packets_out\":%lu"
            "}",
            info.session_id,
            (info.client_ip >> 24) & 0xFF, (info.client_ip >> 16) & 0xFF,
            (info.client_ip >> 8) & 0xFF, info.client_ip & 0xFF,
            info.client_mac[0], info.client_mac[1], info.client_mac[2],
            info.client_mac[3], info.client_mac[4], info.client_mac[5],
            info.state_str,
            info.uptime_sec,
            info.bytes_in, info.bytes_out,
            info.packets_in, info.packets_out);

        if ((size_t)n >= buf_size - 100) break; /* Leave room for closing */
    }

    n += snprintf(buf + n, buf_size - n, "],\"count\":%d}", idx - 1);
    return n;
}

int session_export_csv(char *buf, size_t buf_size)
{
    if (!g_iterator) {
        return snprintf(buf, buf_size, "error,No iterator set\n");
    }

    int n = snprintf(buf, buf_size,
        "session_id,client_ip,client_mac,state,uptime,bytes_in,bytes_out,packets_in,packets_out\n");

    struct session_info info;
    int idx = 0;
    while (g_iterator(g_iterator_ctx, idx++, &info) == 0) {
        n += snprintf(buf + n, buf_size - n,
            "%u,%u.%u.%u.%u,%02x:%02x:%02x:%02x:%02x:%02x,%s,%lu,%lu,%lu,%lu,%lu\n",
            info.session_id,
            (info.client_ip >> 24) & 0xFF, (info.client_ip >> 16) & 0xFF,
            (info.client_ip >> 8) & 0xFF, info.client_ip & 0xFF,
            info.client_mac[0], info.client_mac[1], info.client_mac[2],
            info.client_mac[3], info.client_mac[4], info.client_mac[5],
            info.state_str,
            info.uptime_sec,
            info.bytes_in, info.bytes_out,
            info.packets_in, info.packets_out);

        if ((size_t)n >= buf_size - 200) break;
    }

    return n;
}

int session_lookup_by_ip(uint32_t ip, struct session_info *info)
{
    if (!g_iterator || !info) return -1;

    struct session_info tmp;
    int idx = 0;
    while (g_iterator(g_iterator_ctx, idx++, &tmp) == 0) {
        if (tmp.client_ip == ip) {
            memcpy(info, &tmp, sizeof(*info));
            return 0;
        }
    }
    return -1;
}

int session_lookup_by_mac(const uint8_t *mac, struct session_info *info)
{
    if (!g_iterator || !info || !mac) return -1;

    struct session_info tmp;
    int idx = 0;
    while (g_iterator(g_iterator_ctx, idx++, &tmp) == 0) {
        if (memcmp(tmp.client_mac, mac, 6) == 0) {
            memcpy(info, &tmp, sizeof(*info));
            return 0;
        }
    }
    return -1;
}

int session_lookup_by_id(uint16_t session_id, struct session_info *info)
{
    if (!g_iterator || !info) return -1;

    struct session_info tmp;
    int idx = 0;
    while (g_iterator(g_iterator_ctx, idx++, &tmp) == 0) {
        if (tmp.session_id == session_id) {
            memcpy(info, &tmp, sizeof(*info));
            return 0;
        }
    }
    return -1;
}

void session_print_info(const struct session_info *info)
{
    printf("Session ID: %u\n", info->session_id);
    printf("Client IP:  %u.%u.%u.%u\n",
           (info->client_ip >> 24) & 0xFF, (info->client_ip >> 16) & 0xFF,
           (info->client_ip >> 8) & 0xFF, info->client_ip & 0xFF);
    printf("Client MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           info->client_mac[0], info->client_mac[1], info->client_mac[2],
           info->client_mac[3], info->client_mac[4], info->client_mac[5]);
    printf("State:      %s\n", info->state_str);
    printf("Uptime:     %lu seconds\n", info->uptime_sec);
    printf("Bytes In:   %lu\n", info->bytes_in);
    printf("Bytes Out:  %lu\n", info->bytes_out);
    printf("Packets In: %lu\n", info->packets_in);
    printf("Packets Out:%lu\n", info->packets_out);
}
