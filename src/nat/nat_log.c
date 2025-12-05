/**
 * @file nat_log.c
 * @brief NAT Event Logging Implementation
 *
 * Implements basic logging of NAT events.
 * Currently supports logging to syslog/console.
 * Future: IPFIX/Netflow v9 export.
 */

#include "nat_log.h"
#include "log.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

static struct {
    uint32_t collector_ip;
    uint16_t collector_port;
    bool enabled;
} g_nat_log_config;

int nat_log_init(uint32_t collector_ip, uint16_t collector_port)
{
    g_nat_log_config.collector_ip = collector_ip;
    g_nat_log_config.collector_port = collector_port;
    g_nat_log_config.enabled = true;

    YLOG_INFO("NAT logging initialized (Collector: %u.%u.%u.%u:%u)",
              (collector_ip >> 24) & 0xFF, (collector_ip >> 16) & 0xFF,
              (collector_ip >> 8) & 0xFF, collector_ip & 0xFF,
              collector_port);
    return 0;
}

void nat_log_event(enum nat_event_type event_type,
                   uint32_t inside_ip, uint16_t inside_port,
                   uint32_t outside_ip, uint16_t outside_port,
                   uint8_t protocol, uint64_t timestamp)
{
    if (!g_nat_log_config.enabled) return;

    char inside_str[32], outside_str[32];
    struct in_addr addr;
    const char *event_str;

    switch (event_type) {
        case NAT_EVENT_CREATE: event_str = "CREATE"; break;
        case NAT_EVENT_DELETE: event_str = "DELETE"; break;
        case NAT_EVENT_QUOTA_EXCEEDED: event_str = "QUOTA_EXCEEDED"; break;
        default: event_str = "UNKNOWN"; break;
    }

    addr.s_addr = htonl(inside_ip);
    inet_ntop(AF_INET, &addr, inside_str, sizeof(inside_str));

    addr.s_addr = htonl(outside_ip);
    inet_ntop(AF_INET, &addr, outside_str, sizeof(outside_str));

    /* For now, log to stdout since main logging is disabled */
    printf("NAT_EVENT: %s | Proto: %u | %s:%u -> %s:%u | TS: %lu\n",
              event_str, protocol,
              inside_str, inside_port,
              outside_str, outside_port,
              timestamp);
}

void nat_log_cleanup(void)
{
    g_nat_log_config.enabled = false;
    YLOG_INFO("NAT logging cleanup");
}
