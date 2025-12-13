/**
 * @file nat_log.c
 * @brief NAT Event Logging - Unified Dispatcher
 *
 * Dispatches NAT events to configured logging targets:
 * - Syslog (console/system log)
 * - IPFIX (RFC 7011/8158)
 * - NetFlow v9 (Cisco)
 */

#include "nat_log.h"
#include "log.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Global logging configuration */
static struct {
    struct nat_log_config config;
    struct nat_log_stats stats;
    bool initialized;
    pthread_mutex_t lock;
} g_nat_log = {.initialized = false, .lock = PTHREAD_MUTEX_INITIALIZER};

int nat_log_subsystem_init(void)
{
    pthread_mutex_lock(&g_nat_log.lock);

    if (g_nat_log.initialized) {
        pthread_mutex_unlock(&g_nat_log.lock);
        return 0;
    }

    /* Default configuration */
    memset(&g_nat_log.config, 0, sizeof(g_nat_log.config));
    g_nat_log.config.events = NAT_LOG_EVENTS_ALL;
    g_nat_log.config.template_refresh_interval = 600;

    memset(&g_nat_log.stats, 0, sizeof(g_nat_log.stats));

    g_nat_log.initialized = true;

    pthread_mutex_unlock(&g_nat_log.lock);

    YLOG_INFO("NAT logging subsystem initialized");
    return 0;
}

int nat_log_configure_ipfix(uint32_t collector_ip, uint16_t collector_port,
                            uint32_t observation_domain_id)
{
    pthread_mutex_lock(&g_nat_log.lock);

    g_nat_log.config.ipfix_collector_ip = collector_ip;
    g_nat_log.config.ipfix_collector_port = collector_port;
    g_nat_log.config.ipfix_observation_domain = observation_domain_id;

    /* Initialize the new IPFIX exporter */
    extern int natexport_init_ipfix(uint32_t ip, uint16_t port, uint32_t domain_id);
    natexport_init_ipfix(collector_ip, collector_port, observation_domain_id);

    g_nat_log.config.targets |= NAT_LOG_TARGET_IPFIX;

    pthread_mutex_unlock(&g_nat_log.lock);
    return 0;
}

int nat_log_configure_netflow(uint32_t collector_ip, uint16_t collector_port, uint32_t source_id)
{
    pthread_mutex_lock(&g_nat_log.lock);

    g_nat_log.config.netflow_collector_ip = collector_ip;
    g_nat_log.config.netflow_collector_port = collector_port;
    g_nat_log.config.netflow_source_id = source_id;

    /* Initialize the new NetFlow v9 exporter */
    extern int natexport_init_v9(uint32_t ip, uint16_t port, uint32_t source_id);
    natexport_init_v9(collector_ip, collector_port, source_id);

    g_nat_log.config.targets |= NAT_LOG_TARGET_NETFLOW;

    pthread_mutex_unlock(&g_nat_log.lock);
    return 0;
}

void nat_log_set_target(uint32_t target, bool enable)
{
    pthread_mutex_lock(&g_nat_log.lock);

    if (enable) {
        g_nat_log.config.targets |= target;
    } else {
        g_nat_log.config.targets &= ~target;
        /* Cleanup disabled exporters - No-op for new exporter (runs continuously) */
    }

    pthread_mutex_unlock(&g_nat_log.lock);
}

void nat_log_set_events(uint32_t events, bool enable)
{
    pthread_mutex_lock(&g_nat_log.lock);

    if (enable) {
        g_nat_log.config.events |= events;
    } else {
        g_nat_log.config.events &= ~events;
    }

    pthread_mutex_unlock(&g_nat_log.lock);
}

/* Legacy API */
int nat_log_init(uint32_t collector_ip, uint16_t collector_port)
{
    nat_log_subsystem_init();

    /* Enable syslog by default for legacy API */
    nat_log_set_target(NAT_LOG_TARGET_SYSLOG, true);

    /* If collector configured, enable IPFIX */
    if (collector_ip != 0) {
        return nat_log_configure_ipfix(collector_ip, collector_port, 1);
    }

    return 0;
}

/* Convert event type to filter bit */
static uint32_t event_to_filter(enum nat_event_type event)
{
    switch (event) {
    case NAT_EVENT_CREATE:
        return NAT_LOG_EVENTS_CREATE;
    case NAT_EVENT_DELETE:
        return NAT_LOG_EVENTS_DELETE;
    case NAT_EVENT_QUOTA_EXCEEDED:
        return NAT_LOG_EVENTS_QUOTA;
    default:
        return 0;
    }
}

/* Convert event type to string */
static const char *event_to_string(enum nat_event_type event)
{
    switch (event) {
    case NAT_EVENT_CREATE:
        return "CREATE";
    case NAT_EVENT_DELETE:
        return "DELETE";
    case NAT_EVENT_QUOTA_EXCEEDED:
        return "QUOTA_EXCEEDED";
    default:
        return "UNKNOWN";
    }
}

/* Log to syslog/console */
static void log_to_syslog(enum nat_event_type event_type, uint32_t inside_ip, uint16_t inside_port,
                          uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol)
{
    char inside_str[INET_ADDRSTRLEN];
    char outside_str[INET_ADDRSTRLEN];
    char dest_str[INET_ADDRSTRLEN];
    struct in_addr addr;

    addr.s_addr = htonl(inside_ip);
    inet_ntop(AF_INET, &addr, inside_str, sizeof(inside_str));

    addr.s_addr = htonl(outside_ip);
    inet_ntop(AF_INET, &addr, outside_str, sizeof(outside_str));

    addr.s_addr = htonl(dest_ip);
    inet_ntop(AF_INET, &addr, dest_str, sizeof(dest_str));

    /* Use printf for syslog target - YLOG_INFO is disabled in production */
    printf("NAT %s: %s:%u -> %s:%u (dst %s:%u proto %u)\n", event_to_string(event_type), inside_str,
           inside_port, outside_str, outside_port, dest_str, dest_port, protocol);
}

void nat_log_session_event(enum nat_event_type event_type, uint32_t inside_ip, uint16_t inside_port,
                           uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                           uint16_t dest_port, uint8_t protocol, uint32_t pool_id, uint32_t vrf_id)
{
    pthread_mutex_lock(&g_nat_log.lock);

    /* Check if event type is enabled */
    uint32_t filter = event_to_filter(event_type);
    if (!(g_nat_log.config.events & filter)) {
        g_nat_log.stats.events_filtered++;
        pthread_mutex_unlock(&g_nat_log.lock);
        return;
    }

    g_nat_log.stats.events_logged++;
    uint32_t targets = g_nat_log.config.targets;

    pthread_mutex_unlock(&g_nat_log.lock);

    /* Dispatch to enabled targets (outside lock for performance) */

    /* Syslog */
    if (targets & NAT_LOG_TARGET_SYSLOG) {
        log_to_syslog(event_type, inside_ip, inside_port, outside_ip, outside_port, dest_ip,
                      dest_port, protocol);
        __atomic_fetch_add(&g_nat_log.stats.syslog_events, 1, __ATOMIC_RELAXED);
    }

    /* IPFIX / NetFlow via new natexport module */
    if (targets & (NAT_LOG_TARGET_IPFIX | NAT_LOG_TARGET_NETFLOW)) {
        extern int natexport_log(uint8_t event_type, uint32_t src_ip, uint16_t src_port,
                                 uint32_t xlate_ip, uint16_t xlate_port,
                                 uint32_t dst_ip, uint16_t dst_port, uint8_t protocol,
                                 uint32_t pool_id, uint32_t vrf_id);
        natexport_log((uint8_t)event_type, inside_ip, inside_port, outside_ip,
                      outside_port, dest_ip, dest_port, protocol, pool_id, vrf_id);
        __atomic_fetch_add(&g_nat_log.stats.ipfix_events, 1, __ATOMIC_RELAXED);
    }
}


/* Legacy API - backward compatible */
void nat_log_event(enum nat_event_type event_type, uint32_t inside_ip, uint16_t inside_port,
                   uint32_t outside_ip, uint16_t outside_port, uint8_t protocol, uint64_t timestamp)
{
    (void)timestamp; /* Ignored - we use current time */

    nat_log_session_event(event_type, inside_ip, inside_port, outside_ip, outside_port, 0, 0,
                          protocol, 0, 0);
}

void nat_log_flush(void)
{
    /* Legacy flush - no op for now as new exporter runs continuously in thread */
}

void nat_log_get_stats(struct nat_log_stats *stats)
{
    if (!stats)
        return;

    pthread_mutex_lock(&g_nat_log.lock);
    memcpy(stats, &g_nat_log.stats, sizeof(*stats));
    pthread_mutex_unlock(&g_nat_log.lock);
}

void nat_log_print_config(void)
{
    pthread_mutex_lock(&g_nat_log.lock);

    printf("\nNAT Logging Configuration:\n");
    printf("  Status: %s\n", g_nat_log.initialized ? "Initialized" : "Not initialized");

    printf("\n  Targets:\n");
    printf("    Syslog:   %s\n",
           (g_nat_log.config.targets & NAT_LOG_TARGET_SYSLOG) ? "Enabled" : "Disabled");
    printf("    IPFIX:    %s",
           (g_nat_log.config.targets & NAT_LOG_TARGET_IPFIX) ? "Enabled" : "Disabled");
    if (g_nat_log.config.targets & NAT_LOG_TARGET_IPFIX) {
        /* New exporter init handled via global init or lazy load */
        printf(" (collector: %u.%u.%u.%u:%u, domain: %u)",
               (g_nat_log.config.ipfix_collector_ip >> 24) & 0xFF,
               (g_nat_log.config.ipfix_collector_ip >> 16) & 0xFF,
               (g_nat_log.config.ipfix_collector_ip >> 8) & 0xFF,
               g_nat_log.config.ipfix_collector_ip & 0xFF, g_nat_log.config.ipfix_collector_port,
               g_nat_log.config.ipfix_observation_domain);
    }
    printf("\n");

    printf("    NetFlow:  %s",
           (g_nat_log.config.targets & NAT_LOG_TARGET_NETFLOW) ? "Enabled" : "Disabled");
    if (g_nat_log.config.targets & NAT_LOG_TARGET_NETFLOW) {
        /* New exporter init handled via global init or lazy load */
        printf(" (collector: %u.%u.%u.%u:%u, source: %u)",
               (g_nat_log.config.netflow_collector_ip >> 24) & 0xFF,
               (g_nat_log.config.netflow_collector_ip >> 16) & 0xFF,
               (g_nat_log.config.netflow_collector_ip >> 8) & 0xFF,
               g_nat_log.config.netflow_collector_ip & 0xFF,
               g_nat_log.config.netflow_collector_port, g_nat_log.config.netflow_source_id);
    }
    printf("\n");

    printf("\n  Event Filters:\n");
    printf("    CREATE:         %s\n",
           (g_nat_log.config.events & NAT_LOG_EVENTS_CREATE) ? "Enabled" : "Disabled");
    printf("    DELETE:         %s\n",
           (g_nat_log.config.events & NAT_LOG_EVENTS_DELETE) ? "Enabled" : "Disabled");
    printf("    QUOTA_EXCEEDED: %s\n",
           (g_nat_log.config.events & NAT_LOG_EVENTS_QUOTA) ? "Enabled" : "Disabled");

    printf("\n  Statistics:\n");
    printf("    Events logged:   %lu\n", g_nat_log.stats.events_logged);
    printf("    Events filtered: %lu\n", g_nat_log.stats.events_filtered);
    printf("    Syslog events:   %lu\n", g_nat_log.stats.syslog_events);
    printf("    IPFIX events:    %lu\n", g_nat_log.stats.ipfix_events);
    printf("    NetFlow events:  %lu\n", g_nat_log.stats.netflow_events);

    pthread_mutex_unlock(&g_nat_log.lock);
}

void nat_log_cleanup(void)
{
    pthread_mutex_lock(&g_nat_log.lock);

    if (g_nat_log.initialized) {
        /* Cleanup exporters - No-op */

        g_nat_log.initialized = false;
        YLOG_INFO("NAT logging cleanup complete");
    }

    pthread_mutex_unlock(&g_nat_log.lock);
}
