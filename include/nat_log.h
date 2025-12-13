/**
 * @file nat_log.h
 * @brief NAT Event Logging (IPFIX/Netflow)
 *
 * Unified interface for NAT event logging.
 * Dispatches events to configured exporters (IPFIX, NetFlow v9, syslog).
 */

#ifndef NAT_LOG_H
#define NAT_LOG_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/* NAT Event Types */
enum nat_event_type { NAT_EVENT_CREATE = 1, NAT_EVENT_DELETE = 2, NAT_EVENT_QUOTA_EXCEEDED = 3 };

/* Logging Targets */
#define NAT_LOG_TARGET_SYSLOG (1 << 0)
#define NAT_LOG_TARGET_IPFIX (1 << 1)
#define NAT_LOG_TARGET_NETFLOW (1 << 2)

/* Event Filters */
#define NAT_LOG_EVENTS_CREATE (1 << 0)
#define NAT_LOG_EVENTS_DELETE (1 << 1)
#define NAT_LOG_EVENTS_QUOTA (1 << 2)
#define NAT_LOG_EVENTS_ALL (NAT_LOG_EVENTS_CREATE | NAT_LOG_EVENTS_DELETE | NAT_LOG_EVENTS_QUOTA)

/* NAT Logging Configuration */
struct nat_log_config {
    uint32_t targets; /* Bitmask of enabled targets */
    uint32_t events;  /* Bitmask of enabled events */

    /* IPFIX settings */
    uint32_t ipfix_collector_ip;
    uint16_t ipfix_collector_port;
    uint32_t ipfix_observation_domain;

    /* NetFlow v9 settings */
    uint32_t netflow_collector_ip;
    uint16_t netflow_collector_port;
    uint32_t netflow_source_id;

    /* Common settings */
    uint32_t template_refresh_interval; /* seconds */
};

/* NAT Logging Statistics */
struct nat_log_stats {
    uint64_t events_logged;
    uint64_t events_filtered;
    uint64_t syslog_events;
    uint64_t ipfix_events;
    uint64_t netflow_events;
};

/**
 * Initialize NAT logging subsystem
 * @return 0 on success, -1 on error
 */
int nat_log_subsystem_init(void);

/**
 * Configure IPFIX exporter
 * @param collector_ip Collector IP address (host byte order)
 * @param collector_port Collector UDP port (default: 4739)
 * @param observation_domain_id Unique domain identifier
 * @return 0 on success, -1 on error
 */
int nat_log_configure_ipfix(uint32_t collector_ip, uint16_t collector_port,
                            uint32_t observation_domain_id);

/**
 * Configure NetFlow v9 exporter
 * @param collector_ip Collector IP address (host byte order)
 * @param collector_port Collector UDP port (default: 2055)
 * @param source_id Source/Engine ID
 * @return 0 on success, -1 on error
 */
int nat_log_configure_netflow(uint32_t collector_ip, uint16_t collector_port, uint32_t source_id);

/**
 * Enable/disable logging target
 * @param target Target bitmask (NAT_LOG_TARGET_*)
 * @param enable true to enable, false to disable
 */
void nat_log_set_target(uint32_t target, bool enable);

/**
 * Enable/disable event types
 * @param events Event bitmask (NAT_LOG_EVENTS_*)
 * @param enable true to enable, false to disable
 */
void nat_log_set_events(uint32_t events, bool enable);

/**
 * Initialize NAT logging (legacy API - deprecated)
 * @param collector_ip IP address of the IPFIX collector
 * @param collector_port Port of the IPFIX collector
 * @return 0 on success, -1 on error
 */
int nat_log_init(uint32_t collector_ip, uint16_t collector_port);

/**
 * Log a NAT session event
 * @param event_type Type of event (create/delete)
 * @param inside_ip Inside (private) IP
 * @param inside_port Inside port
 * @param outside_ip Outside (public) IP
 * @param outside_port Outside port
 * @param protocol Protocol (TCP/UDP/ICMP)
 * @param timestamp Timestamp of the event
 */
void nat_log_event(enum nat_event_type event_type, uint32_t inside_ip, uint16_t inside_port,
                   uint32_t outside_ip, uint16_t outside_port, uint8_t protocol,
                   uint64_t timestamp);

/**
 * Log NAT session event with full tuple (extended API)
 * @param event_type Type of event (create/delete)
 * @param inside_ip Inside (private) IP
 * @param inside_port Inside port
 * @param outside_ip Outside (public) IP
 * @param outside_port Outside port
 * @param dest_ip Destination IP
 * @param dest_port Destination port
 * @param protocol Protocol (TCP/UDP/ICMP)
 */
void nat_log_session_event(enum nat_event_type event_type, uint32_t inside_ip, uint16_t inside_port,
                           uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                           uint16_t dest_port, uint8_t protocol, uint32_t pool_id, uint32_t vrf_id);

/**
 * Flush all buffered log events
 */
void nat_log_flush(void);

/**
 * Get logging statistics
 * @param stats Output structure for statistics
 */
void nat_log_get_stats(struct nat_log_stats *stats);

/**
 * Print logging configuration
 */
void nat_log_print_config(void);

/**
 * Cleanup NAT logging
 */
void nat_log_cleanup(void);

#endif /* NAT_LOG_H */
