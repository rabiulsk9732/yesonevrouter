/**
 * @file nat_log.h
 * @brief NAT Event Logging (IPFIX/Netflow)
 */

#ifndef NAT_LOG_H
#define NAT_LOG_H

#include <stdint.h>
#include <netinet/in.h>

/* NAT Event Types */
enum nat_event_type {
    NAT_EVENT_CREATE = 1,
    NAT_EVENT_DELETE = 2,
    NAT_EVENT_QUOTA_EXCEEDED = 3
};

/**
 * Initialize NAT logging
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
void nat_log_event(enum nat_event_type event_type,
                   uint32_t inside_ip, uint16_t inside_port,
                   uint32_t outside_ip, uint16_t outside_port,
                   uint8_t protocol, uint64_t timestamp);

/**
 * Cleanup NAT logging
 */
void nat_log_cleanup(void);

#endif /* NAT_LOG_H */
