/**
 * @file nat_ipfix.h
 * @brief IPFIX NAT Event Logging (RFC 7011, RFC 8158)
 *
 * IPFIX (IP Flow Information Export) implementation for NAT event logging.
 * Exports NAT session create/delete events to an IPFIX collector.
 */

#ifndef NAT_IPFIX_H
#define NAT_IPFIX_H

#include <stdbool.h>
#include <stdint.h>

/* IPFIX Version */
#define IPFIX_VERSION 10

/* IPFIX Standard Ports */
#define IPFIX_DEFAULT_PORT 4739

/* Set IDs */
#define IPFIX_SET_TEMPLATE 2
#define IPFIX_SET_OPTIONS_TEMPLATE 3
#define IPFIX_SET_DATA_MIN 256

/* Our Template IDs */
#define IPFIX_TEMPLATE_NAT44_SESSION 256
#define IPFIX_TEMPLATE_NAT44_QUOTA 257

/* IPFIX Information Element IDs (RFC 8158 - NAT Logging) */
#define IPFIX_IE_OBSERVATION_TIME_MS 324       /* observationTimeMilliseconds */
#define IPFIX_IE_NAT_EVENT 230                 /* natEvent */
#define IPFIX_IE_NAT_POOL_ID 283               /* natPoolId */
#define IPFIX_IE_NAT_POOL_NAME 284             /* natPoolName */
#define IPFIX_IE_SOURCE_IPV4_ADDRESS 8         /* sourceIPv4Address */
#define IPFIX_IE_POST_NAT_SOURCE_IPV4 225      /* postNATSourceIPv4Address */
#define IPFIX_IE_SOURCE_TRANSPORT_PORT 7       /* sourceTransportPort */
#define IPFIX_IE_POST_NAT_SOURCE_PORT 227      /* postNATSourceTransportPort */
#define IPFIX_IE_DESTINATION_IPV4_ADDRESS 12   /* destinationIPv4Address */
#define IPFIX_IE_DESTINATION_TRANSPORT_PORT 11 /* destinationTransportPort */
#define IPFIX_IE_PROTOCOL_IDENTIFIER 4         /* protocolIdentifier */
#define IPFIX_IE_INGRESS_VRF_ID 234            /* ingressVRFID */

/* NAT Event Types (RFC 8158 Section 4) */
#define NAT44_EVENT_SESSION_CREATE 1
#define NAT44_EVENT_SESSION_DELETE 2
#define NAT44_EVENT_POOL_EXHAUSTED 3
#define NAT44_EVENT_QUOTA_EXCEEDED 4
#define NAT44_EVENT_PORT_BLOCK_ALLOC 5
#define NAT44_EVENT_PORT_BLOCK_FREE 6

/* IPFIX Header (RFC 7011 Section 3.1) */
struct __attribute__((packed)) ipfix_header {
    uint16_t version;               /* Version = 10 */
    uint16_t length;                /* Total length of message */
    uint32_t export_time;           /* Seconds since epoch */
    uint32_t sequence_number;       /* Incremental sequence */
    uint32_t observation_domain_id; /* Domain ID */
};

/* IPFIX Set Header (RFC 7011 Section 3.3) */
struct __attribute__((packed)) ipfix_set_header {
    uint16_t set_id; /* Template ID or Data Set ID */
    uint16_t length; /* Length including header */
};

/* Template Field Specifier (RFC 7011 Section 3.2) */
struct __attribute__((packed)) ipfix_field_specifier {
    uint16_t information_element_id; /* IE ID (high bit = enterprise) */
    uint16_t field_length;           /* Length in bytes */
    /* If enterprise bit set, followed by 4-byte enterprise number */
};

/* Template Record Header */
struct __attribute__((packed)) ipfix_template_header {
    uint16_t template_id; /* Template ID (256+) */
    uint16_t field_count; /* Number of fields */
};

/* NAT44 Session Data Record */
struct __attribute__((packed)) ipfix_nat44_session_record {
    uint64_t observation_time_ms;  /* Timestamp in milliseconds */
    uint8_t nat_event;             /* Event type */
    uint32_t source_ipv4;          /* Original source IP */
    uint16_t source_port;          /* Original source port */
    uint32_t post_nat_source_ipv4; /* Translated source IP */
    uint16_t post_nat_source_port; /* Translated source port */
    uint32_t destination_ipv4;     /* Destination IP */
    uint16_t destination_port;     /* Destination port */
    uint8_t protocol;              /* IP protocol */
};

/* IPFIX Exporter Statistics */
struct ipfix_stats {
    uint64_t templates_sent;
    uint64_t data_records_sent;
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t send_errors;
    uint64_t buffer_overflows;
};

/**
 * Initialize IPFIX exporter
 * @param collector_ip Collector IP address (host byte order)
 * @param collector_port Collector UDP port (default: 4739)
 * @param observation_domain_id Unique domain identifier
 * @return 0 on success, -1 on error
 */
int nat_ipfix_init(uint32_t collector_ip, uint16_t collector_port, uint32_t observation_domain_id);

/**
 * Send template set to collector
 * Must be called periodically (recommended: every 10 minutes)
 * @return 0 on success, -1 on error
 */
int nat_ipfix_send_template(void);

/**
 * Log NAT session event
 * @param event_type NAT event type (create/delete)
 * @param inside_ip Original (inside) IP address
 * @param inside_port Original (inside) port
 * @param outside_ip Translated (outside) IP address
 * @param outside_port Translated (outside) port
 * @param dest_ip Destination IP address
 * @param dest_port Destination port
 * @param protocol IP protocol (TCP/UDP/ICMP)
 * @return 0 on success, -1 on error
 */
int nat_ipfix_log_session(uint8_t event_type, uint32_t inside_ip, uint16_t inside_port,
                          uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                          uint16_t dest_port, uint8_t protocol);

/**
 * Log quota exceeded event
 * @param inside_ip IP that exceeded quota
 * @return 0 on success, -1 on error
 */
int nat_ipfix_log_quota_exceeded(uint32_t inside_ip);

/**
 * Flush buffered records to collector
 */
void nat_ipfix_flush(void);

/**
 * Get IPFIX exporter statistics
 * @param stats Output structure for statistics
 */
void nat_ipfix_get_stats(struct ipfix_stats *stats);

/**
 * Check if IPFIX exporter is enabled
 * @return true if enabled
 */
bool nat_ipfix_is_enabled(void);

/**
 * Cleanup IPFIX exporter
 */
void nat_ipfix_cleanup(void);

#endif /* NAT_IPFIX_H */
