/**
 * @file nat_netflow.h
 * @brief NetFlow v9 NAT Event Logging (Cisco NetFlow Export Format)
 *
 * NetFlow v9 implementation for NAT event logging.
 * Provides backward compatibility with legacy collectors.
 */

#ifndef NAT_NETFLOW_H
#define NAT_NETFLOW_H

#include <stdbool.h>
#include <stdint.h>

/* NetFlow Version */
#define NETFLOW_V9_VERSION 9

/* NetFlow v9 Standard Port */
#define NETFLOW_DEFAULT_PORT 2055

/* FlowSet IDs */
#define NF9_FLOWSET_TEMPLATE 0
#define NF9_FLOWSET_OPTIONS 1
#define NF9_FLOWSET_DATA_MIN 256

/* Our Template IDs */
#define NF9_TEMPLATE_NAT44_SESSION 300
#define NF9_TEMPLATE_NAT44_QUOTA 301

/* NetFlow v9 Field Types (from Cisco documentation) */
#define NF9_FIELD_IN_BYTES 1
#define NF9_FIELD_IN_PKTS 2
#define NF9_FIELD_PROTOCOL 4
#define NF9_FIELD_SRC_TOS 5
#define NF9_FIELD_L4_SRC_PORT 7
#define NF9_FIELD_IPV4_SRC_ADDR 8
#define NF9_FIELD_L4_DST_PORT 11
#define NF9_FIELD_IPV4_DST_ADDR 12
#define NF9_FIELD_LAST_SWITCHED 21
#define NF9_FIELD_FIRST_SWITCHED 22
#define NF9_FIELD_OUT_BYTES 23
#define NF9_FIELD_OUT_PKTS 24
#define NF9_FIELD_FLOW_SAMPLER_ID 48

/* NAT-specific Field Types (Cisco NAT Extension) */
#define NF9_FIELD_NAT_EVENT 230
#define NF9_FIELD_POST_NAT_SRC_ADDR 225
#define NF9_FIELD_POST_NAT_DST_ADDR 226
#define NF9_FIELD_POST_NAT_SRC_PORT 227
#define NF9_FIELD_POST_NAT_DST_PORT 228
#define NF9_FIELD_OBSERVATION_TIME_MS 323

/* NAT Event Types */
#define NF9_NAT_EVENT_CREATE 1
#define NF9_NAT_EVENT_DELETE 2
#define NF9_NAT_EVENT_EXHAUSTED 3

/* NetFlow v9 Header */
struct __attribute__((packed)) netflow9_header {
    uint16_t version;    /* Version = 9 */
    uint16_t count;      /* Number of FlowSets in packet */
    uint32_t sys_uptime; /* Milliseconds since device boot */
    uint32_t unix_secs;  /* Seconds since epoch */
    uint32_t sequence;   /* Sequence counter */
    uint32_t source_id;  /* Source ID (Engine ID) */
};

/* FlowSet Header */
struct __attribute__((packed)) netflow9_flowset_header {
    uint16_t flowset_id; /* 0=Template, 1=Options, 256+=Data */
    uint16_t length;     /* Total length including header */
};

/* Template Record Header */
struct __attribute__((packed)) netflow9_template_header {
    uint16_t template_id; /* Template ID (256-65535) */
    uint16_t field_count; /* Number of fields */
};

/* Template Field Definition */
struct __attribute__((packed)) netflow9_field_def {
    uint16_t field_type;   /* Field type */
    uint16_t field_length; /* Field length in bytes */
};

/* NAT44 Session Data Record (matches our template) */
struct __attribute__((packed)) netflow9_nat44_record {
    uint32_t observation_time;  /* Timestamp (seconds) */
    uint8_t nat_event;          /* Event type */
    uint32_t ipv4_src_addr;     /* Original source IP */
    uint16_t l4_src_port;       /* Original source port */
    uint32_t post_nat_src_addr; /* Translated source IP */
    uint16_t post_nat_src_port; /* Translated source port */
    uint32_t ipv4_dst_addr;     /* Destination IP */
    uint16_t l4_dst_port;       /* Destination port */
    uint8_t protocol;           /* IP protocol */
};

/* NetFlow v9 Exporter Statistics */
struct netflow9_stats {
    uint64_t templates_sent;
    uint64_t data_records_sent;
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t send_errors;
};

/**
 * Initialize NetFlow v9 exporter
 * @param collector_ip Collector IP address (host byte order)
 * @param collector_port Collector UDP port (default: 2055)
 * @param source_id Source/Engine ID
 * @return 0 on success, -1 on error
 */
int nat_netflow_init(uint32_t collector_ip, uint16_t collector_port, uint32_t source_id);

/**
 * Send template FlowSet to collector
 * Must be called periodically (recommended: every 10 minutes)
 * @return 0 on success, -1 on error
 */
int nat_netflow_send_template(void);

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
int nat_netflow_log_session(uint8_t event_type, uint32_t inside_ip, uint16_t inside_port,
                            uint32_t outside_ip, uint16_t outside_port, uint32_t dest_ip,
                            uint16_t dest_port, uint8_t protocol);

/**
 * Flush buffered records to collector
 */
void nat_netflow_flush(void);

/**
 * Get NetFlow v9 exporter statistics
 * @param stats Output structure for statistics
 */
void nat_netflow_get_stats(struct netflow9_stats *stats);

/**
 * Check if NetFlow v9 exporter is enabled
 * @return true if enabled
 */
bool nat_netflow_is_enabled(void);

/**
 * Cleanup NetFlow v9 exporter
 */
void nat_netflow_cleanup(void);

#endif /* NAT_NETFLOW_H */
