/**
 * @file natexport.h
 * @brief NAT Export - ipt-netflow compatible NetFlow v9 & IPFIX exporter
 *
 * Clean implementation based on https://github.com/aabc/ipt-netflow
 * Supports both NetFlow v9 and IPFIX (v10) for DPDK-based vBNG.
 */

#ifndef NATEXPORT_H
#define NATEXPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/*============================================================================
 * Protocol Versions
 *============================================================================*/

#define NETFLOW_V9_VERSION      9
#define IPFIX_VERSION           10
#define NETFLOW_DEFAULT_PORT    2055

/* Export protocol selection */
typedef enum {
    NATEXPORT_PROTO_NETFLOW_V9 = 9,
    NATEXPORT_PROTO_IPFIX = 10
} natexport_protocol_t;

/*============================================================================
 * FlowSet IDs
 *============================================================================*/

/* NetFlow v9 FlowSet IDs */
#define NF9_FLOWSET_TEMPLATE    0       /* Template FlowSet */
#define NF9_FLOWSET_OPTIONS     1       /* Options Template */

/* IPFIX FlowSet IDs */
#define IPFIX_FLOWSET_TEMPLATE  2       /* Template Set */
#define IPFIX_FLOWSET_OPTIONS   3       /* Options Template Set */

/* Data FlowSets start at 256 for both */
#define FLOWSET_DATA_MIN        256

/* Template IDs */
#define TEMPLATE_ID_NAT         256

/*============================================================================
 * IANA IPFIX Information Elements
 * https://www.iana.org/assignments/ipfix/ipfix.xhtml
 * Used by both NetFlow v9 and IPFIX
 *============================================================================*/

#define IE_OCTET_DELTA_COUNT            1
#define IE_PACKET_DELTA_COUNT           2
#define IE_PROTOCOL_IDENTIFIER          4
#define IE_IP_CLASS_OF_SERVICE          5
#define IE_TCP_CONTROL_BITS             6
#define IE_SOURCE_TRANSPORT_PORT        7
#define IE_SOURCE_IPV4_ADDRESS          8
#define IE_INGRESS_INTERFACE            10
#define IE_DESTINATION_TRANSPORT_PORT   11
#define IE_DESTINATION_IPV4_ADDRESS     12
#define IE_EGRESS_INTERFACE             14
#define IE_FLOW_END_SYS_UP_TIME         21
#define IE_FLOW_START_SYS_UP_TIME       22

/* IPFIX-specific timing */
#define IE_FLOW_START_MS                152
#define IE_FLOW_END_MS                  153

/* NAT-specific IEs (RFC 8158 / RFC 7659) */
#define IE_POST_NAT_SRC_IPV4            225
#define IE_POST_NAT_DST_IPV4            226
#define IE_POST_NAPT_SRC_PORT           227
#define IE_POST_NAPT_DST_PORT           228
#define IE_NAT_EVENT                    230
#define IE_INGRESS_VRF_ID               234
#define IE_NAT_POOL_ID                  283
#define IE_NAT_PORT_RANGE_START         361
#define IE_NAT_PORT_RANGE_END           362

/* Observation time */
#define IE_OBSERVATION_TIME_MS          323

/* Internal Compact Event Structure (Cache Aligned) */
struct nat_event_v2 {
    uint8_t event_type;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t xlate_port;
    uint16_t reserved;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t xlate_ip;
    uint32_t pool_id;
    uint32_t vrf_id;
    uint64_t timestamp;
} __attribute__((packed));

/*============================================================================
 * NAT Event Types (ipt-netflow compatible)
 *============================================================================*/

#define NAT_EVENT_CREATE        1
#define NAT_EVENT_DELETE        2
#define NAT_EVENT_EXHAUSTED     3
#define NAT_EVENT_ACTIVE_TIMEOUT 4    /* RFC 8158 periodic export (non-standard) */

/* TCP flags for ipt-netflow compatibility */
#define TCP_SYN_ACK             0x12    /* Session create */
#define TCP_FIN_RST             0x05    /* Session delete */
#define TCP_ACK                 0x10    /* Active session (for periodic exports) */

/*============================================================================
 * Flow Cache Configuration (ipt-netflow/Cisco compatible)
 *============================================================================*/

#define ACTIVE_TIMEOUT_SEC      1800    /* Active timeout: 30 minutes (export long flows) */
#define INACTIVE_TIMEOUT_SEC    15      /* Inactive timeout: 15 seconds (export idle flows) */
#define MAXFLOWS                2000000 /* Maximum flows in cache: 2M */

/*============================================================================
 * ipt-netflow Refresh Parameters
 *============================================================================*/

#define REFRESH_RATE            20      /* Template every N PDUs */
#define TIMEOUT_RATE_SEC        60      /* Template every N seconds */

/*============================================================================
 * Packet Structures
 *============================================================================*/

/* NetFlow v9 Header (20 bytes) */
struct __attribute__((packed)) nf9_header {
    uint16_t version;           /* Version = 9 */
    uint16_t count;             /* FlowSet count */
    uint32_t sys_uptime;        /* Milliseconds since boot */
    uint32_t unix_secs;         /* Seconds since epoch */
    uint32_t sequence;          /* Sequence number */
    uint32_t source_id;         /* Source/Observation Domain ID */
};

/* IPFIX Header (16 bytes) */
struct __attribute__((packed)) ipfix_header {
    uint16_t version;           /* Version = 10 */
    uint16_t length;            /* Total message length */
    uint32_t export_time;       /* Seconds since epoch */
    uint32_t sequence;          /* Sequence number */
    uint32_t domain_id;         /* Observation Domain ID */
};

/* FlowSet/Set Header (4 bytes) - same for both */
struct __attribute__((packed)) flowset_header {
    uint16_t id;                /* FlowSet ID: 0/2=template, 256+=data */
    uint16_t length;            /* Total length including header */
};

/* Template Header (4 bytes) */
struct __attribute__((packed)) template_header {
    uint16_t template_id;       /* Template ID (256-65535) */
    uint16_t field_count;       /* Number of fields */
};

/* Field Specifier (4 bytes) */
struct __attribute__((packed)) field_spec {
    uint16_t type;              /* Field type (IE number) */
    uint16_t length;            /* Field length in bytes */
};

/*============================================================================
 * NAT Record Template (ipt-netflow compatible - 14 fields)
 *
 * Field order (same for NetFlow v9 and IPFIX):
 * 1.  observationTimeMilliseconds (323) - 8 bytes
 * 2.  natEvent (230) - 1 byte
 * 3.  protocolIdentifier (4) - 1 byte
 * 4.  sourceIPv4Address (8) - 4 bytes
 * 5.  sourceTransportPort (7) - 2 bytes
 * 6.  destinationIPv4Address (12) - 4 bytes
 * 7.  destinationTransportPort (11) - 2 bytes
 * 8.  postNATSourceIPv4Address (225) - 4 bytes
 * 9.  postNAPTSourceTransportPort (227) - 2 bytes
 * 10. postNATDestinationIPv4Address (226) - 4 bytes
 * 11. postNAPTDestinationTransportPort (228) - 2 bytes
 * 12. tcpControlBits (6) - 1 byte
 * 13. ingressInterface (10) - 4 bytes
 * 14. egressInterface (14) - 4 bytes
 * 15. flowStartMilliseconds (152) - 8 bytes [RFC 8158]
 * 16. flowEndMilliseconds (153) - 8 bytes [RFC 8158]
 * 17. packetDeltaCount (2) - 8 bytes [RFC 8158]
 * 18. octetDeltaCount (1) - 8 bytes [RFC 8158]
 *
 * 19. natPoolId (283) - 4 bytes [RFC 8158]
 * 20. ingressVRFID (234) - 4 bytes [RFC 8158]
 *
 * Total: 83 bytes per record (enhanced template v2)
 *============================================================================*/

#define NAT_TEMPLATE_FIELD_COUNT    20
#define NAT_RECORD_SIZE             83

/*============================================================================
 * Statistics
 *============================================================================*/

struct natexport_stats {
    uint64_t templates_sent;
    uint64_t data_records_sent;
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t errors;

    /* Health monitoring */
    uint64_t dpdk_send_success;
    uint64_t dpdk_send_failures;
    uint64_t socket_send_success;
    uint64_t socket_send_failures;
    uint64_t flush_count;
    time_t   last_flush_time;
    time_t   last_error_time;
};

/*============================================================================
 * Configuration
 *============================================================================*/

struct natexport_config {
    uint32_t collector_ip;      /* Host byte order */
    uint16_t collector_port;
    uint32_t source_id;         /* Observation Domain ID */
    natexport_protocol_t protocol;  /* v9 or v10 */
};

/*============================================================================
 * API Functions
 *============================================================================*/

/**
 * Initialize NAT exporter with NetFlow v9
 */
int natexport_init_v9(uint32_t collector_ip, uint16_t collector_port, uint32_t source_id);

/**
 * Initialize NAT exporter with IPFIX
 */
int natexport_init_ipfix(uint32_t collector_ip, uint16_t collector_port, uint32_t domain_id);

/**
 * Log NAT session event
 * @param event_type NAT_EVENT_CREATE or NAT_EVENT_DELETE
 * @param src_ip Original source IP (private IP, host byte order)
 * @param src_port Original source port
 * @param xlate_ip Translated source IP (public IP, host byte order)
 * @param xlate_port Translated source port
 * @param dst_ip Destination IP (host byte order)
 * @param dst_port Destination port
 * @param protocol IP protocol (TCP=6, UDP=17)
 */
int natexport_log(uint8_t event_type,
                  uint32_t src_ip, uint16_t src_port,
                  uint32_t xlate_ip, uint16_t xlate_port,
                  uint32_t dst_ip, uint16_t dst_port,
                  uint8_t protocol,
                  uint32_t pool_id, uint32_t vrf_id);

/**
 * Initialize per-worker resources (lockless ring)
 * Must be called by each NAT worker thread
 */
int natexport_init_worker(uint32_t worker_id);

/**
 * Force send template (for CLI)
 */
int natexport_send_template(void);

/**
 * Flush pending records
 */
void natexport_flush(void);

/**
 * Get statistics
 */
void natexport_get_stats(struct natexport_stats *stats);

/**
 * Check if enabled
 */
bool natexport_is_enabled(void);

/**
 * Shutdown
 */
void natexport_cleanup(void);

/**
 * Log NAT session with full RFC 8158 flow data (for active timeout)
 * @param event_type NAT event type
 * @param src_ip Original source IP (private IP, host byte order)
 * @param src_port Original source port
 * @param xlate_ip Translated source IP (public IP, host byte order)
 * @param xlate_port Translated source port
 * @param dst_ip Destination IP (host byte order)
 * @param dst_port Destination port
 * @param protocol IP protocol (TCP=6, UDP=17, ICMP=1)
 * @param flow_start_ms Flow start timestamp (milliseconds since epoch)
 * @param flow_end_ms Flow end timestamp (milliseconds since epoch)
 * @param delta_pkts Packet count since last export
 * @param delta_bytes Byte count since last export
 */
int natexport_log_flow(uint8_t event_type,
                       uint32_t src_ip, uint16_t src_port,
                       uint32_t xlate_ip, uint16_t xlate_port,
                       uint32_t dst_ip, uint16_t dst_port,
                       uint8_t protocol,
                       uint64_t flow_start_ms, uint64_t flow_end_ms,
                       uint64_t delta_pkts, uint64_t delta_bytes);

/**
 * Start active timeout scanner thread
 * Periodically scans NAT sessions and exports flows with traffic
 */
int natexport_start_active_timeout(void);

/**
 * Stop active timeout scanner thread
 */
void natexport_stop_active_timeout(void);

/*============================================================================
 * Runtime Configuration API
 *============================================================================*/

/**
 * Set active timeout (export long-running flows)
 * @param seconds Timeout in seconds (default 1800 = 30 minutes)
 */
void natexport_set_active_timeout(uint32_t seconds);

/**
 * Set inactive timeout (export idle flows)
 * @param seconds Timeout in seconds (default 15)
 */
void natexport_set_inactive_timeout(uint32_t seconds);

/**
 * Get current active timeout
 * @return Active timeout in seconds
 */
uint32_t natexport_get_active_timeout(void);

/**
 * Get current inactive timeout
 * @return Inactive timeout in seconds
 */
uint32_t natexport_get_inactive_timeout(void);

#endif /* NATEXPORT_H */

/*============================================================================
 * 100G+ Production Features
 *============================================================================*/

/* Event Sampling API */
void natexport_set_sampling_rate(uint32_t rate);
void natexport_set_protocol_sampling(uint8_t protocol, uint32_t rate);
void natexport_get_sampling_stats(uint64_t *sampled, uint64_t *dropped);

/* Rate Limiting API */
void natexport_set_rate_limit(uint32_t sustained, uint32_t burst);
void natexport_get_rate_limit_stats(uint64_t *limited);

/* Health Check API */
void natexport_start_health_check(void);
void natexport_stop_health_check(void);
bool natexport_collector_healthy(int index);
int natexport_healthy_collector_count(void);

/* CLI Support API */
void natexport_print_collectors(void);
void natexport_print_config(void);
bool natexport_is_enabled(void);

/* Port Range IEs for bulk port allocation (RFC 7659) */
#define IPFIX_IE_PORT_RANGE_START       361
#define IPFIX_IE_PORT_RANGE_END         362
#define IPFIX_IE_PORT_RANGE_STEP_SIZE   363
#define IPFIX_IE_PORT_RANGE_NUM_PORTS   364

/* Quota event type (RFC 6888) */
#define NAT_EVENT_QUOTA_EXCEEDED        4
