#ifndef EXPORT_COMMON_H
#define EXPORT_COMMON_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/* Constants */
#define MAX_EXPORTERS 2
#define EXPORT_BATCH_SIZE 50
#define FLOW_CACHE_SIZE 131072 /* 128K flows per core */
#define EVENT_RING_SIZE 4096

/* Protocol Constants */
#define NETFLOW_V9_VERSION 9
#define IPFIX_VERSION 10
#define OBSERVATION_DOMAIN_ID 1

/* Timeouts (default) */
#define ACTIVE_TIMEOUT_SEC 60
#define INACTIVE_TIMEOUT_SEC 15
#define TEMPLATE_REFRESH_SEC 30

/* 5-tuple Flow Key */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

/* Flow Direction */
enum flow_direction { FLOW_DIR_INGRESS = 0, FLOW_DIR_EGRESS = 1, FLOW_DIR_FORWARD = 2 };

/* Flow Record (Tracking data) */
struct flow_record {
    struct flow_key key;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint32_t packets_in;
    uint32_t packets_out;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint8_t direction; // enum flow_direction
    uint32_t input_if_idx;
    uint32_t output_if_idx;
};

/* NAT Event Types */
enum nat_event_type {
    EXP_NAT_EVENT_CREATE = 1,
    EXP_NAT_EVENT_DELETE = 2,
    EXP_NAT_EVENT_QUOTA_EXCEEDED = 3
};

/* NAT Event Record */
struct nat_event_record {
    uint32_t original_ip;
    uint16_t original_port;
    uint32_t translated_ip;
    uint16_t translated_port;
    uint32_t destination_ip;
    uint16_t destination_port;
    uint8_t protocol;
    uint8_t event_type; // enum nat_event_type
    uint64_t timestamp_ms;
    uint64_t bytes_in;  /* For delete events */
    uint64_t bytes_out; /* For delete events */
};

/* Configuration */
struct exporter_target {
    char ip_str[32];
    uint32_t ip;
    uint16_t port;
    bool enabled;
};

struct export_config {
    struct exporter_target collectors[MAX_EXPORTERS];
    uint32_t active_timeout;
    uint32_t inactive_timeout;
    uint32_t template_refresh_rate;
    bool enabled;
};

/* Exporter message type for the ring */
enum exporter_msg_type { MSG_TYPE_FLOW_RECORD, MSG_TYPE_NAT_EVENT };

struct exporter_msg {
    enum exporter_msg_type type;
    union {
        struct flow_record flow;
        struct nat_event_record nat;
    } data;
};

#endif /* EXPORT_COMMON_H */
