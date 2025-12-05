#ifndef IPFIX_TEMPLATES_H
#define IPFIX_TEMPLATES_H

#include <stdint.h>

/* IANA / Cisco Field Types */
#define IE_PROTOCOL_IDENTIFIER 4
#define IE_IP_CLASS_OF_SERVICE 5
#define IE_SOURCE_TRANSPORT_PORT 7
#define IE_IPV4_SOURCE_ADDRESS 8
#define IE_IPV4_DESTINATION_ADDRESS 12
#define IE_DESTINATION_TRANSPORT_PORT 11
#define IE_INPUT_SNMP 10
#define IE_OUTPUT_SNMP 14
#define IE_FLOW_START_SYS_UP_TIME 22
#define IE_FLOW_END_SYS_UP_TIME 21
#define IE_FLOW_START_MILLISECONDS 152 /* IPFIX */
#define IE_FLOW_END_MILLISECONDS 153   /* IPFIX */
#define IE_OCTET_DELTA_COUNT 1
#define IE_PACKET_DELTA_COUNT 2
#define IE_DIRECTION 61

/* NAT Fields */
#define IE_NAT_EVENT 230
#define IE_POST_NAT_SOURCE_IPV4 225
#define IE_POST_NAT_SOURCE_PORT 227
#define IE_OBSERVATION_TIME_MILLISECONDS 323

/* Template IDs */
#define TEMPLATE_ID_FLOW_V9 256
#define TEMPLATE_ID_NAT_V9 257
#define TEMPLATE_ID_FLOW_IPFIX 256
#define TEMPLATE_ID_NAT_IPFIX 258

/* Structures for Packet Building */

/* NetFlow v9 Header */
struct netflow_v9_header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t sequence;
    uint32_t source_id;
} __attribute__((packed));

/* IPFIX Header */
struct ipfix_header_v10 {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t sequence;
    uint32_t domain_id;
} __attribute__((packed));

/* Set Header (Used by both) */
struct flowset_header {
    uint16_t id;
    uint16_t length;
} __attribute__((packed));

/* Template Field Specifier */
struct field_specifier {
    uint16_t type;
    uint16_t length;
} __attribute__((packed));

/* Template Header */
struct template_header {
    uint16_t template_id;
    uint16_t field_count;
} __attribute__((packed));

#endif /* IPFIX_TEMPLATES_H */
