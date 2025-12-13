/**
 * @file ipoe_dhcp.h
 * @brief IPoE DHCP Engine - Packet Processing and State Machine
 *
 * RFC 2131 compliant DHCP handling for IPoE subscribers
 * Supports local server and relay mode with Option 82
 */

#ifndef IPOE_DHCP_H
#define IPOE_DHCP_H

#include <ipoe_session.h>
#include <stdint.h>
#include <stdbool.h>

/*============================================================================
 * DHCP Constants (RFC 2131)
 *============================================================================*/

#define DHCP_SERVER_PORT        67
#define DHCP_CLIENT_PORT        68

#define DHCP_MAGIC_COOKIE       0x63825363

/* DHCP Message Types */
#define DHCP_DISCOVER           1
#define DHCP_OFFER              2
#define DHCP_REQUEST            3
#define DHCP_DECLINE            4
#define DHCP_ACK                5
#define DHCP_NAK                6
#define DHCP_RELEASE            7
#define DHCP_INFORM             8

/* DHCP Options */
#define DHCP_OPT_PAD            0
#define DHCP_OPT_SUBNET_MASK    1
#define DHCP_OPT_ROUTER         3
#define DHCP_OPT_DNS            6
#define DHCP_OPT_HOSTNAME       12
#define DHCP_OPT_DOMAIN         15
#define DHCP_OPT_REQUESTED_IP   50
#define DHCP_OPT_LEASE_TIME     51
#define DHCP_OPT_MSG_TYPE       53
#define DHCP_OPT_SERVER_ID      54
#define DHCP_OPT_PARAM_LIST     55
#define DHCP_OPT_MESSAGE        56
#define DHCP_OPT_MAX_SIZE       57
#define DHCP_OPT_RENEWAL_TIME   58
#define DHCP_OPT_REBIND_TIME    59
#define DHCP_OPT_CLIENT_ID      61
#define DHCP_OPT_RELAY_INFO     82
#define DHCP_OPT_END            255

/* Option 82 Sub-options */
#define DHCP_RELAY_CIRCUIT_ID   1
#define DHCP_RELAY_REMOTE_ID    2

/*============================================================================
 * DHCP Packet Structure
 *============================================================================*/

struct dhcp_packet {
    uint8_t  op;              /* Message type: 1=BOOTREQUEST, 2=BOOTREPLY */
    uint8_t  htype;           /* Hardware type: 1=Ethernet */
    uint8_t  hlen;            /* Hardware address length: 6 */
    uint8_t  hops;            /* Relay hops */
    uint32_t xid;             /* Transaction ID */
    uint16_t secs;            /* Seconds elapsed */
    uint16_t flags;           /* Flags (broadcast) */
    uint32_t ciaddr;          /* Client IP address */
    uint32_t yiaddr;          /* 'Your' IP address (assigned) */
    uint32_t siaddr;          /* Server IP address */
    uint32_t giaddr;          /* Gateway IP address (relay) */
    uint8_t  chaddr[16];      /* Client hardware address */
    uint8_t  sname[64];       /* Server hostname */
    uint8_t  file[128];       /* Boot filename */
    uint32_t magic;           /* Magic cookie (0x63825363) */
    uint8_t  options[312];    /* DHCP options */
} __attribute__((packed));

/*============================================================================
 * Parsed DHCP Options
 *============================================================================*/

struct dhcp_options {
    uint8_t  msg_type;
    uint32_t requested_ip;
    uint32_t server_id;
    uint32_t lease_time;
    uint32_t subnet_mask;
    uint32_t router;
    uint32_t dns_primary;
    uint32_t dns_secondary;
    char     hostname[64];
    bool     has_circuit_id;
    uint8_t  circuit_id[64];
    uint8_t  circuit_id_len;
    bool     has_remote_id;
    uint8_t  remote_id[64];
    uint8_t  remote_id_len;
};

/*============================================================================
 * DHCP Configuration
 *============================================================================*/

struct ipoe_dhcp_config {
    bool     enabled;
    bool     relay_mode;          /* true=relay, false=local server */
    uint32_t server_ip;           /* Local server IP or upstream server */
    uint32_t relay_gateway;       /* Gateway IP for relay */

    /* Default lease parameters */
    uint32_t default_lease_time;
    uint32_t min_lease_time;
    uint32_t max_lease_time;

    /* Option 82 */
    bool     option82_enable;
    char     circuit_id_format[64];   /* e.g., "%port%:%svlan%:%cvlan%" */
    char     remote_id_format[64];    /* e.g., "%mac%" */

    /* Security */
    uint32_t rate_limit_per_mac;      /* DHCP packets/sec per MAC */
    bool     rogue_server_detect;

    /* Statistics */
    uint64_t discovers_rx;
    uint64_t offers_tx;
    uint64_t requests_rx;
    uint64_t acks_tx;
    uint64_t naks_tx;
    uint64_t releases_rx;
    uint64_t rate_limited;
    uint64_t rogue_detected;
};

/*============================================================================
 * DHCP API
 *============================================================================*/

/* Initialization */
int ipoe_dhcp_init(void);
void ipoe_dhcp_cleanup(void);
void ipoe_dhcp_set_config(struct ipoe_dhcp_config *config);

/* Packet processing */
int ipoe_dhcp_process_packet(const uint8_t *pkt, size_t len,
                              uint16_t svlan, uint16_t cvlan,
                              uint32_t ifindex);

/* Option parsing */
int ipoe_dhcp_parse_options(const struct dhcp_packet *pkt, struct dhcp_options *opts);
int ipoe_dhcp_insert_option82(struct dhcp_packet *pkt, struct ipoe_session *sess);
int ipoe_dhcp_remove_option82(struct dhcp_packet *pkt);

/* Packet building */
int ipoe_dhcp_build_offer(struct ipoe_session *sess, struct dhcp_packet *pkt);
int ipoe_dhcp_build_ack(struct ipoe_session *sess, struct dhcp_packet *pkt);
int ipoe_dhcp_build_nak(struct ipoe_session *sess, struct dhcp_packet *pkt, const char *msg);

/* Lease management */
int ipoe_dhcp_allocate_ip(struct ipoe_session *sess);
void ipoe_dhcp_release_ip(struct ipoe_session *sess);
void ipoe_dhcp_check_leases(void);

/* Statistics */
void ipoe_dhcp_get_stats(struct ipoe_dhcp_config *stats);
void ipoe_dhcp_print_stats(void);

#endif /* IPOE_DHCP_H */
