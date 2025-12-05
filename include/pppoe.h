/**
 * @file pppoe.h
 * @brief PPPoE Server API and Structures
 */

#ifndef PPPOE_H
#define PPPOE_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <time.h>
#include "qos.h"
#include "pppoe_defs.h"

/* Forward declarations */
struct pkt_buf;
struct interface;

/* PPPoE Header (packed) */
struct pppoe_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
    uint8_t ver:4;      /* Version (must be 1) */
    uint8_t type:4;     /* Type (must be 1) */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
    uint8_t type:4;
    uint8_t ver:4;
#endif
    uint8_t code;       /* Code (PADI/PADO/etc) */
    uint16_t session_id;/* Session ID */
    uint16_t length;    /* Payload length */
} __attribute__((packed));

/* PPPoE Tag Header */
struct pppoe_tag {
    uint16_t type;
    uint16_t length;
    uint8_t value[];
} __attribute__((packed));

/* PPPoE Session State */
enum pppoe_state {
    PPPOE_STATE_INITIAL,
    PPPOE_STATE_PADI_RCVD,
    PPPOE_STATE_PADR_RCVD,
    PPPOE_STATE_SESSION_ESTABLISHED,
    PPPOE_STATE_TERMINATED
};

/* PPP LCP State */
enum ppp_lcp_state {
    LCP_STATE_INITIAL,
    LCP_STATE_STARTING,
    LCP_STATE_CLOSED,
    LCP_STATE_STOPPED,
    LCP_STATE_CLOSING,
    LCP_STATE_STOPPING,
    LCP_STATE_REQ_SENT,
    LCP_STATE_ACK_RCVD,
    LCP_STATE_ACK_SENT,
    LCP_STATE_OPENED
};

/* PPPoE Session Entry */
struct pppoe_session {
    uint16_t session_id;
    struct rte_ether_addr client_mac;
    struct interface *iface;

    enum pppoe_state state;
    enum ppp_lcp_state lcp_state;
    uint8_t next_lcp_identifier;

    uint32_t client_ip;
    uint32_t server_ip;

    uint32_t magic_number;
    uint32_t peer_magic_number;

    uint8_t chap_challenge[16];
    uint8_t chap_challenge_len;

    uint64_t created_ts;
    uint64_t last_activity_ts;
    uint64_t last_echo_ts;
    uint8_t echo_failures;

    uint64_t last_acct_ts;
    uint32_t acct_interim_interval; /* 0 = disabled */

    /* Advanced Session */
    uint32_t session_timeout; /* 0 = disabled */
    uint32_t idle_timeout;    /* 0 = disabled */
    uint64_t start_ts;        /* Session start time */

    /* QoS */
    struct token_bucket downlink_tb;

    /* Counters */
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;

    struct pppoe_session *next;
};

/**
 * Initialize PPPoE subsystem
 * @return 0 on success, -1 on error
 */
int pppoe_init(void);

/**
 * Cleanup PPPoE subsystem
 */
void pppoe_cleanup(void);

/**
 * Process PPPoE Discovery packet (PADI/PADR/PADT)
 * @param pkt Packet buffer
 * @param iface Ingress interface
 * @return 0 on success, -1 on error
 */
int pppoe_process_discovery(struct pkt_buf *pkt, struct interface *iface);

/**
 * Process PPPoE Session packet
 * @param pkt Packet buffer
 * @param iface Ingress interface
 * @return 0 on success, -1 on error
 */
int pppoe_process_session(struct pkt_buf *pkt, struct interface *iface);

/**
 * Find session by Client IP
 * @param ip Client IP (host byte order)
 * @return Session pointer or NULL
 */
struct pppoe_session *pppoe_find_session_by_ip(uint32_t ip);

/**
 * Send IP packet via PPPoE session (Encapsulation)
 * @param session PPPoE session
 * @param pkt IP packet buffer
 * @return 0 on success, -1 on error
 */
int pppoe_send_session_packet(struct pppoe_session *session, struct pkt_buf *pkt);

/**
 * Check session keepalives (call periodically)
 */
void pppoe_check_keepalives(void);

/**
 * Check accounting updates (call periodically)
 */
void pppoe_check_accounting(void);

/**
 * Update QoS for a session
 */
void pppoe_update_qos(const uint8_t *mac, uint64_t rate_bps);

/**
 * Send PADT (graceful session termination)
 */
int pppoe_send_padt(struct pppoe_session *session);

/**
 * Terminate session (send PADT + cleanup)
 */
void pppoe_terminate_session(struct pppoe_session *session, const char *reason);

#endif /* PPPOE_H */
