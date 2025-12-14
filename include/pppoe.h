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

/* Global PPP Settings (set once, apply to all sessions) */
struct pppoe_global_settings {
    uint16_t mtu;                /* Default: 1492 */
    uint16_t mru;                /* Default: 1492 */
    uint16_t lcp_echo_interval;  /* Default: 30 sec */
    uint8_t  lcp_echo_failure;   /* Default: 3 */
    uint32_t idle_timeout;       /* Default: 0 (disabled) */
    uint32_t session_timeout;    /* Default: 0 (disabled) */
    uint16_t pado_delay_ms;      /* PADO delay in milliseconds (0-2000) */
    uint32_t padi_rate_limit;    /* Max PADI per second (0 = unlimited) */
    char     ac_name[64];
    char     service_name[64];
};

/* Global settings accessor */
struct pppoe_global_settings *pppoe_get_settings(void);

/* PADO delay setter */
void pppoe_set_pado_delay(uint16_t delay_ms);

/* PADI rate limit setter */
void pppoe_set_padi_rate_limit(uint32_t rate_per_sec);

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
#define MAX_SESSIONS 65535 /* Max 16-bit session ID */

/* PPPoE Session Entry - Cache Aligned */
/* Hot fields in 1st cacheline, Cold in 2nd */
struct pppoe_session {
    /* Cacheline 0: Hot Path (Data/Encapsulation) */
    uint16_t session_id;
    uint8_t state;         /* enum pppoe_state */
    uint8_t lcp_state;     /* enum ppp_lcp_state */
    uint8_t ipcp_state;    /* enum ppp_ipcp_state */
    uint32_t client_ip;    /* Host Order */

    struct rte_ether_addr client_mac;
    struct interface *iface;

    /* QoS Enforcer (Hot for TX) */
    struct token_bucket downlink_tb;

    uint64_t last_activity_ts; /* For idle timeout */

    /* Pad to 64 bytes (Cacheline) */
    uint8_t _pad0[64 - 2 - 1 - 1 - 1 - 4 - 6 - 8 - 16 - 8];

    /* Cacheline 1: Control Plane (LCP/Auth/IPCP/Counters) */
    uint32_t server_ip;
    uint8_t next_lcp_identifier;
    uint8_t echo_failures;
    uint8_t auth_complete;     /* 1 if RADIUS auth completed */

    uint32_t magic_number;
    uint32_t peer_magic_number;
    uint16_t peer_mru;
    uint8_t conf_req_retries;

    uint8_t chap_challenge[16];
    uint8_t chap_challenge_len;

    uint64_t created_ts;
    uint64_t last_echo_ts;
    uint64_t last_conf_req_ts;
    uint64_t last_acct_ts;
    uint32_t acct_interim_interval;

    uint32_t session_timeout;
    uint32_t idle_timeout;
    uint64_t start_ts;

    /* Counters */
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;

    /* Info */
    char username[64];
    uint64_t rate_bps;

    /* Debug */
    bool debug;

    /* Profile */
    uint16_t vlan_id;
    uint16_t auth_protocol;  /* Negotiated auth: PPP_PROTO_PAP or PPP_PROTO_CHAP */
    char pool_name[32];
} __attribute__((aligned(64)));

/* Global storage (defined in pppoe.c) */
extern struct pppoe_session *g_pppoe_session_slab;

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
 * Set AC Name
 */
void pppoe_set_ac_name(const char *name);

/**
 * Set Service Name
 */
void pppoe_set_service_name(const char *name);

/**
 * Set MTU (applies to new sessions)
 */
void pppoe_set_mtu(uint16_t mtu);

/**
 * Set MRU (applies to new sessions)
 */
void pppoe_set_mru(uint16_t mru);

/**
 * Set LCP Echo Interval (seconds)
 */
void pppoe_set_lcp_echo_interval(uint16_t seconds);

/**
 * Set LCP Echo Failure count
 */
void pppoe_set_lcp_echo_failure(uint8_t count);

/**
 * Set Idle Timeout (0 = disabled)
 */
void pppoe_set_idle_timeout(uint32_t seconds);

/**
 * Set Session Timeout (0 = disabled)
 */
void pppoe_set_session_timeout(uint32_t seconds);

/**
 * Terminate session (send PADT + cleanup)
 */
void pppoe_terminate_session(struct pppoe_session *session, const char *reason);

/**
 * Print all active sessions to stdout
 */
void pppoe_print_sessions(void);
void pppoe_print_statistics(void);

/* Debug */
void pppoe_set_session_debug(uint16_t session_id, bool enable);

/* Profile */
void pppoe_add_profile(const char *iface_name, uint16_t vlan_id, const char *pool_name);

#endif /* PPPOE_H */
