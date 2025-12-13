/**
 * @file ipoe_session.h
 * @brief IPoE Session Management - Data Structures and API
 *
 * Carrier-grade IPoE subscriber session management supporting:
 * - L2 Mode (MAC-based identification)
 * - L3 Mode (VLAN-based identification with Option 82)
 * - 1M+ concurrent sessions
 * - Lockless lookup tables
 */

#ifndef IPOE_SESSION_H
#define IPOE_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

#ifdef HAVE_DPDK
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#endif

/*============================================================================
 * Lockless DPDK Configuration
 *============================================================================*/

#define IPOE_MAX_WORKERS            32
#define IPOE_WORKER_RING_SIZE       4096    /* Per-worker event ring */
#define IPOE_SESSION_MEMPOOL_SIZE   (IPOE_MAX_SESSIONS + 1024)
#define IPOE_TX_RING_SIZE           1024    /* TX response queue */

/*============================================================================
 * Constants
 *============================================================================*/

#define IPOE_MAX_SESSIONS           1000000
#define IPOE_MAX_IPS_PER_MAC        4
#define IPOE_MAX_USERNAME_LEN       64
#define IPOE_MAX_POOL_NAME_LEN      32
#define IPOE_SESSION_HASH_ENTRIES   (IPOE_MAX_SESSIONS * 2)

/*============================================================================
 * Session States
 *============================================================================*/

typedef enum {
    IPOE_STATE_INIT = 0,          /* New session, not yet authenticated */
    IPOE_STATE_AUTH_PENDING,      /* RADIUS Access-Request sent */
    IPOE_STATE_AUTH_REJECTED,     /* RADIUS Access-Reject received */
    IPOE_STATE_DHCP_PENDING,      /* Authorized, waiting for DHCP */
    IPOE_STATE_IP_BOUND,          /* DHCP ACK received, IP assigned */
    IPOE_STATE_ACTIVE,            /* Fully active, traffic allowed */
    IPOE_STATE_IDLE,              /* No traffic, idle timeout pending */
    IPOE_STATE_EXPIRED,           /* Lease/session expired */
    IPOE_STATE_TERMINATING,       /* Being cleaned up */
    IPOE_STATE_MAX
} ipoe_session_state_t;

/*============================================================================
 * DHCP States (RFC 2131)
 *============================================================================*/

typedef enum {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_SELECTING,         /* DISCOVER sent */
    DHCP_STATE_REQUESTING,        /* REQUEST sent */
    DHCP_STATE_BOUND,             /* ACK received */
    DHCP_STATE_RENEWING,          /* T1 expired, unicast RENEW */
    DHCP_STATE_REBINDING,         /* T2 expired, broadcast REBIND */
    DHCP_STATE_EXPIRED,           /* Lease expired */
    DHCP_STATE_MAX
} dhcp_state_t;

/*============================================================================
 * AAA States
 *============================================================================*/

typedef enum {
    AAA_STATE_NONE = 0,
    AAA_STATE_PENDING,            /* Access-Request sent */
    AAA_STATE_AUTHORIZED,         /* Access-Accept received */
    AAA_STATE_REJECTED,           /* Access-Reject received */
    AAA_STATE_TIMEOUT,            /* No response */
    AAA_STATE_MAX
} aaa_state_t;

/*============================================================================
 * Session Flags
 *============================================================================*/

#define IPOE_FLAG_L2_MODE           0x01    /* L2 MAC-based identification */
#define IPOE_FLAG_L3_MODE           0x02    /* L3 VLAN-based identification */
#define IPOE_FLAG_MAC_AUTH          0x04    /* MAC authentication enabled */
#define IPOE_FLAG_STATIC_IP         0x08    /* Static IP assignment */
#define IPOE_FLAG_MULTI_IP          0x10    /* Multiple IPs per MAC allowed */
#define IPOE_FLAG_ANTI_SPOOF        0x20    /* Anti-spoof enabled */
#define IPOE_FLAG_OPTION82          0x40    /* Option 82 inserted */
#define IPOE_FLAG_ACCOUNTING        0x80    /* RADIUS accounting active */

/*============================================================================
 * Session Termination Reasons
 *============================================================================*/

typedef enum {
    IPOE_TERM_NONE = 0,
    IPOE_TERM_USER_REQUEST,       /* DHCP Release */
    IPOE_TERM_ADMIN,              /* CLI clear */
    IPOE_TERM_RADIUS_DM,          /* RADIUS Disconnect-Message */
    IPOE_TERM_LEASE_EXPIRE,       /* DHCP lease expired */
    IPOE_TERM_IDLE_TIMEOUT,       /* No traffic timeout */
    IPOE_TERM_SESSION_TIMEOUT,    /* Max session time reached */
    IPOE_TERM_AUTH_FAILURE,       /* RADIUS reject */
    IPOE_TERM_PORT_DOWN,          /* Interface down */
    IPOE_TERM_DUPLICATE_MAC,      /* MAC conflict */
    IPOE_TERM_ARP_CONFLICT,       /* ARP/IP conflict */
    IPOE_TERM_MAX
} ipoe_term_reason_t;

/*============================================================================
 * Core Session Structure
 *============================================================================*/

struct ipoe_session {
    /* Allocation tracking */
    uint8_t in_use;               /* 1 if slot is in use (for lockless alloc) */
    uint8_t _pad[3];              /* Alignment padding */

    /* Session ID */
    uint32_t session_id;          /* Unique session identifier */
    uint64_t acct_session_id;     /* RADIUS Acct-Session-Id */

    /*========== Identification ==========*/
    uint8_t  mac[6];              /* Subscriber MAC address */
    uint16_t svlan;               /* S-VLAN (outer) - 0 if L2 mode */
    uint16_t cvlan;               /* C-VLAN (inner) - 0 if L2 mode */
    uint32_t ifindex;             /* Ingress interface index */
    uint16_t port_id;             /* Physical port ID */

    /*========== IP Binding ==========*/
    uint32_t ip_addr;             /* Primary assigned IPv4 */
    uint32_t ip_mask;             /* Subnet mask */
    uint32_t gateway;             /* Default gateway */
    uint32_t dns_primary;         /* Primary DNS */
    uint32_t dns_secondary;       /* Secondary DNS */

    /* Multi-IP support */
    uint32_t secondary_ips[IPOE_MAX_IPS_PER_MAC - 1];
    uint8_t  num_ips;             /* Number of bound IPs */

    /*========== DHCP State ==========*/
    dhcp_state_t dhcp_state;
    uint32_t dhcp_xid;            /* Transaction ID */
    uint32_t dhcp_server;         /* DHCP server IP */
    uint64_t lease_start;         /* Lease start timestamp (ns) */
    uint32_t lease_duration;      /* Lease time (seconds) */
    uint64_t lease_expire;        /* Expiry timestamp (ns) */
    uint64_t t1_time;             /* Renewal time */
    uint64_t t2_time;             /* Rebind time */

    /*========== AAA State ==========*/
    aaa_state_t aaa_state;
    char     username[IPOE_MAX_USERNAME_LEN];
    char     pool_name[IPOE_MAX_POOL_NAME_LEN];
    uint32_t session_timeout;     /* Max session time (seconds) */
    uint32_t idle_timeout;        /* Inactivity timeout (seconds) */

    /*========== Policy References ==========*/
    uint32_t qos_policy_id;       /* QoS policy index */
    uint32_t acl_id;              /* ACL index */
    uint32_t nat_pool_id;         /* NAT pool index */
    uint32_t rate_limit_up;       /* Upload rate limit (kbps) */
    uint32_t rate_limit_down;     /* Download rate limit (kbps) */

    /*========== Counters ==========*/
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t last_activity;       /* Last packet timestamp (ns) */
    uint64_t session_start;       /* Session creation timestamp (ns) */

    /*========== State & Flags ==========*/
    ipoe_session_state_t state;
    uint8_t  flags;
    ipoe_term_reason_t term_reason;

    /*========== Option 82 ==========*/
    uint8_t  circuit_id[64];
    uint8_t  circuit_id_len;
    uint8_t  remote_id[64];
    uint8_t  remote_id_len;

    /*========== Linkage ==========*/
    struct ipoe_session *next;    /* Hash chain */
} __attribute__((aligned(64)));   /* Cache-line aligned */

/*============================================================================
 * Lookup Key Structures
 *============================================================================*/

struct ipoe_mac_key {
    uint8_t mac[6];
    uint16_t pad;
} __attribute__((packed));

struct ipoe_vlan_mac_key {
    uint8_t  mac[6];
    uint16_t svlan;
    uint16_t cvlan;
    uint16_t pad;
} __attribute__((packed));

/*============================================================================
 * Session Manager Context (Lockless DPDK Architecture)
 *============================================================================*/

struct ipoe_session_mgr {
    /* Session pool (pre-allocated) */
    struct ipoe_session *session_pool;
    uint32_t pool_size;
    uint32_t active_count;

    /*========== Lockless Session Allocation (DPDK) ==========*/
    struct rte_mempool *session_mempool;  /* NUMA-aware session allocation */

    /*========== Per-Worker Event Rings (Lockless) ==========*/
    struct rte_ring *worker_rings[IPOE_MAX_WORKERS];
    uint32_t num_workers;

    /*========== TX Response Ring ==========*/
    struct rte_ring *tx_ring;             /* DHCP responses to TX */
    struct rte_mempool *pkt_mempool;      /* Packet mbuf pool */

    /*========== Lockless Lookup Tables (rte_hash) ==========*/
    struct rte_hash *mac_table;
    struct rte_hash *vlan_mac_table;
    struct rte_hash *ip_table;
    struct rte_hash *xid_table;

    /*========== Per-Worker Statistics (Lockless) ==========*/
    struct {
        uint64_t sessions_created;
        uint64_t sessions_destroyed;
        uint64_t dhcp_rx;
        uint64_t dhcp_tx;
        uint64_t auth_success;
        uint64_t auth_failures;
    } __attribute__((aligned(64))) worker_stats[IPOE_MAX_WORKERS];

    /* Global Statistics (aggregated) */
    uint64_t sessions_created;
    uint64_t sessions_destroyed;
    uint64_t auth_success;
    uint64_t auth_failures;
    uint64_t dhcp_discovers;
    uint64_t dhcp_offers;
    uint64_t dhcp_acks;
    uint64_t dhcp_naks;

    /* Configuration */
    uint8_t  mode;                /* L2, L3, or auto */
    bool     mac_auth_enabled;
    bool     anti_spoof_enabled;
    bool     multi_ip_enabled;
    uint32_t default_lease_time;
    uint32_t default_session_timeout;
    uint32_t default_idle_timeout;
};

/*============================================================================
 * Session Management API
 *============================================================================*/

/* Initialization */
int ipoe_session_mgr_init(uint32_t max_sessions);
void ipoe_session_mgr_cleanup(void);

/* Session lifecycle */
struct ipoe_session *ipoe_session_create(const uint8_t *mac, uint16_t svlan, uint16_t cvlan);
int ipoe_session_destroy(struct ipoe_session *sess, ipoe_term_reason_t reason);
void ipoe_session_update_state(struct ipoe_session *sess, ipoe_session_state_t new_state);

/* Lookup functions */
struct ipoe_session *ipoe_session_find_by_mac(const uint8_t *mac);
struct ipoe_session *ipoe_session_find_by_vlan_mac(uint16_t svlan, uint16_t cvlan, const uint8_t *mac);
struct ipoe_session *ipoe_session_find_by_ip(uint32_t ip);
struct ipoe_session *ipoe_session_find_by_xid(uint32_t xid);
struct ipoe_session *ipoe_session_find_by_id(uint32_t session_id);

/* IP binding */
int ipoe_session_bind_ip(struct ipoe_session *sess, uint32_t ip);
int ipoe_session_unbind_ip(struct ipoe_session *sess);

/* XID management (temporary DHCP tracking) */
int ipoe_session_set_xid(struct ipoe_session *sess, uint32_t xid);
int ipoe_session_clear_xid(struct ipoe_session *sess);

/* Iteration */
typedef void (*ipoe_session_callback_t)(struct ipoe_session *sess, void *ctx);
void ipoe_session_iterate(ipoe_session_callback_t callback, void *ctx);

/* Statistics */
void ipoe_session_get_stats(uint64_t *active, uint64_t *created, uint64_t *destroyed);
void ipoe_session_print_stats(void);

/* Utilities */
const char *ipoe_state_to_string(ipoe_session_state_t state);
const char *ipoe_term_reason_to_string(ipoe_term_reason_t reason);
void ipoe_session_format_mac(const uint8_t *mac, char *buf, size_t len);

#endif /* IPOE_SESSION_H */

/*============================================================================
 * Lockless DPDK API
 *============================================================================*/

#ifdef HAVE_DPDK

/* Lockless initialization */
int ipoe_session_mgr_init_dpdk(uint32_t max_sessions, uint32_t num_workers);

/* Lockless session allocation */
struct ipoe_session *ipoe_session_alloc_lockless(void);
void ipoe_session_free_lockless(struct ipoe_session *sess);

/* Per-worker event rings */
int ipoe_enqueue_dhcp_event(uint32_t worker_id, struct rte_mbuf *mbuf);
struct rte_mbuf *ipoe_dequeue_dhcp_event(uint32_t worker_id);

/* TX ring for DHCP responses */
int ipoe_enqueue_dhcp_response(struct rte_mbuf *mbuf);
uint32_t ipoe_tx_burst(uint16_t port_id, uint16_t queue_id, uint32_t max_burst);

/* Worker management */
void ipoe_set_worker_id(uint32_t worker_id);
void ipoe_aggregate_worker_stats(void);

#endif /* HAVE_DPDK */
