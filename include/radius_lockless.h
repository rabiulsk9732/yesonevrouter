/**
 * @file radius_lockless.h
 * @brief Lockless RADIUS Client for DPDK PPPoE Server
 *
 * Architecture:
 * - DPDK lcores submit auth requests to lockless ring (non-blocking)
 * - Separate control thread processes RADIUS I/O (blocking OK)
 * - Results returned via lockless response ring
 * - Zero locks in data plane path
 */

#ifndef RADIUS_LOCKLESS_H
#define RADIUS_LOCKLESS_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ring sizes (must be power of 2) */
#define RADIUS_REQUEST_RING_SIZE    4096
#define RADIUS_RESPONSE_RING_SIZE   4096
#define RADIUS_MEMPOOL_SIZE         8192
#define RADIUS_MEMPOOL_CACHE_SIZE   256

/* Timeouts */
#define RADIUS_DEFAULT_TIMEOUT_MS   3000
#define RADIUS_DEFAULT_RETRIES      3
#define RADIUS_THREAD_POLL_MS       10

/* Accounting status types */
#define RADIUS_ACCT_STATUS_START    1
#define RADIUS_ACCT_STATUS_STOP     2
#define RADIUS_ACCT_STATUS_INTERIM  3
#define RADIUS_ACCT_STATUS_ON       7
#define RADIUS_ACCT_STATUS_OFF      8

/* Auth types */
typedef enum {
    RADIUS_AUTH_PAP = 1,
    RADIUS_AUTH_CHAP = 2,
    RADIUS_AUTH_MSCHAP = 3,
    RADIUS_AUTH_MSCHAPV2 = 4
} radius_auth_type_t;

/* Result codes */
typedef enum {
    RADIUS_RESULT_PENDING = 0,
    RADIUS_RESULT_ACCEPT = 1,
    RADIUS_RESULT_REJECT = 2,
    RADIUS_RESULT_TIMEOUT = 3,
    RADIUS_RESULT_ERROR = 4
} radius_result_t;

/**
 * Auth Request Structure (DPDK → Control Thread)
 * Cache-aligned, fixed-size, no pointers
 */
struct radius_auth_request {
    /* Identification */
    uint64_t request_id;            /* Unique request ID */
    uint16_t session_id;            /* PPPoE session ID */
    uint16_t vlan_id;               /* VLAN ID */
    uint32_t nas_port;              /* NAS port number */

    /* Timestamps */
    uint64_t submit_tsc;            /* TSC when submitted */

    /* Auth type and credentials */
    radius_auth_type_t auth_type;

    /* Username (null-terminated) */
    char username[64];

    /* PAP password or CHAP response */
    uint8_t password[64];
    uint8_t password_len;

    /* CHAP specific */
    uint8_t chap_id;
    uint8_t chap_challenge[16];
    uint8_t chap_challenge_len;

    /* Client identification */
    struct rte_ether_addr client_mac;
    uint8_t _pad1[2];

    /* Calling-Station-Id formatted string */
    char calling_station_id[20];    /* "XX:XX:XX:XX:XX:XX" */

    /* Interface info */
    uint32_t ifindex;

    /* Retry tracking */
    uint8_t retry_count;
    uint8_t _pad2[3];

} __rte_cache_aligned;

/**
 * Auth Response Structure (Control Thread → DPDK)
 * Cache-aligned, fixed-size
 */
struct radius_auth_response {
    /* Identification (must match request) */
    uint64_t request_id;
    uint16_t session_id;
    uint16_t vlan_id;

    /* Result */
    radius_result_t result;

    /* Assigned IP (host byte order) */
    uint32_t framed_ip;
    uint32_t framed_netmask;

    /* DNS servers (host byte order) */
    uint32_t dns_primary;
    uint32_t dns_secondary;

    /* Timeouts (seconds) */
    uint32_t session_timeout;
    uint32_t idle_timeout;

    /* Rate limits (bytes per second, 0 = unlimited) */
    uint64_t rate_limit_up;
    uint64_t rate_limit_down;

    /* NAT policy */
    bool use_nat;
    uint8_t _pad1[3];

    /* Framed MTU */
    uint16_t framed_mtu;
    uint16_t _pad2;

    /* Reply message for errors */
    char reply_message[128];

    /* Client MAC (copied from request for lookup) */
    struct rte_ether_addr client_mac;
    uint8_t _pad3[2];

    /* Timestamps */
    uint64_t complete_tsc;

} __rte_cache_aligned;

/**
 * RADIUS Server Configuration
 */
struct radius_server_config {
    uint32_t ip;                    /* Host byte order */
    uint16_t auth_port;
    uint16_t acct_port;
    char secret[64];
    int priority;
    bool enabled;
};

/**
 * Lockless RADIUS Client Context
 */
struct radius_lockless_ctx {
    /* Lockless rings */
    struct rte_ring *request_ring;      /* DPDK → Control thread */
    struct rte_ring *response_ring;     /* Control thread → DPDK */

    /* Memory pool for request/response objects */
    struct rte_mempool *req_pool;
    struct rte_mempool *resp_pool;

    /* Request ID generator (atomic) */
    rte_atomic64_t next_request_id;

    /* Control thread state */
    volatile bool running;
    volatile bool thread_ready;
    pthread_t control_thread;

    /* RADIUS servers */
    struct radius_server_config servers[4];
    int num_servers;
    int active_server;

    /* Configuration */
    uint32_t nas_ip;                    /* NAS-IP-Address (host order) */
    char nas_identifier[64];            /* NAS-Identifier */
    uint32_t timeout_ms;
    uint8_t max_retries;

    /* Statistics (per-thread safe via atomics) */
    struct {
        rte_atomic64_t requests_submitted;
        rte_atomic64_t requests_sent;
        rte_atomic64_t responses_received;
        rte_atomic64_t accepts;
        rte_atomic64_t rejects;
        rte_atomic64_t timeouts;
        rte_atomic64_t errors;
        rte_atomic64_t ring_full_drops;
    } stats;

    /* Socket for RADIUS communication */
    int auth_sock;
    int acct_sock;
};

/* Global context */
extern struct radius_lockless_ctx *g_radius_ll_ctx;

/*
 * ==========================================================================
 * Initialization API
 * ==========================================================================
 */

/**
 * Initialize lockless RADIUS client
 * Creates rings, mempool, starts control thread
 * @param numa_socket NUMA socket for memory allocation
 * @return 0 on success, -1 on error
 */
int radius_lockless_init(int numa_socket);

/**
 * Cleanup lockless RADIUS client
 * Stops control thread, frees resources
 */
void radius_lockless_cleanup(void);

/**
 * Add RADIUS server
 */
int radius_lockless_add_server(uint32_t ip, uint16_t auth_port,
                                uint16_t acct_port, const char *secret,
                                int priority);

/**
 * Set NAS identification
 */
void radius_lockless_set_nas(uint32_t nas_ip, const char *nas_identifier);

/**
 * Set timeouts
 */
void radius_lockless_set_timeout(uint32_t timeout_ms, uint8_t retries);

/**
 * Bind sockets to configured source IP (call after set_nas)
 */
int radius_lockless_bind_source(void);

/*
 * ==========================================================================
 * DPDK Lcore API (Non-blocking, lockless)
 * ==========================================================================
 */

/**
 * Submit PAP auth request (non-blocking)
 * Called from DPDK lcore when PADR received
 *
 * @param session_id PPPoE session ID
 * @param username Username string
 * @param password Password string
 * @param client_mac Client MAC address
 * @param vlan_id VLAN ID
 * @param ifindex Interface index
 * @return request_id on success, 0 on failure (ring full)
 */
uint64_t radius_lockless_auth_pap(uint16_t session_id,
                                   const char *username,
                                   const char *password,
                                   const struct rte_ether_addr *client_mac,
                                   uint16_t vlan_id,
                                   uint32_t ifindex);

/**
 * Submit CHAP auth request (non-blocking)
 *
 * @param session_id PPPoE session ID
 * @param username Username string
 * @param chap_id CHAP identifier
 * @param chap_challenge Challenge value
 * @param chap_challenge_len Challenge length
 * @param chap_response Response value (includes ID prefix)
 * @param chap_response_len Response length
 * @param client_mac Client MAC address
 * @param vlan_id VLAN ID
 * @param ifindex Interface index
 * @return request_id on success, 0 on failure (ring full)
 */
uint64_t radius_lockless_auth_chap(uint16_t session_id,
                                    const char *username,
                                    uint8_t chap_id,
                                    const uint8_t *chap_challenge,
                                    uint8_t chap_challenge_len,
                                    const uint8_t *chap_response,
                                    uint8_t chap_response_len,
                                    const struct rte_ether_addr *client_mac,
                                    uint16_t vlan_id,
                                    uint32_t ifindex);

/**
 * Poll for auth responses (non-blocking)
 * Called from DPDK lcore in main loop
 *
 * @param responses Array to store responses
 * @param max_responses Maximum responses to dequeue
 * @return Number of responses dequeued
 */
unsigned int radius_lockless_poll_responses(
    struct radius_auth_response **responses,
    unsigned int max_responses);

/**
 * Return response object to pool
 * Must be called after processing response
 */
void radius_lockless_free_response(struct radius_auth_response *resp);

/*
 * ==========================================================================
 * Statistics API
 * ==========================================================================
 */

/**
 * Get statistics snapshot
 */
void radius_lockless_get_stats(uint64_t *submitted, uint64_t *sent,
                                uint64_t *received, uint64_t *accepts,
                                uint64_t *rejects, uint64_t *timeouts,
                                uint64_t *errors, uint64_t *drops);

/**
 * Print statistics
 */
void radius_lockless_print_stats(void);

/**
 * Check if control thread is healthy
 */
bool radius_lockless_is_healthy(void);

/*
 * ==========================================================================
 * Accounting API (stub for now - TODO: implement lockless accounting)
 * ==========================================================================
 */

/**
 * Send RADIUS accounting request (stub - does nothing for now)
 */
static inline int radius_acct_request(int status, uint16_t session_id,
                                       const char *username, uint32_t client_ip)
{
    (void)status;
    (void)session_id;
    (void)username;
    (void)client_ip;
    return 0; /* TODO: Implement lockless accounting */
}

#ifdef __cplusplus
}
#endif

#endif /* RADIUS_LOCKLESS_H */
