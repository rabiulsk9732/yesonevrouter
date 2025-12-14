/**
 * @file radius_lockless.c
 * @brief Lockless RADIUS Client Implementation for DPDK PPPoE Server
 *
 * Implements the control thread that handles blocking RADIUS I/O
 * while DPDK lcores use lockless rings for communication.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include <rte_common.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>

#include "radius_lockless.h"
#include "log.h"
#include "interface.h"
#include "arp.h"

/* DPDK TX for RADIUS */
static struct rte_mempool *g_radius_pktmbuf_pool = NULL;
static uint16_t g_radius_src_port = 1645; /* Source port for RADIUS packets */

/* Global context */
struct radius_lockless_ctx *g_radius_ll_ctx = NULL;

/* RADIUS packet codes */
#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCOUNTING_REQUEST  4
#define RADIUS_CODE_ACCOUNTING_RESPONSE 5

/* RADIUS attribute types */
#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_SERVICE_TYPE        6
#define RADIUS_ATTR_FRAMED_PROTOCOL     7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS   8
#define RADIUS_ATTR_FRAMED_IP_NETMASK   9
#define RADIUS_ATTR_FRAMED_MTU          12
#define RADIUS_ATTR_REPLY_MESSAGE       18
#define RADIUS_ATTR_SESSION_TIMEOUT     27
#define RADIUS_ATTR_IDLE_TIMEOUT        28
#define RADIUS_ATTR_CALLING_STATION_ID  31
#define RADIUS_ATTR_NAS_IDENTIFIER      32
#define RADIUS_ATTR_CHAP_CHALLENGE      60
#define RADIUS_ATTR_NAS_PORT_TYPE       61

/* Pending request tracking in control thread */
#define MAX_PENDING_REQUESTS 256

struct pending_radius_request {
    bool active;
    uint8_t radius_id;
    uint64_t request_id;
    uint16_t session_id;
    uint64_t send_tsc;
    uint8_t retries;
    uint8_t authenticator[16];
    struct radius_auth_request *orig_request;
};

static struct pending_radius_request g_pending[MAX_PENDING_REQUESTS];
static uint8_t g_next_radius_id = 0;

/* Forward declarations */
static void *radius_control_thread(void *arg);
static int radius_send_access_request(struct radius_auth_request *req);
static void radius_process_response(uint8_t *buf, ssize_t len);
static void radius_check_timeouts(void);
static void compute_md5(const uint8_t *data, size_t len, uint8_t *out);

/*
 * ==========================================================================
 * Initialization
 * ==========================================================================
 */

int radius_lockless_init(int numa_socket)
{
    if (g_radius_ll_ctx) {
        YLOG_WARNING("RADIUS lockless: Already initialized");
        return 0;
    }

    /* Allocate context */
    g_radius_ll_ctx = rte_zmalloc_socket("radius_ll_ctx",
                                          sizeof(struct radius_lockless_ctx),
                                          RTE_CACHE_LINE_SIZE,
                                          numa_socket);
    if (!g_radius_ll_ctx) {
        YLOG_ERROR("RADIUS lockless: Failed to allocate context");
        return -1;
    }

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    /* Initialize atomics */
    rte_atomic64_init(&ctx->next_request_id);
    rte_atomic64_set(&ctx->next_request_id, 1);

    rte_atomic64_init(&ctx->stats.requests_submitted);
    rte_atomic64_init(&ctx->stats.requests_sent);
    rte_atomic64_init(&ctx->stats.responses_received);
    rte_atomic64_init(&ctx->stats.accepts);
    rte_atomic64_init(&ctx->stats.rejects);
    rte_atomic64_init(&ctx->stats.timeouts);
    rte_atomic64_init(&ctx->stats.errors);
    rte_atomic64_init(&ctx->stats.ring_full_drops);

    /* Create DPDK packet mbuf pool for RADIUS TX */
    g_radius_pktmbuf_pool = rte_pktmbuf_pool_create("radius_pkt_pool",
                                                     256, 32, 0,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     numa_socket);
    if (!g_radius_pktmbuf_pool) {
        YLOG_ERROR("RADIUS lockless: Failed to create packet mbuf pool");
        goto fail;
    }

    /* Create request ring (MPSC - multiple DPDK lcores, single control thread) */
    ctx->request_ring = rte_ring_create("radius_req_ring",
                                         RADIUS_REQUEST_RING_SIZE,
                                         numa_socket,
                                         RING_F_SC_DEQ); /* Single consumer */
    if (!ctx->request_ring) {
        YLOG_ERROR("RADIUS lockless: Failed to create request ring");
        goto fail;
    }

    /* Create response ring (SPMC - single control thread producer, multiple lcore consumers) */
    ctx->response_ring = rte_ring_create("radius_resp_ring",
                                          RADIUS_RESPONSE_RING_SIZE,
                                          numa_socket,
                                          RING_F_SP_ENQ); /* Single producer, default multi consumer */
    if (!ctx->response_ring) {
        YLOG_ERROR("RADIUS lockless: Failed to create response ring");
        goto fail;
    }

    /* Create request mempool */
    ctx->req_pool = rte_mempool_create("radius_req_pool",
                                        RADIUS_MEMPOOL_SIZE,
                                        sizeof(struct radius_auth_request),
                                        RADIUS_MEMPOOL_CACHE_SIZE,
                                        0, /* No private data */
                                        NULL, NULL, /* No init */
                                        NULL, NULL, /* No obj init */
                                        numa_socket,
                                        0); /* No flags */
    if (!ctx->req_pool) {
        YLOG_ERROR("RADIUS lockless: Failed to create request mempool");
        goto fail;
    }

    /* Create response mempool */
    ctx->resp_pool = rte_mempool_create("radius_resp_pool",
                                         RADIUS_MEMPOOL_SIZE,
                                         sizeof(struct radius_auth_response),
                                         RADIUS_MEMPOOL_CACHE_SIZE,
                                         0,
                                         NULL, NULL,
                                         NULL, NULL,
                                         numa_socket,
                                         0);
    if (!ctx->resp_pool) {
        YLOG_ERROR("RADIUS lockless: Failed to create response mempool");
        goto fail;
    }

    /* Set defaults */
    ctx->timeout_ms = RADIUS_DEFAULT_TIMEOUT_MS;
    ctx->max_retries = RADIUS_DEFAULT_RETRIES;
    strncpy(ctx->nas_identifier, "yesrouter", sizeof(ctx->nas_identifier) - 1);

    /* Create UDP sockets for RADIUS */
    ctx->auth_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->auth_sock < 0) {
        YLOG_ERROR("RADIUS lockless: Failed to create auth socket: %s", strerror(errno));
        goto fail;
    }

    ctx->acct_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->acct_sock < 0) {
        YLOG_ERROR("RADIUS lockless: Failed to create acct socket: %s", strerror(errno));
        goto fail;
    }

    /* Set socket timeouts for non-blocking behavior in poll */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
    setsockopt(ctx->auth_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Note: Source IP binding done via radius_lockless_bind_source() after config */

    /* Start control thread */
    ctx->running = true;
    ctx->thread_ready = false;

    if (pthread_create(&ctx->control_thread, NULL, radius_control_thread, ctx) != 0) {
        YLOG_ERROR("RADIUS lockless: Failed to create control thread: %s", strerror(errno));
        ctx->running = false;
        goto fail;
    }

    /* Wait for thread to be ready */
    int wait_count = 0;
    while (!ctx->thread_ready && wait_count < 100) {
        usleep(10000); /* 10ms */
        wait_count++;
    }

    if (!ctx->thread_ready) {
        YLOG_ERROR("RADIUS lockless: Control thread failed to start");
        ctx->running = false;
        pthread_join(ctx->control_thread, NULL);
        goto fail;
    }

    YLOG_INFO("RADIUS lockless: Initialized (req_ring=%u, resp_ring=%u, pool=%u)",
              RADIUS_REQUEST_RING_SIZE, RADIUS_RESPONSE_RING_SIZE, RADIUS_MEMPOOL_SIZE);

    return 0;

fail:
    radius_lockless_cleanup();
    return -1;
}

void radius_lockless_cleanup(void)
{
    if (!g_radius_ll_ctx)
        return;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    /* Stop control thread */
    if (ctx->running) {
        ctx->running = false;
        pthread_join(ctx->control_thread, NULL);
    }

    /* Close sockets */
    if (ctx->auth_sock >= 0)
        close(ctx->auth_sock);
    if (ctx->acct_sock >= 0)
        close(ctx->acct_sock);

    /* Free rings and pools */
    if (ctx->request_ring)
        rte_ring_free(ctx->request_ring);
    if (ctx->response_ring)
        rte_ring_free(ctx->response_ring);
    if (ctx->req_pool)
        rte_mempool_free(ctx->req_pool);
    if (ctx->resp_pool)
        rte_mempool_free(ctx->resp_pool);

    rte_free(ctx);
    g_radius_ll_ctx = NULL;

    YLOG_INFO("RADIUS lockless: Cleanup complete");
}

int radius_lockless_bind_source(void)
{
    if (!g_radius_ll_ctx || g_radius_ll_ctx->nas_ip == 0)
        return -1;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = 0, /* Let kernel pick ephemeral port */
        .sin_addr.s_addr = htonl(ctx->nas_ip)
    };

    if (bind(ctx->auth_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        YLOG_ERROR("RADIUS lockless: Failed to bind auth socket to source IP: %s", strerror(errno));
        return -1;
    }

    struct in_addr addr = { .s_addr = htonl(ctx->nas_ip) };
    YLOG_INFO("RADIUS lockless: Auth socket bound to source IP %s", inet_ntoa(addr));
    return 0;
}

int radius_lockless_add_server(uint32_t ip, uint16_t auth_port,
                                uint16_t acct_port, const char *secret,
                                int priority)
{
    if (!g_radius_ll_ctx)
        return -1;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    if (ctx->num_servers >= 4) {
        YLOG_ERROR("RADIUS lockless: Maximum servers reached");
        return -1;
    }

    struct radius_server_config *srv = &ctx->servers[ctx->num_servers];
    srv->ip = ip;
    srv->auth_port = auth_port;
    srv->acct_port = acct_port;
    strncpy(srv->secret, secret, sizeof(srv->secret) - 1);
    srv->priority = priority;
    srv->enabled = true;

    ctx->num_servers++;

    struct in_addr addr = { .s_addr = htonl(ip) };
    YLOG_INFO("RADIUS lockless: Added server %s:%d (priority %d)",
              inet_ntoa(addr), auth_port, priority);

    return ctx->num_servers - 1;
}

void radius_lockless_set_nas(uint32_t nas_ip, const char *nas_identifier)
{
    if (!g_radius_ll_ctx)
        return;

    g_radius_ll_ctx->nas_ip = nas_ip;
    if (nas_identifier)
        strncpy(g_radius_ll_ctx->nas_identifier, nas_identifier,
                sizeof(g_radius_ll_ctx->nas_identifier) - 1);
}

void radius_lockless_set_timeout(uint32_t timeout_ms, uint8_t retries)
{
    if (!g_radius_ll_ctx)
        return;

    g_radius_ll_ctx->timeout_ms = timeout_ms;
    g_radius_ll_ctx->max_retries = retries;
}

/*
 * ==========================================================================
 * DPDK Lcore API (Non-blocking)
 * ==========================================================================
 */

uint64_t radius_lockless_auth_pap(uint16_t session_id,
                                   const char *username,
                                   const char *password,
                                   const struct rte_ether_addr *client_mac,
                                   uint16_t vlan_id,
                                   uint32_t ifindex)
{
    if (!g_radius_ll_ctx || !g_radius_ll_ctx->running)
        return 0;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    /* Allocate request from pool (non-blocking) */
    struct radius_auth_request *req;
    if (rte_mempool_get(ctx->req_pool, (void **)&req) != 0) {
        rte_atomic64_inc(&ctx->stats.ring_full_drops);
        YLOG_WARNING("RADIUS lockless: Request pool exhausted");
        return 0;
    }

    /* Fill request */
    memset(req, 0, sizeof(*req));
    req->request_id = rte_atomic64_add_return(&ctx->next_request_id, 1);
    req->session_id = session_id;
    req->vlan_id = vlan_id;
    req->ifindex = ifindex;
    req->submit_tsc = rte_rdtsc();
    req->auth_type = RADIUS_AUTH_PAP;

    strncpy(req->username, username, sizeof(req->username) - 1);
    strncpy((char *)req->password, password, sizeof(req->password) - 1);
    req->password_len = strlen(password);

    rte_ether_addr_copy(client_mac, &req->client_mac);
    snprintf(req->calling_station_id, sizeof(req->calling_station_id),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             client_mac->addr_bytes[0], client_mac->addr_bytes[1],
             client_mac->addr_bytes[2], client_mac->addr_bytes[3],
             client_mac->addr_bytes[4], client_mac->addr_bytes[5]);

    /* Enqueue to request ring (non-blocking) */
    if (rte_ring_enqueue(ctx->request_ring, req) != 0) {
        rte_mempool_put(ctx->req_pool, req);
        rte_atomic64_inc(&ctx->stats.ring_full_drops);
        YLOG_WARNING("RADIUS lockless: Request ring full");
        return 0;
    }

    rte_atomic64_inc(&ctx->stats.requests_submitted);

    YLOG_DEBUG("RADIUS lockless: PAP auth submitted req_id=%lu session=%u user='%s'",
               req->request_id, session_id, username);

    return req->request_id;
}

uint64_t radius_lockless_auth_chap(uint16_t session_id,
                                    const char *username,
                                    uint8_t chap_id,
                                    const uint8_t *chap_challenge,
                                    uint8_t chap_challenge_len,
                                    const uint8_t *chap_response,
                                    uint8_t chap_response_len,
                                    const struct rte_ether_addr *client_mac,
                                    uint16_t vlan_id,
                                    uint32_t ifindex)
{
    if (!g_radius_ll_ctx || !g_radius_ll_ctx->running)
        return 0;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    /* Allocate request from pool */
    struct radius_auth_request *req;
    if (rte_mempool_get(ctx->req_pool, (void **)&req) != 0) {
        rte_atomic64_inc(&ctx->stats.ring_full_drops);
        YLOG_WARNING("RADIUS lockless: Request pool exhausted");
        return 0;
    }

    /* Fill request */
    memset(req, 0, sizeof(*req));
    req->request_id = rte_atomic64_add_return(&ctx->next_request_id, 1);
    req->session_id = session_id;
    req->vlan_id = vlan_id;
    req->ifindex = ifindex;
    req->submit_tsc = rte_rdtsc();
    req->auth_type = RADIUS_AUTH_CHAP;

    strncpy(req->username, username, sizeof(req->username) - 1);

    /* CHAP password = ID + Response */
    req->chap_id = chap_id;
    if (chap_response_len <= sizeof(req->password)) {
        memcpy(req->password, chap_response, chap_response_len);
        req->password_len = chap_response_len;
    }

    /* CHAP challenge */
    if (chap_challenge_len <= sizeof(req->chap_challenge)) {
        memcpy(req->chap_challenge, chap_challenge, chap_challenge_len);
        req->chap_challenge_len = chap_challenge_len;
    }

    rte_ether_addr_copy(client_mac, &req->client_mac);
    snprintf(req->calling_station_id, sizeof(req->calling_station_id),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             client_mac->addr_bytes[0], client_mac->addr_bytes[1],
             client_mac->addr_bytes[2], client_mac->addr_bytes[3],
             client_mac->addr_bytes[4], client_mac->addr_bytes[5]);

    /* Enqueue to request ring */
    if (rte_ring_enqueue(ctx->request_ring, req) != 0) {
        rte_mempool_put(ctx->req_pool, req);
        rte_atomic64_inc(&ctx->stats.ring_full_drops);
        YLOG_WARNING("RADIUS lockless: Request ring full");
        return 0;
    }

    rte_atomic64_inc(&ctx->stats.requests_submitted);

    YLOG_DEBUG("RADIUS lockless: CHAP auth submitted req_id=%lu session=%u user='%s'",
               req->request_id, session_id, username);

    return req->request_id;
}

unsigned int radius_lockless_poll_responses(
    struct radius_auth_response **responses,
    unsigned int max_responses)
{
    if (!g_radius_ll_ctx)
        return 0;

    return rte_ring_dequeue_burst(g_radius_ll_ctx->response_ring,
                                   (void **)responses,
                                   max_responses,
                                   NULL);
}

void radius_lockless_free_response(struct radius_auth_response *resp)
{
    if (g_radius_ll_ctx && resp)
        rte_mempool_put(g_radius_ll_ctx->resp_pool, resp);
}

/*
 * ==========================================================================
 * Control Thread Implementation
 * ==========================================================================
 */

static void *radius_control_thread(void *arg)
{
    struct radius_lockless_ctx *ctx = (struct radius_lockless_ctx *)arg;
    struct radius_auth_request *req;
    uint8_t recv_buf[4096];

    YLOG_INFO("RADIUS lockless: Control thread started");
    ctx->thread_ready = true;

    /* Set up poll for socket */
    struct pollfd pfd = {
        .fd = ctx->auth_sock,
        .events = POLLIN
    };

    while (ctx->running) {
        /* 1. Dequeue auth requests from ring (non-blocking batch) */
        void *reqs[32];
        unsigned int n_req = rte_ring_dequeue_burst(ctx->request_ring,
                                                     reqs, 32, NULL);

        for (unsigned int i = 0; i < n_req; i++) {
            req = (struct radius_auth_request *)reqs[i];

            /* Send RADIUS Access-Request */
            if (radius_send_access_request(req) == 0) {
                rte_atomic64_inc(&ctx->stats.requests_sent);
            } else {
                /* Send failure - generate error response */
                struct radius_auth_response *resp;
                if (rte_mempool_get(ctx->resp_pool, (void **)&resp) == 0) {
                    memset(resp, 0, sizeof(*resp));
                    resp->request_id = req->request_id;
                    resp->session_id = req->session_id;
                    resp->result = RADIUS_RESULT_ERROR;
                    rte_ether_addr_copy(&req->client_mac, &resp->client_mac);
                    strncpy(resp->reply_message, "RADIUS send failed",
                            sizeof(resp->reply_message) - 1);

                    rte_ring_enqueue(ctx->response_ring, resp);
                    rte_atomic64_inc(&ctx->stats.errors);
                }
                rte_mempool_put(ctx->req_pool, req);
            }
        }

        /* 2. Poll for RADIUS responses */
        int poll_ret = poll(&pfd, 1, RADIUS_THREAD_POLL_MS);
        if (poll_ret > 0 && (pfd.revents & POLLIN)) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);

            ssize_t len = recvfrom(ctx->auth_sock, recv_buf, sizeof(recv_buf), 0,
                                   (struct sockaddr *)&from, &from_len);
            if (len > 0) {
                radius_process_response(recv_buf, len);
            }
        }

        /* 3. Check for timeouts */
        radius_check_timeouts();
    }

    YLOG_INFO("RADIUS lockless: Control thread exiting");
    return NULL;
}

/* Helper: Add attribute to RADIUS packet */
static int radius_add_attr(uint8_t *pkt, int offset, uint8_t type,
                           const uint8_t *data, uint8_t len)
{
    pkt[offset] = type;
    pkt[offset + 1] = len + 2;
    memcpy(&pkt[offset + 2], data, len);
    return offset + len + 2;
}

/* Helper: Encode PAP password per RFC 2865 */
static void encode_pap_password(const char *password, const char *secret,
                                const uint8_t *authenticator,
                                uint8_t *out, int *out_len)
{
    int pass_len = strlen(password);
    int padded_len = ((pass_len + 15) / 16) * 16;
    if (padded_len == 0) padded_len = 16;

    memset(out, 0, padded_len);
    memcpy(out, password, pass_len);

    int secret_len = strlen(secret);
    uint8_t md5_input[256];
    uint8_t md5_hash[16];

    /* First block: MD5(secret + authenticator) */
    memcpy(md5_input, secret, secret_len);
    memcpy(md5_input + secret_len, authenticator, 16);
    compute_md5(md5_input, secret_len + 16, md5_hash);

    for (int i = 0; i < 16; i++)
        out[i] ^= md5_hash[i];

    /* Subsequent blocks */
    for (int i = 16; i < padded_len; i += 16) {
        memcpy(md5_input, secret, secret_len);
        memcpy(md5_input + secret_len, &out[i - 16], 16);
        compute_md5(md5_input, secret_len + 16, md5_hash);

        for (int j = 0; j < 16; j++)
            out[i + j] ^= md5_hash[j];
    }

    *out_len = padded_len;
}

static int radius_send_access_request(struct radius_auth_request *req)
{
    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    if (ctx->num_servers == 0) {
        YLOG_ERROR("RADIUS lockless: No servers configured");
        return -1;
    }

    struct radius_server_config *srv = &ctx->servers[ctx->active_server];

    uint8_t pkt[4096];
    int offset = 20; /* Skip header for now */

    /* Generate authenticator */
    uint8_t authenticator[16];
    for (int i = 0; i < 16; i++)
        authenticator[i] = rand() & 0xFF;

    /* User-Name */
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_USER_NAME,
                              (uint8_t *)req->username, strlen(req->username));

    if (req->auth_type == RADIUS_AUTH_PAP) {
        /* PAP: Encode password */
        uint8_t enc_pass[128];
        int enc_len;
        encode_pap_password((char *)req->password, srv->secret, authenticator,
                            enc_pass, &enc_len);
        offset = radius_add_attr(pkt, offset, RADIUS_ATTR_USER_PASSWORD,
                                  enc_pass, enc_len);
    } else if (req->auth_type == RADIUS_AUTH_CHAP) {
        /* CHAP-Password: ID + Response */
        offset = radius_add_attr(pkt, offset, RADIUS_ATTR_CHAP_PASSWORD,
                                  req->password, req->password_len);

        /* CHAP-Challenge */
        if (req->chap_challenge_len > 0) {
            offset = radius_add_attr(pkt, offset, RADIUS_ATTR_CHAP_CHALLENGE,
                                      req->chap_challenge, req->chap_challenge_len);
        }
    }

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(ctx->nas_ip);
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS,
                              (uint8_t *)&nas_ip, 4);

    /* NAS-Identifier */
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                              (uint8_t *)ctx->nas_identifier,
                              strlen(ctx->nas_identifier));

    /* Calling-Station-Id */
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_CALLING_STATION_ID,
                              (uint8_t *)req->calling_station_id,
                              strlen(req->calling_station_id));

    /* NAS-Port */
    uint32_t nas_port = htonl(req->session_id);
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_NAS_PORT,
                              (uint8_t *)&nas_port, 4);

    /* NAS-Port-Type = Ethernet (15) */
    uint32_t port_type = htonl(15);
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_NAS_PORT_TYPE,
                              (uint8_t *)&port_type, 4);

    /* Service-Type = Framed (2) */
    uint32_t service_type = htonl(2);
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_SERVICE_TYPE,
                              (uint8_t *)&service_type, 4);

    /* Framed-Protocol = PPP (1) */
    uint32_t framed_proto = htonl(1);
    offset = radius_add_attr(pkt, offset, RADIUS_ATTR_FRAMED_PROTOCOL,
                              (uint8_t *)&framed_proto, 4);

    /* Build header */
    uint8_t radius_id = g_next_radius_id++;
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = radius_id;
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;
    memcpy(&pkt[4], authenticator, 16);

    /* Save pending request */
    int pending_idx = radius_id % MAX_PENDING_REQUESTS;
    g_pending[pending_idx].active = true;
    g_pending[pending_idx].radius_id = radius_id;
    g_pending[pending_idx].request_id = req->request_id;
    g_pending[pending_idx].session_id = req->session_id;
    g_pending[pending_idx].send_tsc = rte_rdtsc();
    g_pending[pending_idx].retries = 0;
    memcpy(g_pending[pending_idx].authenticator, authenticator, 16);
    g_pending[pending_idx].orig_request = req;

    /* Send packet via kernel socket */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(srv->auth_port),
        .sin_addr.s_addr = htonl(srv->ip)
    };

    ssize_t sent = sendto(ctx->auth_sock, pkt, offset, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        YLOG_ERROR("RADIUS lockless: sendto failed: %s", strerror(errno));
        g_pending[pending_idx].active = false;
        return -1;
    }

    YLOG_INFO("RADIUS lockless: Sent Access-Request id=%u user='%s' to %s:%d",
              radius_id, req->username, inet_ntoa(dest.sin_addr), srv->auth_port);

    return 0;
}

/* Helper: Verify response authenticator */
static bool verify_response_authenticator(const uint8_t *response, ssize_t len,
                                          const uint8_t *req_auth,
                                          const char *secret)
{
    if (len < 20) return false;

    uint8_t verify_buf[4096];
    memcpy(verify_buf, response, len);
    memcpy(&verify_buf[4], req_auth, 16); /* Replace with request authenticator */

    int secret_len = strlen(secret);
    memcpy(&verify_buf[len], secret, secret_len);

    uint8_t computed[16];
    compute_md5(verify_buf, len + secret_len, computed);

    return memcmp(computed, &response[4], 16) == 0;
}

/* Forward declaration */
static void radius_process_response(uint8_t *buf, ssize_t len);

/* Process RADIUS response received via DPDK RX path */
void radius_lockless_process_dpdk_response(uint8_t *data, uint16_t len)
{
    if (!g_radius_ll_ctx) return;
    YLOG_INFO("RADIUS DPDK RX: Processing response len=%d", len);
    radius_process_response(data, (ssize_t)len);
}

static void radius_process_response(uint8_t *buf, ssize_t len)
{
    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    if (len < 20) {
        YLOG_WARNING("RADIUS lockless: Response too short (%zd bytes)", len);
        return;
    }

    uint8_t code = buf[0];
    uint8_t id = buf[1];

    YLOG_INFO("RADIUS lockless: Received response code=%d id=%d len=%zd", code, id, len);

    /* Find pending request */
    int pending_idx = id % MAX_PENDING_REQUESTS;
    if (!g_pending[pending_idx].active || g_pending[pending_idx].radius_id != id) {
        YLOG_WARNING("RADIUS lockless: Response for unknown request id=%d", id);
        return;
    }

    struct pending_radius_request *pending = &g_pending[pending_idx];
    struct radius_server_config *srv = &ctx->servers[ctx->active_server];

    /* Verify response authenticator */
    if (!verify_response_authenticator(buf, len, pending->authenticator, srv->secret)) {
        YLOG_ERROR("RADIUS lockless: Response authenticator verification failed id=%d", id);
        return;
    }

    rte_atomic64_inc(&ctx->stats.responses_received);

    /* Allocate response object */
    struct radius_auth_response *resp;
    if (rte_mempool_get(ctx->resp_pool, (void **)&resp) != 0) {
        YLOG_ERROR("RADIUS lockless: Response pool exhausted");
        pending->active = false;
        rte_mempool_put(ctx->req_pool, pending->orig_request);
        return;
    }

    memset(resp, 0, sizeof(*resp));
    resp->request_id = pending->request_id;
    resp->session_id = pending->session_id;
    resp->complete_tsc = rte_rdtsc();
    rte_ether_addr_copy(&pending->orig_request->client_mac, &resp->client_mac);

    if (code == RADIUS_CODE_ACCESS_ACCEPT) {
        resp->result = RADIUS_RESULT_ACCEPT;
        rte_atomic64_inc(&ctx->stats.accepts);

        /* Parse attributes */
        int offset = 20;
        while (offset < len) {
            uint8_t attr_type = buf[offset];
            uint8_t attr_len = buf[offset + 1];
            if (attr_len < 2) break;

            uint8_t *attr_val = &buf[offset + 2];
            int val_len = attr_len - 2;

            switch (attr_type) {
                case RADIUS_ATTR_FRAMED_IP_ADDRESS:
                    if (val_len >= 4) {
                        uint32_t ip;
                        memcpy(&ip, attr_val, 4);
                        resp->framed_ip = ntohl(ip);
                    }
                    break;
                case RADIUS_ATTR_FRAMED_IP_NETMASK:
                    if (val_len >= 4) {
                        uint32_t mask;
                        memcpy(&mask, attr_val, 4);
                        resp->framed_netmask = ntohl(mask);
                    }
                    break;
                case RADIUS_ATTR_SESSION_TIMEOUT:
                    if (val_len >= 4) {
                        uint32_t timeout;
                        memcpy(&timeout, attr_val, 4);
                        resp->session_timeout = ntohl(timeout);
                    }
                    break;
                case RADIUS_ATTR_IDLE_TIMEOUT:
                    if (val_len >= 4) {
                        uint32_t timeout;
                        memcpy(&timeout, attr_val, 4);
                        resp->idle_timeout = ntohl(timeout);
                    }
                    break;
                case RADIUS_ATTR_FRAMED_MTU:
                    if (val_len >= 4) {
                        uint32_t mtu;
                        memcpy(&mtu, attr_val, 4);
                        resp->framed_mtu = (uint16_t)ntohl(mtu);
                    }
                    break;
                case RADIUS_ATTR_REPLY_MESSAGE:
                    if (val_len < sizeof(resp->reply_message)) {
                        memcpy(resp->reply_message, attr_val, val_len);
                    }
                    break;
            }
            offset += attr_len;
        }

        YLOG_INFO("RADIUS lockless: Access-Accept session=%u IP=%u.%u.%u.%u",
                  resp->session_id,
                  (resp->framed_ip >> 24) & 0xFF, (resp->framed_ip >> 16) & 0xFF,
                  (resp->framed_ip >> 8) & 0xFF, resp->framed_ip & 0xFF);

    } else if (code == RADIUS_CODE_ACCESS_REJECT) {
        resp->result = RADIUS_RESULT_REJECT;
        rte_atomic64_inc(&ctx->stats.rejects);

        /* Parse Reply-Message if present */
        int offset = 20;
        while (offset < len) {
            uint8_t attr_type = buf[offset];
            uint8_t attr_len = buf[offset + 1];
            if (attr_len < 2) break;

            if (attr_type == RADIUS_ATTR_REPLY_MESSAGE) {
                int val_len = attr_len - 2;
                if (val_len < (int)sizeof(resp->reply_message)) {
                    memcpy(resp->reply_message, &buf[offset + 2], val_len);
                }
                break;
            }
            offset += attr_len;
        }

        YLOG_INFO("RADIUS lockless: Access-Reject session=%u msg='%s'",
                  resp->session_id, resp->reply_message);
    } else {
        resp->result = RADIUS_RESULT_ERROR;
        rte_atomic64_inc(&ctx->stats.errors);
        snprintf(resp->reply_message, sizeof(resp->reply_message),
                 "Unknown RADIUS code %d", code);
    }

    /* Enqueue response to DPDK */
    if (rte_ring_enqueue(ctx->response_ring, resp) != 0) {
        YLOG_ERROR("RADIUS lockless: Response ring full!");
        rte_mempool_put(ctx->resp_pool, resp);
    }

    /* Cleanup pending */
    pending->active = false;
    rte_mempool_put(ctx->req_pool, pending->orig_request);
}

static void radius_check_timeouts(void)
{
    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;
    uint64_t now_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    uint64_t timeout_tsc = (ctx->timeout_ms * hz) / 1000;

    for (int i = 0; i < MAX_PENDING_REQUESTS; i++) {
        if (!g_pending[i].active)
            continue;

        if (now_tsc - g_pending[i].send_tsc > timeout_tsc) {
            struct pending_radius_request *pending = &g_pending[i];

            if (pending->retries < ctx->max_retries) {
                /* Retry */
                pending->retries++;
                YLOG_WARNING("RADIUS lockless: Timeout id=%d, retrying (%d/%d)",
                             pending->radius_id, pending->retries, ctx->max_retries);

                /* Resend - reuse the original request */
                pending->send_tsc = now_tsc;
                radius_send_access_request(pending->orig_request);
            } else {
                /* Max retries - generate timeout response */
                YLOG_ERROR("RADIUS lockless: Request id=%d timed out after %d retries",
                           pending->radius_id, pending->retries);

                struct radius_auth_response *resp;
                if (rte_mempool_get(ctx->resp_pool, (void **)&resp) == 0) {
                    memset(resp, 0, sizeof(*resp));
                    resp->request_id = pending->request_id;
                    resp->session_id = pending->session_id;
                    resp->result = RADIUS_RESULT_TIMEOUT;
                    rte_ether_addr_copy(&pending->orig_request->client_mac,
                                        &resp->client_mac);
                    strncpy(resp->reply_message, "RADIUS timeout",
                            sizeof(resp->reply_message) - 1);
                    resp->complete_tsc = now_tsc;

                    rte_ring_enqueue(ctx->response_ring, resp);
                }

                rte_atomic64_inc(&ctx->stats.timeouts);
                pending->active = false;
                rte_mempool_put(ctx->req_pool, pending->orig_request);
            }
        }
    }
}

/*
 * ==========================================================================
 * Statistics
 * ==========================================================================
 */

void radius_lockless_get_stats(uint64_t *submitted, uint64_t *sent,
                                uint64_t *received, uint64_t *accepts,
                                uint64_t *rejects, uint64_t *timeouts,
                                uint64_t *errors, uint64_t *drops)
{
    if (!g_radius_ll_ctx) return;

    struct radius_lockless_ctx *ctx = g_radius_ll_ctx;

    if (submitted) *submitted = rte_atomic64_read(&ctx->stats.requests_submitted);
    if (sent) *sent = rte_atomic64_read(&ctx->stats.requests_sent);
    if (received) *received = rte_atomic64_read(&ctx->stats.responses_received);
    if (accepts) *accepts = rte_atomic64_read(&ctx->stats.accepts);
    if (rejects) *rejects = rte_atomic64_read(&ctx->stats.rejects);
    if (timeouts) *timeouts = rte_atomic64_read(&ctx->stats.timeouts);
    if (errors) *errors = rte_atomic64_read(&ctx->stats.errors);
    if (drops) *drops = rte_atomic64_read(&ctx->stats.ring_full_drops);
}

void radius_lockless_print_stats(void)
{
    uint64_t submitted, sent, received, accepts, rejects, timeouts, errors, drops;
    radius_lockless_get_stats(&submitted, &sent, &received, &accepts,
                               &rejects, &timeouts, &errors, &drops);

    printf("RADIUS Lockless Statistics:\n");
    printf("  Requests Submitted: %lu\n", submitted);
    printf("  Requests Sent:      %lu\n", sent);
    printf("  Responses Received: %lu\n", received);
    printf("  Access-Accept:      %lu\n", accepts);
    printf("  Access-Reject:      %lu\n", rejects);
    printf("  Timeouts:           %lu\n", timeouts);
    printf("  Errors:             %lu\n", errors);
    printf("  Ring Full Drops:    %lu\n", drops);
}

bool radius_lockless_is_healthy(void)
{
    if (!g_radius_ll_ctx)
        return false;

    return g_radius_ll_ctx->running && g_radius_ll_ctx->thread_ready;
}

/*
 * ==========================================================================
 * MD5 Implementation (using OpenSSL)
 * ==========================================================================
 */

#include <openssl/md5.h>

static void compute_md5(const uint8_t *data, size_t len, uint8_t *out)
{
    MD5(data, len, out);
}
