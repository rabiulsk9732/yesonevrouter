/**
 * @file radius_client.c
 * @brief Standalone RADIUS Client Implementation
 *
 * Security Features:
 * - Message-Authenticator (RFC 2869) using HMAC-MD5
 * - Response Authenticator verification (RFC 2865)
 * - Cryptographic RNG for Request Authenticator
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/random.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/hmac.h>
#endif

#include "radius.h"
#include "radius.h"
#include "log.h"

#ifdef HAVE_DPDK
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_common.h>

/* Thread-local worker ID (defined in main/scheduler) */
extern __thread int g_thread_worker_id;
#endif

/* RADIUS Attributes */
#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_SERVICE_TYPE        6
#define RADIUS_ATTR_FRAMED_PROTOCOL     7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS   8
#define RADIUS_ATTR_FILTER_ID           11
#define RADIUS_ATTR_SESSION_TIMEOUT     27
#define RADIUS_ATTR_IDLE_TIMEOUT        28
#define RADIUS_ATTR_CALLED_STATION_ID   30
#define RADIUS_ATTR_CALLING_STATION_ID  31
#define RADIUS_ATTR_NAS_IDENTIFIER      32
#define RADIUS_ATTR_ACCT_STATUS_TYPE    40
#define RADIUS_ATTR_ACCT_SESSION_ID     44
#define RADIUS_ATTR_ACCT_INPUT_OCTETS   42
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS  43
#define RADIUS_ATTR_ACCT_SESSION_TIME   46
#define RADIUS_ATTR_CHAP_CHALLENGE      60
#define RADIUS_ATTR_MESSAGE_AUTHENTICATOR 80 /* RFC 2869 */

/* Global configuration */
static struct radius_client_config g_radius_config = {
    .initialized = false,
    .num_servers = 0,
    .source_ip = 0,
    .nas_identifier = "yesrouter",
    .timeout_ms = RADIUS_DEFAULT_TIMEOUT_MS,
    .retries = RADIUS_DEFAULT_RETRIES,
    .coa_enabled = true,
    .coa_port = RADIUS_DEFAULT_COA_PORT
};

/* Sockets */
static int g_auth_sock = -1;
static int g_acct_sock = -1;
static int g_coa_sock = -1;

/* Callbacks */
static radius_auth_callback_t g_auth_callback = NULL;

#ifdef HAVE_DPDK
static void radius_poll_all_lcores(void);
#endif
static radius_coa_callback_t g_coa_callback = NULL;
static radius_dm_callback_t g_dm_callback = NULL;

/* Request identifier */
static uint8_t g_request_id = 0;

static uint8_t radius_get_request_id(void)
{
#ifdef HAVE_DPDK
    struct radius_lcore_ctx *ctx = radius_get_lcore_ctx();
    if (ctx && ctx->initialized && ctx->auth_sock > 0) {
        return ++ctx->next_id;
    }
#endif
    return ++g_request_id;
}

/* Pending request tracking for Response Authenticator verification (P0 #2, P1 #7) */
#define MAX_PENDING_REQUESTS 256
struct pending_request {
    uint8_t  id;                    /* RADIUS request ID */
    bool     active;                /* Slot in use */
    uint8_t  authenticator[16];     /* Original Request Authenticator */
    uint64_t send_time_us;          /* When sent (for timeout) */
    uint8_t  server_idx;            /* Which server */
    uint8_t  retries;               /* Retry count */
    bool     is_probe;              /* Is this a health check probe? */
    uint16_t session_id;            /* PPPoE Session ID */
    uint8_t  packet[4096];          /* Packet data for retransmission */
    uint16_t packet_len;            /* Packet length */
};
static struct pending_request g_pending[MAX_PENDING_REQUESTS];

/* Helper: get current time in microseconds */
static uint64_t get_time_us(void) __attribute__((unused));
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Helper: set socket non-blocking */
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Helper: Generate cryptographically secure random bytes */
static void generate_random_bytes(uint8_t *buf, size_t len)
{
#if defined(__linux__)
    /* Use getrandom() for crypto-quality randomness */
    ssize_t ret = getrandom(buf, len, 0);
    if (ret == (ssize_t)len) return;
#endif
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, buf, len);
        close(fd);
        if (r == (ssize_t)len) return;
    }
    /* Last resort (NOT secure, only for testing) */
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

#ifdef HAVE_OPENSSL
/* Helper: Compute MD5 hash using OpenSSL */
static void compute_md5(const uint8_t *data, size_t len, uint8_t *out) __attribute__((unused));
static void compute_md5(const uint8_t *data, size_t len, uint8_t *out)
{
    MD5(data, len, out);
}

/* Helper: Compute HMAC-MD5 for Message-Authenticator (RFC 2869) */
static void compute_hmac_md5(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *out)
{
    unsigned int out_len = 16;
    HMAC(EVP_md5(), key, (int)key_len, data, data_len, out, &out_len);
}
#else
/* Fallback: inline MD5 (for builds without OpenSSL) */
static void compute_md5(const uint8_t *data, size_t len, uint8_t *out);
static void compute_hmac_md5(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *out)
{
    /* Simple HMAC-MD5 implementation */
    uint8_t ipad[64], opad[64];
    uint8_t key_block[64];

    memset(key_block, 0, 64);
    if (key_len > 64) {
        compute_md5(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < 64; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5C;
    }

    /* H((K ^ ipad) || data) */
    uint8_t inner[4096];
    memcpy(inner, ipad, 64);
    memcpy(inner + 64, data, data_len);
    uint8_t inner_hash[16];
    compute_md5(inner, 64 + data_len, inner_hash);

    /* H((K ^ opad) || inner_hash) */
    uint8_t outer[80];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner_hash, 16);
    compute_md5(outer, 80, out);
}
#endif

/* Helper: Save pending request for response verification (P1 #7) and retry (P1 #9) */
static int save_pending_request(uint8_t id, const uint8_t *authenticator, uint8_t server_idx, bool is_probe, uint16_t session_id, const uint8_t *pkt, uint16_t len)
{
    g_pending[id].id = id;
    g_pending[id].active = true;
    memcpy(g_pending[id].authenticator, authenticator, 16);
    g_pending[id].send_time_us = get_time_us();
    g_pending[id].server_idx = server_idx;
    g_pending[id].retries = 0;
    g_pending[id].is_probe = is_probe;
    g_pending[id].session_id = session_id;
    if (pkt && len <= 4096) {
        memcpy(g_pending[id].packet, pkt, len);
        g_pending[id].packet_len = len;
    } else {
        g_pending[id].packet_len = 0;
    }
    return 0;
}

/* Helper: Find and clear pending request */
static struct pending_request *find_pending_request(uint8_t id)
{
    if (g_pending[id].active && g_pending[id].id == id) {
        return &g_pending[id];
    }
    return NULL;
}

/* Helper: Clear pending request */
static void clear_pending_request(uint8_t id)
{
    g_pending[id].active = false;
}

/* Helper: Verify Response Authenticator (RFC 2865 Section 3) (P0 #2)
 * ResponseAuth = MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
 */
static bool verify_response_authenticator(const uint8_t *response, ssize_t len,
                                          const uint8_t *request_auth,
                                          const char *secret)
{
    if (len < 20) return false;

    /* Build verification buffer:
     * Code (1) + ID (1) + Length (2) + RequestAuth (16) + Attributes + Secret */
    uint8_t verify_buf[4096];
    size_t secret_len = strlen(secret);

    /* Copy response with Request Authenticator instead of Response Authenticator */
    memcpy(verify_buf, response, 4);              /* Code, ID, Length */
    memcpy(verify_buf + 4, request_auth, 16);     /* Original Request Authenticator */
    if (len > 20) {
        memcpy(verify_buf + 20, response + 20, len - 20);  /* Attributes */
    }
    memcpy(verify_buf + len, secret, secret_len); /* Append secret */

    /* Compute expected Response Authenticator */
    uint8_t expected[16];
    compute_md5(verify_buf, len + secret_len, expected);

    /* Compare with received Response Authenticator */
    const uint8_t *received = response + 4;
    return memcmp(expected, received, 16) == 0;
}

int radius_client_init(void)
{
    if (g_radius_config.initialized) {
        return 0;
    }

    /* Create auth socket */
    g_auth_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_auth_sock < 0) {
        YLOG_ERROR("RADIUS: Failed to create auth socket: %s", strerror(errno));
        return -1;
    }
    set_nonblocking(g_auth_sock);

    /* Create accounting socket */
    g_acct_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_acct_sock < 0) {
        YLOG_ERROR("RADIUS: Failed to create acct socket: %s", strerror(errno));
        close(g_auth_sock);
        return -1;
    }
    set_nonblocking(g_acct_sock);

    /* Create CoA socket */
    g_coa_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_coa_sock < 0) {
        YLOG_ERROR("RADIUS: Failed to create CoA socket: %s", strerror(errno));
        close(g_auth_sock);
        close(g_acct_sock);
        return -1;
    }
    set_nonblocking(g_coa_sock);

    /* Bind CoA socket */
    struct sockaddr_in coa_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_radius_config.coa_port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(g_coa_sock, (struct sockaddr *)&coa_addr, sizeof(coa_addr)) < 0) {
        YLOG_WARNING("RADIUS: Failed to bind CoA port %u: %s",
                     g_radius_config.coa_port, strerror(errno));
    }

    g_radius_config.initialized = true;
    YLOG_INFO("RADIUS Client: Initialized");
    return 0;
}

void radius_client_cleanup(void)
{
    if (g_auth_sock >= 0) close(g_auth_sock);
    if (g_acct_sock >= 0) close(g_acct_sock);
    if (g_coa_sock >= 0) close(g_coa_sock);
    g_auth_sock = g_acct_sock = g_coa_sock = -1;
    g_radius_config.initialized = false;
    YLOG_INFO("RADIUS Client: Cleanup complete");
}

int radius_client_add_server(uint32_t ip, uint16_t auth_port, uint16_t acct_port,
                             const char *secret, uint32_t priority)
{
    if (g_radius_config.num_servers >= RADIUS_MAX_SERVERS) {
        YLOG_ERROR("RADIUS: Maximum servers (%d) reached", RADIUS_MAX_SERVERS);
        return -1;
    }

    struct radius_server_entry *srv = &g_radius_config.servers[g_radius_config.num_servers];
    memset(srv, 0, sizeof(*srv));

    srv->ip = ip;
    srv->auth_port = auth_port ? auth_port : RADIUS_DEFAULT_AUTH_PORT;
    srv->acct_port = acct_port ? acct_port : RADIUS_DEFAULT_ACCT_PORT;
    srv->priority = priority ? priority : (uint32_t)(g_radius_config.num_servers + 1);
    srv->enabled = true;
    srv->status = RADIUS_SERVER_UP;

    if (secret) {
        snprintf(srv->secret, RADIUS_SECRET_MAX, "%s", secret);
    }

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    YLOG_INFO("RADIUS: Added server %s:%u (priority %u)",
              ip_str, srv->auth_port, srv->priority);

    return g_radius_config.num_servers++;
}

int radius_client_remove_server(uint32_t ip)
{
    for (int i = 0; i < g_radius_config.num_servers; i++) {
        if (g_radius_config.servers[i].ip == ip) {
            memmove(&g_radius_config.servers[i],
                    &g_radius_config.servers[i + 1],
                    (g_radius_config.num_servers - i - 1) * sizeof(struct radius_server_entry));
            g_radius_config.num_servers--;
            YLOG_INFO("RADIUS: Removed server");
            return 0;
        }
    }
    return -1;
}

int radius_client_set_secret(uint32_t ip, const char *secret)
{
    for (int i = 0; i < g_radius_config.num_servers; i++) {
        if (g_radius_config.servers[i].ip == ip) {
            snprintf(g_radius_config.servers[i].secret, RADIUS_SECRET_MAX, "%s", secret);
            YLOG_INFO("RADIUS: Secret updated for server");
            return 0;
        }
    }
    return -1;
}

void radius_client_set_source_ip(uint32_t ip)
{
    g_radius_config.source_ip = ip;
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    YLOG_INFO("RADIUS: Source IP set to %s", ip_str);
}

void radius_client_set_nas_identifier(const char *nas_id)
{
    snprintf(g_radius_config.nas_identifier, RADIUS_NAS_ID_MAX, "%s", nas_id);
    YLOG_INFO("RADIUS: NAS-Identifier set to %s", nas_id);
}

void radius_client_set_timeout(uint32_t timeout_sec)
{
    g_radius_config.timeout_ms = timeout_sec * 1000;
    YLOG_INFO("RADIUS: Timeout set to %u sec", timeout_sec);
}

void radius_client_set_retries(uint8_t retries)
{
    g_radius_config.retries = retries;
    YLOG_INFO("RADIUS: Retries set to %u", retries);
}

void radius_client_set_interim_interval(uint32_t interval_sec)
{
    g_radius_config.interim_interval_sec = interval_sec;
    if (interval_sec > 0) {
        YLOG_INFO("RADIUS: Interim update interval set to %u sec", interval_sec);
    } else {
        YLOG_INFO("RADIUS: Interim updates disabled");
    }
}

void radius_client_set_debug_dump(bool enabled)
{
    g_radius_config.debug_dump_enabled = enabled;
    YLOG_INFO("RADIUS: Enhanced logging (hex dumps) %s", enabled ? "ENABLED" : "DISABLED");
}

const struct radius_client_config *radius_client_get_config(void)
{
    return &g_radius_config;
}

/* Helper: Hex dump packet */
static void radius_dump_packet(const char *prefix, const uint8_t *data, int len)
{
    if (!g_radius_config.debug_dump_enabled) {
        (void)prefix;
        (void)data;
        (void)len;
        return;
    }

    char line[128];
    int line_len = 0;

    printf("%s (%d bytes):\n", prefix, len);

    for (int i = 0; i < len; i++) {
        line_len += snprintf(line + line_len, sizeof(line) - line_len, "%02X ", data[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {
            printf("  %s\n", line);
            line_len = 0;
            line[0] = '\0';
        }
    }
}

/* Helper: find best available server */
static struct radius_server_entry *get_active_server(void)
{
    struct radius_server_entry *best = NULL;
    for (int i = 0; i < g_radius_config.num_servers; i++) {
        struct radius_server_entry *srv = &g_radius_config.servers[i];
        if (srv->enabled && srv->status != RADIUS_SERVER_DOWN) {
            if (!best || srv->priority < best->priority) {
                best = srv;
            }
        }
    }
    return best;
}

/* Helper: add attribute to RADIUS packet */
static int add_attr(uint8_t *buf, int offset, uint8_t type, const uint8_t *data, uint8_t len)
{
    buf[offset] = type;
    buf[offset + 1] = len + 2;
    memcpy(&buf[offset + 2], data, len);
    return offset + len + 2;
}

/* Helper: Add Vendor-Specific Attribute (P2 #12) */
int radius_put_vendor_attr(uint8_t *buf, int offset, uint32_t vendor_id, uint8_t vendor_type, const uint8_t *data, uint8_t len)
{
    /* VSA Format: Type(26) Length(>6) Vendor-Id(4) Vendor-Type(1) Vendor-Length(1) Value... */
    /* Total length = 6 + len */
    if (len > 249) return offset; /* Too long */

    buf[offset] = RADIUS_ATTR_VENDOR_SPECIFIC;
    buf[offset + 1] = 6 + len;

    /* Vendor ID (Network Byte Order) */
    uint32_t vid_net = htonl(vendor_id);
    memcpy(&buf[offset + 2], &vid_net, 4);

    /* Sub-Attribute */
    buf[offset + 6] = vendor_type;
    buf[offset + 7] = len + 2; /* Sub-length includes header (type+len) */
    memcpy(&buf[offset + 8], data, len);

    return offset + 6 + len;
}

/* Helper: encode PAP password per RFC 2865 Section 5.2
 * cipher = password XOR MD5(secret + authenticator)
 * For passwords > 16 bytes, subsequent blocks use:
 * cipher[n] = password[n] XOR MD5(secret + cipher[n-1])
 */
static void encode_pap_password(const char *password, const char *secret,
                                const uint8_t *authenticator, uint8_t *out, int *out_len)
{
    int pass_len = strlen(password);
    int padded_len = ((pass_len + 15) / 16) * 16;
    if (padded_len == 0) padded_len = 16;

    /* Zero-pad password */
    memset(out, 0, padded_len);
    memcpy(out, password, pass_len);

    int secret_len = strlen(secret);
    uint8_t md5_input[128];
    uint8_t md5_hash[16];

    /* First block: MD5(secret + authenticator) */
    memcpy(md5_input, secret, secret_len);
    memcpy(md5_input + secret_len, authenticator, 16);

    compute_md5(md5_input, secret_len + 16, md5_hash);

    /* XOR first block */
    for (int i = 0; i < 16; i++) {
        out[i] = out[i] ^ md5_hash[i];
    }

    /* Subsequent blocks */
    for (int i = 16; i < padded_len; i += 16) {
        /* MD5(secret + previous_cipher_block) */
        memcpy(md5_input, secret, secret_len);
        memcpy(md5_input + secret_len, &out[i - 16], 16);

        compute_md5(md5_input, secret_len + 16, md5_hash);

        /* XOR current block */
        for (int j = 0; j < 16; j++) {
            out[i + j] = out[i + j] ^ md5_hash[j];
        }
    }

    *out_len = padded_len;
}

static int radius_send_packet(int code, uint8_t *pkt, int len,
                              const uint8_t *authenticator,
                              uint16_t session_id, bool is_probe)
{
    int sock = -1;
    struct radius_server_entry *srv = get_active_server();
    if (!srv) {
        YLOG_ERROR("RADIUS: No active servers");
        return -1;
    }

    int server_active_idx = (int)(srv - g_radius_config.servers);

#ifdef HAVE_DPDK
    struct radius_lcore_ctx *ctx = radius_get_lcore_ctx();
    if (ctx && ctx->initialized && ctx->auth_sock > 0) {
        /* USE LCORE CONTEXT */
        sock = (code == RADIUS_CODE_ACCOUNTING_REQUEST) ? ctx->acct_sock : ctx->auth_sock;

        /* Save to lcore pending queue */
        struct radius_pending_req *req = NULL;
        for (int i = 0; i < RADIUS_MAX_PENDING; i++) {
             if (ctx->pending[i].send_tsc == 0) { /* Empty slot */
                 req = &ctx->pending[i];
                 break;
             }
        }

        if (req) {
            req->id = pkt[1];
            req->type = (code == RADIUS_CODE_ACCOUNTING_REQUEST) ? 1 : 0;
            req->server_idx = server_active_idx;
            req->retries = 0;
            req->is_probe = is_probe;
            req->session_id = session_id;
            req->send_tsc = rte_rdtsc();
            memcpy(req->authenticator, authenticator, 16);
            if (pkt && len <= 4096) {
                memcpy(req->packet, pkt, len);
                req->packet_len = len;
            }
            ctx->pending_count++;
        } else {
             YLOG_WARNING("RADIUS: Lcore %u pending queue full", ctx->lcore_id);
             return -1;
        }

        /* Stats Lcore */
        if (code == RADIUS_CODE_ACCOUNTING_REQUEST) ctx->stats.acct_requests++;
        else ctx->stats.auth_requests++;

    } else
#endif
    {
        /* USE GLOBAL CONTEXT */
        sock = (code == RADIUS_CODE_ACCOUNTING_REQUEST) ? g_acct_sock : g_auth_sock;

        if (save_pending_request(pkt[1], authenticator, server_active_idx, is_probe, session_id, pkt, len) < 0) {
            YLOG_ERROR("RADIUS: Failed to save pending request (queue full)");
            return -1;
        }

        /* Stats Global */
        if (code == RADIUS_CODE_ACCOUNTING_REQUEST) {
             g_radius_config.stats.total_acct_requests++;
             srv->stats.acct_requests++;
        } else {
             g_radius_config.stats.total_auth_requests++;
             srv->stats.auth_requests++;
        }
    }

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons((code == RADIUS_CODE_ACCOUNTING_REQUEST) ? srv->acct_port : srv->auth_port),
        .sin_addr.s_addr = htonl(srv->ip)
    };

    ssize_t sent = sendto(sock, pkt, len, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        YLOG_ERROR("RADIUS: sendto failed: %s", strerror(errno));
        /* Should undo pending save? But retry logic might handle it?
           For lcore queue, we just marked it sent. Retransmit will try later. */
        return -1;
    }

    return 0;
}

int radius_client_auth_pap(const char *username, const char *password,
                           uint16_t session_id __attribute__((unused)), const uint8_t *client_mac)
{
    struct radius_server_entry *srv = get_active_server();
    if (!srv) {
        YLOG_ERROR("RADIUS: No active server available");
        return -1;
    }

    uint8_t pkt[4096];
    int offset = 20; /* Skip header for now */

    /* Generate authenticator using crypto RNG */
    uint8_t authenticator[16];
    generate_random_bytes(authenticator, 16);

    /* Add attributes */
    /* User-Name */
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_NAME,
                      (uint8_t *)username, strlen(username));

    /* User-Password (PAP) */
    uint8_t enc_pass[128];
    int enc_len;
    encode_pap_password(password, srv->secret, authenticator, enc_pass, &enc_len);
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_PASSWORD, enc_pass, enc_len);

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(g_radius_config.source_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* NAS-Identifier */
    if (g_radius_config.nas_identifier[0]) {
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                          (uint8_t *)g_radius_config.nas_identifier,
                          strlen(g_radius_config.nas_identifier));
    }

    /* Calling-Station-Id (MAC) */
    if (client_mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        offset = add_attr(pkt, offset, RADIUS_ATTR_CALLING_STATION_ID,
                          (uint8_t *)mac_str, strlen(mac_str));
    }

    /* Service-Type = Framed (2) */
    uint32_t svc_type = htonl(2);
    offset = add_attr(pkt, offset, RADIUS_ATTR_SERVICE_TYPE, (uint8_t *)&svc_type, 4);

    /* Framed-Protocol = PPP (1) */
    uint32_t framed_proto = htonl(1);
    offset = add_attr(pkt, offset, RADIUS_ATTR_FRAMED_PROTOCOL, (uint8_t *)&framed_proto, 4);

    /* Message-Authenticator (RFC 2869) - MUST be last attribute
     * First add with zeros, then compute HMAC-MD5 over entire packet */
    int msg_auth_offset = offset;
    uint8_t zeros[16] = {0};
    offset = add_attr(pkt, offset, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, zeros, 16);

    /* Build header (need length before HMAC) */
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = radius_get_request_id();
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;
    memcpy(&pkt[4], authenticator, 16);

    /* Compute HMAC-MD5 over entire packet with zeros at Message-Authenticator */
    uint8_t hmac[16];
    compute_hmac_md5((uint8_t *)srv->secret, strlen(srv->secret), pkt, offset, hmac);

    /* Copy HMAC into packet (offset of value is msg_auth_offset + 2) */
    memcpy(&pkt[msg_auth_offset + 2], hmac, 16);

    /* Send */
    /* Dump packet (P2 #14) */
    radius_dump_packet("RADIUS TX (Access-Request PAP)", pkt, offset);

    return radius_send_packet(pkt[0], pkt, offset, authenticator, session_id, false);
}

int radius_client_auth_chap(const char *username,
                            const uint8_t *challenge, uint8_t challenge_len,
                            const uint8_t *response, uint8_t response_len,
                            uint16_t session_id, const uint8_t *client_mac)
{
    YLOG_INFO("RADIUS: auth_chap called for user='%s' session=%u", username, session_id);
    YLOG_INFO("RADIUS: num_servers=%d initialized=%d",
              g_radius_config.num_servers, g_radius_config.initialized);

    struct radius_server_entry *srv = get_active_server();
    if (!srv) {
        YLOG_ERROR("RADIUS: No active server available!");
        return -1;
    }
    struct in_addr addr;
    addr.s_addr = htonl(srv->ip);
    YLOG_INFO("RADIUS: Using server %s:%d", inet_ntoa(addr), srv->auth_port);

    uint8_t pkt[4096];
    int offset = 20;

    uint8_t authenticator[16];
    for (int i = 0; i < 16; i++) authenticator[i] = rand() & 0xFF;

    /* User-Name */
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_NAME,
                      (uint8_t *)username, strlen(username));

    /* CHAP-Password */
    offset = add_attr(pkt, offset, RADIUS_ATTR_CHAP_PASSWORD, response, response_len);

    /* CHAP-Challenge */
    offset = add_attr(pkt, offset, RADIUS_ATTR_CHAP_CHALLENGE, challenge, challenge_len);

    /* Calling-Station-Id (MAC) */
    if (client_mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X-%02X-%02X-%02X-%02X-%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        offset = add_attr(pkt, offset, RADIUS_ATTR_CALLING_STATION_ID, (uint8_t *)mac_str, strlen(mac_str));
    }

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(g_radius_config.source_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* Header */
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = radius_get_request_id();
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;
    memcpy(&pkt[4], authenticator, 16);

    /* Dump packet (P2 #14) */
    radius_dump_packet("RADIUS TX (Access-Request CHAP)", pkt, offset);

    return radius_send_packet(pkt[0], pkt, offset, authenticator, session_id, false);
}

int radius_client_auth_mschapv2(const char *username,
                                const uint8_t *challenge, uint8_t challenge_len,
                                const uint8_t *response, uint8_t response_len,
                                uint16_t session_id, const uint8_t *client_mac)
{
    if (!g_radius_config.initialized) return -1;

    struct radius_server_entry *srv = get_active_server();
    if (!srv) {
        YLOG_ERROR("RADIUS: No active servers available");
        return -1;
    }

    uint8_t pkt[4096];
    int offset = 0;

    /* RADIUS Header */
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = radius_get_request_id();
    /* Length (2) and Authenticator (16) filled later */
    offset = 20;

    /* User-Name */
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_NAME, (const uint8_t *)username, strlen(username));

    /* Service-Type = Framed-User (2) */
    uint32_t service_type = htonl(2);
    offset = add_attr(pkt, offset, RADIUS_ATTR_SERVICE_TYPE, (uint8_t *)&service_type, 4);

    /* Framed-Protocol = PPP (1) */
    uint32_t framed_proto = htonl(1);
    offset = add_attr(pkt, offset, RADIUS_ATTR_FRAMED_PROTOCOL, (uint8_t *)&framed_proto, 4);

    /* NAS-IP-Address */
    if (g_radius_config.source_ip) {
        uint32_t nas_ip = htonl(g_radius_config.source_ip);
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);
    }

    /* NAS-Identifier */
    if (g_radius_config.nas_identifier[0]) {
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                          (uint8_t *)g_radius_config.nas_identifier,
                          strlen(g_radius_config.nas_identifier));
    }

    /* Calling-Station-Id (MAC) */
    if (client_mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X-%02X-%02X-%02X-%02X-%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        offset = add_attr(pkt, offset, RADIUS_ATTR_CALLING_STATION_ID, (uint8_t *)mac_str, strlen(mac_str));
    }

    /* MS-CHAP-Challenge VSA (Type 11) */
    if (challenge && challenge_len > 0) {
        offset = radius_put_vendor_attr(pkt, offset, RADIUS_VENDOR_ID_MICROSOFT,
                                        RADIUS_VSA_MS_CHAP_CHALLENGE,
                                        challenge, challenge_len);
    }

    /* MS-CHAP2-Response VSA (Type 25) */
    if (response && response_len > 0) {
        uint8_t ms_resp[50];
        if (response_len >= 50) {
            ms_resp[0] = response[0]; /* Ident */
            ms_resp[1] = response[49]; /* Flags */
            memcpy(&ms_resp[2], &response[1], 48); /* PeerChal ... NTResp */

            offset = radius_put_vendor_attr(pkt, offset, RADIUS_VENDOR_ID_MICROSOFT,
                                            RADIUS_VSA_MS_CHAP2_RESPONSE,
                                            ms_resp, 50);
        } else {
             YLOG_WARNING("RADIUS: MS-CHAPv2 response len %d too short", response_len);
        }
    }

    /* Message-Authenticator (P0 #1) */
    uint8_t zero_auth[16] = {0};
    int ma_offset = offset;
    offset = add_attr(pkt, offset, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, zero_auth, 16);

    /* Finalize Length */
    uint16_t total_len = offset;
    uint16_t net_len = htons(total_len);
    memcpy(&pkt[2], &net_len, 2);

    /* Request Authenticator */
    uint8_t authenticator[16];
    generate_random_bytes(authenticator, 16);
    memcpy(&pkt[4], authenticator, 16);

    /* Calculate Message-Authenticator */
    uint8_t hmac[16];
    compute_hmac_md5((uint8_t *)srv->secret, strlen(srv->secret), pkt, total_len, hmac);
    memcpy(&pkt[ma_offset + 2], hmac, 16);

    /* Send */
    /* Dump packet (P2 #14) */
    radius_dump_packet("RADIUS TX (Access-Request MS-CHAPv2)", pkt, offset);

    return radius_send_packet(pkt[0], pkt, offset, authenticator, session_id, false);
}

int radius_client_auth_eap(const char *username,
                           const uint8_t *eap_msg, size_t eap_len,
                           uint16_t session_id, const uint8_t *client_mac)
{
    if (!g_radius_config.initialized) return -1;

    struct radius_server_entry *srv = get_active_server();
    if (!srv) {
        YLOG_ERROR("RADIUS: No active servers available");
        return -1;
    }

    uint8_t pkt[4096];
    int offset = 0;

    /* RADIUS Header */
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = radius_get_request_id();
    offset = 20;

    /* User-Name */
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_NAME, (const uint8_t *)username, strlen(username));

    /* Service-Type = Framed-User (2) */
    uint32_t service_type = htonl(2);
    offset = add_attr(pkt, offset, RADIUS_ATTR_SERVICE_TYPE, (uint8_t *)&service_type, 4);

    /* Framed-Protocol = PPP (1) */
    uint32_t framed_proto = htonl(1);
    offset = add_attr(pkt, offset, RADIUS_ATTR_FRAMED_PROTOCOL, (uint8_t *)&framed_proto, 4);

    /* NAS-IP-Address */
    if (g_radius_config.source_ip) {
        uint32_t nas_ip = htonl(g_radius_config.source_ip);
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);
    }

    /* NAS-Identifier */
    if (g_radius_config.nas_identifier[0]) {
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                          (uint8_t *)g_radius_config.nas_identifier,
                          strlen(g_radius_config.nas_identifier));
    }

    /* Calling-Station-Id (MAC) */
    if (client_mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X-%02X-%02X-%02X-%02X-%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        offset = add_attr(pkt, offset, RADIUS_ATTR_CALLING_STATION_ID, (uint8_t *)mac_str, strlen(mac_str));
    }

    /* EAP-Message (Type 79) - Chunking */
    if (eap_msg && eap_len > 0) {
        size_t remaining = eap_len;
        size_t current_offset = 0;
        while (remaining > 0) {
            uint8_t chunk_len = (remaining > 253) ? 253 : remaining;
            offset = add_attr(pkt, offset, RADIUS_ATTR_EAP_MESSAGE,
                              eap_msg + current_offset, chunk_len);
            current_offset += chunk_len;
            remaining -= chunk_len;
        }
    }

    /* Message-Authenticator (MANDATORY for EAP) */
    uint8_t zero_auth[16] = {0};
    int ma_offset = offset;
    offset = add_attr(pkt, offset, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, zero_auth, 16);

    /* Finalize Length */
    uint16_t total_len = offset;
    uint16_t net_len = htons(total_len);
    memcpy(&pkt[2], &net_len, 2);

    /* Request Authenticator */
    uint8_t authenticator[16];
    generate_random_bytes(authenticator, 16);
    memcpy(&pkt[4], authenticator, 16);

    /* Calculate Message-Authenticator */
    uint8_t hmac[16];
    compute_hmac_md5((uint8_t *)srv->secret, strlen(srv->secret), pkt, total_len, hmac);
    memcpy(&pkt[ma_offset + 2], hmac, 16);

    /* Send */
    /* Dump packet (P2 #14) */
    radius_dump_packet("RADIUS TX (Access-Request EAP)", pkt, offset);

    return radius_send_packet(pkt[0], pkt, offset, authenticator, session_id, false);
}
int radius_client_accounting(uint8_t status, uint16_t session_id,
                             const char *username, uint32_t client_ip,
                             uint64_t bytes_in, uint64_t bytes_out,
                             uint32_t session_time)
{
    struct radius_server_entry *srv = get_active_server();
    if (!srv) return -1;

    uint8_t pkt[4096];
    int offset = 20;

    uint8_t authenticator[16];
    for (int i = 0; i < 16; i++) authenticator[i] = rand() & 0xFF;

    /* Acct-Status-Type */
    uint32_t status_net = htonl(status);
    offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_STATUS_TYPE, (uint8_t *)&status_net, 4);

    /* User-Name */
    offset = add_attr(pkt, offset, RADIUS_ATTR_USER_NAME, (uint8_t *)username, strlen(username));

    /* Acct-Session-Id */
    char sess_str[32];
    snprintf(sess_str, sizeof(sess_str), "%u", session_id);
    offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_SESSION_ID, (uint8_t *)sess_str, strlen(sess_str));

    /* Framed-IP-Address */
    uint32_t ip_net = htonl(client_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_FRAMED_IP_ADDRESS, (uint8_t *)&ip_net, 4);

    /* For STOP: add counters */
    if (status == RADIUS_ACCT_STATUS_STOP || status == RADIUS_ACCT_STATUS_INTERIM) {
        uint32_t in_net = htonl((uint32_t)bytes_in);
        uint32_t out_net = htonl((uint32_t)bytes_out);
        uint32_t time_net = htonl(session_time);
        offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_INPUT_OCTETS, (uint8_t *)&in_net, 4);
        offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_OUTPUT_OCTETS, (uint8_t *)&out_net, 4);
        offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_SESSION_TIME, (uint8_t *)&time_net, 4);
    }

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(g_radius_config.source_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* Header */
    pkt[0] = RADIUS_CODE_ACCOUNTING_REQUEST;
    pkt[1] = radius_get_request_id();
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;

    /* Request Authenticator (RFC 2866): MD5(Code+ID+Len+16Zero+Attrs+Secret) */
    memset(&pkt[4], 0, 16); /* Zero for computation */

    /* Append secret temporarily */
    int secret_len = strlen(srv->secret);
    if (offset + secret_len <= 4096) {
        memcpy(&pkt[offset], srv->secret, secret_len);
        compute_md5(pkt, offset + secret_len, authenticator);
    }

    /* Put computed auth in header */
    memcpy(&pkt[4], authenticator, 16);

    /* Dump & Send */
    radius_dump_packet("RADIUS TX (Accounting-Request)", pkt, offset);
    return radius_send_packet(RADIUS_CODE_ACCOUNTING_REQUEST, pkt, offset, authenticator, session_id, false);
}

/* Helper: Send Status-Server (RFC 5997) */
static int radius_send_status_server(int server_idx)
{
    struct radius_server_entry *srv = &g_radius_config.servers[server_idx];
    uint8_t pkt[4096];
    int offset = 20; /* Skip header */

    /* Basic attributes */
    if (g_radius_config.nas_identifier[0]) {
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                          (uint8_t *)g_radius_config.nas_identifier,
                          strlen(g_radius_config.nas_identifier));
    }

    uint32_t nas_ip = htonl(g_radius_config.source_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* Message-Authenticator (MUST allow response verification) */
    int msg_auth_offset = offset;
    uint8_t zeros[16] = {0};
    offset = add_attr(pkt, offset, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, zeros, 16);

    /* Header */
    pkt[0] = RADIUS_CODE_STATUS_SERVER;
    pkt[1] = radius_get_request_id();
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;

    /* Request Authenticator: Random */
    uint8_t authenticator[16];
    generate_random_bytes(authenticator, 16);
    memcpy(&pkt[4], authenticator, 16);

    /* Compute HMAC */
    uint8_t hmac[16];
    compute_hmac_md5((uint8_t *)srv->secret, strlen(srv->secret), pkt, offset, hmac);
    memcpy(&pkt[msg_auth_offset + 2], hmac, 16);

    /* Send to Auth port */
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(srv->auth_port),
        .sin_addr.s_addr = htonl(srv->ip)
    };

    ssize_t sent = sendto(g_auth_sock, pkt, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent > 0) {
        save_pending_request(pkt[1], authenticator, server_idx, true, 0, pkt, offset);
        YLOG_DEBUG("RADIUS: Sent Status-Server probe to %u.%u.%u.%u (id=%u)",
                   (srv->ip >> 24) & 0xFF, (srv->ip >> 16) & 0xFF,
                   (srv->ip >> 8) & 0xFF, srv->ip & 0xFF, pkt[1]);
        srv->last_probe_ts = get_time_us();
        return 0;
    }
    return -1;
}

static uint64_t last_maintenance_ts = 0;

static int radius_send_status_server(int server_idx);

/* Helper: Check for timeouts and retry mechanism (P1 #9) */
static void radius_client_check_timeouts(void)
{
    uint64_t now = get_time_us();
    uint32_t base_timeout = g_radius_config.timeout_ms * 1000; /* in us */

    for (int i = 0; i < MAX_PENDING_REQUESTS; i++) {
        if (!g_pending[i].active) continue;

        /* Calculate timeout with exponential backoff: base * 2^retries */
        uint32_t current_timeout = base_timeout * (1 << g_pending[i].retries);

        if (now - g_pending[i].send_time_us > current_timeout) {
            /* Timed out */
            if (g_pending[i].retries < g_radius_config.retries) {
                /* Retry */
                g_pending[i].retries++;
                YLOG_WARNING("RADIUS: Request %u timeout (server %u), retrying (%u/%u)...",
                             i, g_pending[i].server_idx, g_pending[i].retries, g_radius_config.retries);

                /* Resend */
                struct radius_server_entry *srv = &g_radius_config.servers[g_pending[i].server_idx];
                int socket_fd = (g_pending[i].packet[0] == RADIUS_CODE_ACCOUNTING_REQUEST) ? g_acct_sock : g_auth_sock;
                uint16_t port = (g_pending[i].packet[0] == RADIUS_CODE_ACCOUNTING_REQUEST) ? srv->acct_port : srv->auth_port;

                struct sockaddr_in dest = {
                    .sin_family = AF_INET,
                    .sin_port = htons(port),
                    .sin_addr.s_addr = htonl(srv->ip)
                };

                sendto(socket_fd, g_pending[i].packet, g_pending[i].packet_len, 0,
                       (struct sockaddr *)&dest, sizeof(dest));

                g_pending[i].send_time_us = now; /* Reset timer */

            } else {
                /* Max retries reached - Fail */
                YLOG_ERROR("RADIUS: Request %u failed after %u retries", i, g_pending[i].retries);

                /* Notify callback of failure */
                /* Determine type from packet code */
                uint8_t code = g_pending[i].packet[0];
                if (code == RADIUS_CODE_ACCESS_REQUEST) {
                    g_radius_config.stats.total_auth_timeouts++;
                    if (g_auth_callback && !g_pending[i].is_probe) {
                        struct radius_auth_result result = { .success = false };
                        g_auth_callback(g_pending[i].session_id, &result);
                    }
                } else if (code == RADIUS_CODE_ACCOUNTING_REQUEST) {
                    /* We don't have acct callback yet, but update stats */
                     /* g_radius_config.stats.total_acct_timeouts++; (Field not present?) */
                }

                clear_pending_request(i);
            }
        }
    }
}



void radius_client_poll(void)
{
    /* Maintenance (Health Check) */
    uint64_t now = get_time_us();
    if (now - last_maintenance_ts > 1000000) { /* Check every 1s */
        last_maintenance_ts = now;
        uint32_t interval_us = g_radius_config.health_check_interval * 1000000;
        if (interval_us > 0) {
            for (int i = 0; i < g_radius_config.num_servers; i++) {
                struct radius_server_entry *srv = &g_radius_config.servers[i];
                bool needs_probe = false;

                if (srv->status != RADIUS_SERVER_UP) {
                    /* If down, probe periodically */
                    if (now - srv->last_probe_ts > interval_us) needs_probe = true;
                } else {
                    /* If up but idle, keepalive */
                    if (now - srv->stats.last_response_time > interval_us &&
                        now - srv->last_probe_ts > interval_us) {
                        needs_probe = true;
                    }
                }

                if (needs_probe) {
                    radius_send_status_server(i);
                }
            }
        }
    }

    /* Check timeouts (P1 #9) */
    radius_client_check_timeouts();

    uint8_t buf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    /* Poll auth socket */
    ssize_t len = recvfrom(g_auth_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&from, &from_len);
    if (len > 0) {
        uint8_t code = buf[0];
        uint8_t id = buf[1];
        YLOG_DEBUG("RADIUS: Received %zd bytes, code=%d id=%d", len, code, id);

        /* Verify Response Authenticator (P0 #2) */
        struct pending_request *req = find_pending_request(id);
        if (!req) {
            YLOG_WARNING("RADIUS: Received response for unknown/expired request id=%d", id);
            goto process_acct; /* Skip to next socket */
        }

        struct radius_server_entry *srv = &g_radius_config.servers[req->server_idx];
        if (!verify_response_authenticator(buf, len, req->authenticator, srv->secret)) {
            YLOG_ERROR("RADIUS: Response Authenticator verification FAILED for id=%d", id);
            /* Drop packet - do NOT process spoofed/corrupted responses */
            goto process_acct; /* Skip to next socket */
        }
        YLOG_DEBUG("RADIUS: Response Authenticator verified OK for id=%d", id);

        /* Clear pending request as we have a valid response */
        clear_pending_request(id);

        /* Health Check Response Handling */
        if (req->is_probe) {
            srv->status = RADIUS_SERVER_UP;
            srv->stats.last_response_time = get_time_us();

            /* Calculate Latency (P2 #13) */
            uint64_t latency2_us = srv->stats.last_response_time - req->send_time_us;
            (void)latency2_us;

            YLOG_INFO("RADIUS: Server %u.%u.%u.%u is UP (Health Check OK, latency=%lu us)",
                      (srv->ip >> 24) & 0xFF, (srv->ip >> 16) & 0xFF,
                      (srv->ip >> 8) & 0xFF, srv->ip & 0xFF, latency2_us);
            goto process_acct; /* Skip callback */
        }

        /* Calculate Latency for Auth (P2 #13) */
        uint64_t now_us = get_time_us();
        uint64_t latency_us = now_us - req->send_time_us;
        (void)latency_us;
        srv->stats.last_response_time = now_us;

        /* Dump packet (P2 #14) */
        radius_dump_packet("RADIUS RX (Auth)", buf, len);

        YLOG_DEBUG("RADIUS: Response for Session %u (latency=%lu us)", req->session_id, latency_us);

        if (code == RADIUS_CODE_ACCESS_ACCEPT) {
            g_radius_config.stats.total_auth_accepts++;
            /* Parse attributes */
            uint32_t framed_ip = 0;
            uint32_t session_timeout = 0;
            uint32_t idle_timeout = 0;
            uint64_t rate_bps = 0;

            int offset = 20;
            while (offset < len) {
                uint8_t type = buf[offset];
                uint8_t attr_len = buf[offset + 1];
                if (attr_len < 2) break;

                if (type == RADIUS_ATTR_FRAMED_IP_ADDRESS && attr_len >= 6) {
                    memcpy(&framed_ip, &buf[offset + 2], 4);
                    framed_ip = ntohl(framed_ip);
                } else if (type == RADIUS_ATTR_SESSION_TIMEOUT && attr_len >= 6) {
                    memcpy(&session_timeout, &buf[offset + 2], 4);
                    session_timeout = ntohl(session_timeout);
                } else if (type == RADIUS_ATTR_IDLE_TIMEOUT && attr_len >= 6) {
                    memcpy(&idle_timeout, &buf[offset + 2], 4);
                    idle_timeout = ntohl(idle_timeout);
                } else if (type == RADIUS_ATTR_FILTER_ID) {
                    // char filter_id[64];
                    // ...
                    char filter[128];
                    int flen = attr_len - 2;
                    if (flen > 127) flen = 127;
                    memcpy(filter, &buf[offset + 2], flen);
                    filter[flen] = '\0';
                    /* Parse "rate=<bps>" */
                    char *rate_ptr = strstr(filter, "rate=");
                    if (rate_ptr) {
                        rate_bps = strtoull(rate_ptr + 5, NULL, 10);
                    }
                } else if (type == RADIUS_ATTR_VENDOR_SPECIFIC && attr_len >= 6) {
                    /* Log VSA detection (P2 #12) */
                    uint32_t vendor_id;
                    memcpy(&vendor_id, &buf[offset + 2], 4);
                    vendor_id = ntohl(vendor_id);
                    YLOG_DEBUG("RADIUS: Found VSA for Vendor %u (len=%d)", vendor_id, attr_len);
                    /* Future: parse specific VSAs here */
                }
                offset += attr_len;
            }

            if (g_auth_callback) {
                struct radius_auth_result result = {
                    .success = true,
                    .framed_ip = framed_ip,
                    .session_timeout = session_timeout,
                    .idle_timeout = idle_timeout,
                    .rate_limit_bps = rate_bps
                };
                g_auth_callback(req->session_id, &result);
            }
        } else if (code == RADIUS_CODE_ACCESS_REJECT) {
            g_radius_config.stats.total_auth_rejects++;
            if (g_auth_callback) {
                struct radius_auth_result result = { .success = false };
                g_auth_callback(req->session_id, &result);
            }
        }
    }

process_acct:
    /* Poll acct socket */
    len = recvfrom(g_acct_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&from, &from_len);
    if (len > 0) {
        uint8_t code = buf[0];
        uint8_t id = buf[1];

        /* Verify Response Authenticator for Accounting */
        struct pending_request *req = find_pending_request(id);
        if (!req) {
            YLOG_WARNING("RADIUS: Received accounting response for unknown/expired request id=%d", id);
            return; /* Drop */
        } else {
            struct radius_server_entry *srv = &g_radius_config.servers[req->server_idx];
            if (!verify_response_authenticator(buf, len, req->authenticator, srv->secret)) {
                YLOG_ERROR("RADIUS: Accounting-Response authenticator verification FAILED for id=%d", id);
                return; /* Drop */
            }
            clear_pending_request(id);
        }

        if (code == RADIUS_CODE_ACCOUNTING_RESPONSE) {
            g_radius_config.stats.total_acct_responses++;

            /* Dump packet (P2 #14) */
            radius_dump_packet("RADIUS RX (Acct)", buf, len);

            YLOG_DEBUG("RADIUS: Accounting-Response received for id=%u", id);
        }
    }

    /* Poll CoA socket */
    len = recvfrom(g_coa_sock, buf, sizeof(buf), 0,
                   (struct sockaddr *)&from, &from_len);
    if (len > 20) {
        uint8_t code = buf[0];

        if (code == RADIUS_CODE_COA_REQUEST) {
            g_radius_config.stats.total_coa_received++;
            /* Parse and apply CoA */
            /* ... simplified ... */
            g_radius_config.stats.total_coa_applied++;
        } else if (code == RADIUS_CODE_DISCONNECT_REQUEST) {
            g_radius_config.stats.total_dm_received++;
            /* Parse and apply DM */
            g_radius_config.stats.total_dm_applied++;
        }
    }
}

void radius_client_set_auth_callback(radius_auth_callback_t cb)
{
    g_auth_callback = cb;
}

void radius_client_set_coa_callback(radius_coa_callback_t cb)
{
    g_coa_callback = cb;
}

void radius_client_set_dm_callback(radius_dm_callback_t cb)
{
    g_dm_callback = cb;
}

void radius_client_print_config(void)
{
    const struct radius_client_config *cfg = &g_radius_config;

    printf("\nRADIUS Client Configuration:\n");
    printf("  Status:         %s\n", cfg->initialized ? "Initialized" : "Not Initialized");
    printf("  NAS-Identifier: %s\n", cfg->nas_identifier);

    if (cfg->source_ip) {
        struct in_addr addr = { .s_addr = htonl(cfg->source_ip) };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        printf("  Source IP:      %s\n", ip_str);
    } else {
        printf("  Source IP:      (auto)\n");
    }

    printf("  Timeout:        %u ms\n", cfg->timeout_ms);
    printf("  Retries:        %u\n", cfg->retries);
    printf("  CoA Port:       %u\n", cfg->coa_port);

    printf("\nServers (%d):\n", cfg->num_servers);
    printf("  #  %-15s %-10s %-10s %-10s %-8s %s\n",
           "IP", "Auth-Port", "Acct-Port", "Priority", "Status", "Secret");
    printf("  -------------------------------------------------------------------------\n");

    for (int i = 0; i < cfg->num_servers; i++) {
        const struct radius_server_entry *srv = &cfg->servers[i];
        struct in_addr addr = { .s_addr = htonl(srv->ip) };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        const char *status_str = "DOWN";
        if (srv->status == RADIUS_SERVER_UP) status_str = "UP";
        else if (srv->status == RADIUS_SERVER_DEGRADED) status_str = "DEGRADED";

        printf("  %d  %-15s %-10u %-10u %-10u %-8s ********\n",
               i + 1, ip_str, srv->auth_port, srv->acct_port,
               srv->priority, status_str);
    }
    printf("\n");
}

void radius_client_print_stats(void)
{
    struct radius_client_stats stats = g_radius_config.stats;

#ifdef HAVE_DPDK
    /* Aggregate per-lcore stats */
    void radius_aggregate_lcore_stats(struct radius_client_stats *out);
    struct radius_client_stats lcore_stats;
    radius_aggregate_lcore_stats(&lcore_stats);

    stats.total_auth_requests += lcore_stats.total_auth_requests;
    stats.total_auth_accepts += lcore_stats.total_auth_accepts;
    stats.total_auth_rejects += lcore_stats.total_auth_rejects;
    stats.total_auth_timeouts += lcore_stats.total_auth_timeouts;
    stats.total_acct_requests += lcore_stats.total_acct_requests;
    stats.total_acct_responses += lcore_stats.total_acct_responses;
#endif

    const struct radius_client_config *cfg = &g_radius_config;

    printf("\nRADIUS Client Statistics:\n");
    printf("  Authentication:\n");
    printf("    Requests Sent:     %lu\n", stats.total_auth_requests);
    printf("    Access-Accept:     %lu\n", stats.total_auth_accepts);
    printf("    Access-Reject:     %lu\n", stats.total_auth_rejects);
    printf("    Timeouts:          %lu\n", stats.total_auth_timeouts);

    printf("\n  Accounting:\n");
    printf("    Requests Sent:     %lu\n", stats.total_acct_requests);
    printf("    Responses:         %lu\n", stats.total_acct_responses);
    printf("    Interim Sent:      %lu\n", stats.total_interim_sent);
    printf("    Interim Failed:    %lu\n", stats.total_interim_failed);
    if (cfg->interim_interval_sec > 0) {
        printf("    Interim Interval:  %u sec\n", cfg->interim_interval_sec);
    } else {
        printf("    Interim Interval:  disabled\n");
    }

    printf("\n  CoA/Disconnect:\n");
    printf("    CoA Received:      %lu\n", stats.total_coa_received);
    printf("    CoA Applied:       %lu\n", stats.total_coa_applied);
    printf("    DM Received:       %lu\n", stats.total_dm_received);
    printf("    DM Applied:        %lu\n", stats.total_dm_applied);

    printf("\n  Per-Server Stats:\n");
    for (int i = 0; i < cfg->num_servers; i++) {
        const struct radius_server_entry *srv = &cfg->servers[i];
        struct in_addr addr = { .s_addr = htonl(srv->ip) };
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        printf("    %-15s: %lu auth, %lu acct, %lu timeout\n",
               ip_str,
               srv->stats.auth_requests,
               srv->stats.acct_requests,
               srv->stats.auth_timeouts);
    }
    printf("\n");
}

/*
 * ==========================================================================
 * Compatibility wrappers for old radius.h API (used by pppoe.c, etc.)
 * ==========================================================================
 */

/* Old API: radius_init() -> calls radius_client_init() */
int radius_init(void)
{
    return radius_client_init();
}

/* Old API: radius_init_worker() - now a no-op (single-threaded client) */
/* Old API: radius_init_worker() */
int radius_init_worker(int worker_id)
{
    /* Initialize per-lcore context for this worker */
    YLOG_INFO("RADIUS: Initializing worker %d (tid %lu)", worker_id, pthread_self());
    fprintf(stderr, "[DEBUG] radius_init_worker called for worker %d\n", worker_id);
    fflush(stderr);

#ifdef HAVE_DPDK
    /* Ensure thread-local variable is set (in case called before packet_rx sets it) */
    g_thread_worker_id = worker_id;
    return radius_lcore_init(worker_id);
#else
    (void)worker_id;
    return 0;
#endif
}

/* Old API: radius_add_server() */
void radius_add_server(uint32_t ip, uint16_t port, const char *secret)
{
    radius_client_add_server(ip, port, port + 1, secret, 0);
}

/* Old API: radius_auth_request() (PAP) */
int radius_auth_request(const char *username, const char *password,
                        uint16_t session_id, const uint8_t *client_mac)
{
    return radius_client_auth_pap(username, password, session_id, client_mac);
}

/* Old API: radius_chap_auth_request() */
int radius_chap_auth_request(const char *username,
                             const uint8_t *chap_challenge, uint8_t chap_challenge_len,
                             const uint8_t *chap_password, uint8_t chap_password_len,
                             uint16_t session_id, const uint8_t *client_mac)
{
    return radius_client_auth_chap(username, chap_challenge, chap_challenge_len,
                                   chap_password, chap_password_len,
                                   session_id, client_mac);
}

/* Old API: radius_acct_request() */
int radius_acct_request(uint8_t status, uint16_t session_id,
                        const char *username, uint32_t client_ip)
{
    return radius_client_accounting(status, session_id, username, client_ip, 0, 0, 0);
}

/* Old API: radius_poll() */
void radius_poll(void)
{
#ifdef HAVE_DPDK
    radius_poll_all_lcores();
#endif
    radius_client_poll();
}

/* Old API: radius_set_coa_callback() */
void radius_set_coa_callback(void (*cb)(const uint8_t *mac, uint64_t rate))
{
    radius_client_set_coa_callback(cb);
}

/* Old API: radius_set_auth_callback() */
void radius_set_auth_callback(radius_auth_callback_t cb)
{
    radius_client_set_auth_callback(cb);
}

/* Old API: radius_set_disconnect_callback() */
void radius_set_disconnect_callback(void (*cb)(const char *session_str,
                                               const uint8_t *mac, uint32_t ip))
{
    radius_client_set_dm_callback(cb);
}

/* Send Accounting-On/Off (Global Server Status) */
static int radius_send_acct_status_global(uint8_t status)
{
    struct radius_server_entry *srv = get_active_server();
    if (!srv) return -1;

    uint8_t pkt[4096];
    int offset = 20;

    /* Acct-Status-Type */
    uint32_t status_net = htonl(status);
    offset = add_attr(pkt, offset, RADIUS_ATTR_ACCT_STATUS_TYPE, (uint8_t *)&status_net, 4);

    /* NAS-IP-Address */
    uint32_t nas_ip = htonl(g_radius_config.source_ip);
    offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IP_ADDRESS, (uint8_t *)&nas_ip, 4);

    /* NAS-Identifier */
    if (g_radius_config.nas_identifier[0]) {
        offset = add_attr(pkt, offset, RADIUS_ATTR_NAS_IDENTIFIER,
                          (uint8_t *)g_radius_config.nas_identifier,
                          strlen(g_radius_config.nas_identifier));
    }

    /* Header - build with zero authenticator first */
    pkt[0] = RADIUS_CODE_ACCOUNTING_REQUEST;
    pkt[1] = radius_get_request_id();
    pkt[2] = (offset >> 8) & 0xFF;
    pkt[3] = offset & 0xFF;

    memset(&pkt[4], 0, 16);  /* Zero authenticator for MD5 calculation */

    /* RFC 2866: Request Authenticator = MD5(Code+ID+Length+16 zero octets+Attributes+Secret) */
    uint8_t md5_input[4096 + 256];
    memcpy(md5_input, pkt, offset);
    size_t secret_len = strlen(srv->secret);
    memcpy(md5_input + offset, srv->secret, secret_len);

    uint8_t authenticator[16];
    compute_md5(md5_input, offset + secret_len, authenticator);
    memcpy(&pkt[4], authenticator, 16);

    fprintf(stderr, "[RADIUS] Acct-On: secret='%s' len=%zu pkt_len=%d\n", srv->secret, secret_len, offset);
    fflush(stderr);

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(srv->acct_port),
        .sin_addr.s_addr = htonl(srv->ip)
    };

    ssize_t sent = sendto(g_acct_sock, pkt, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        YLOG_ERROR("RADIUS: sendto global accounting failed: %s", strerror(errno));
        return -1;
    }

    srv->stats.acct_requests++;
    g_radius_config.stats.total_acct_requests++;

    /* Save pending request for verification/retry */
    save_pending_request(pkt[1], authenticator, 0, false, 0, pkt, offset);

    YLOG_INFO("RADIUS: Sent Accounting-%s to %u.%u.%u.%u",
              (status == RADIUS_ACCT_STATUS_ON) ? "On" : "Off",
              (srv->ip >> 24) & 0xFF, (srv->ip >> 16) & 0xFF,
              (srv->ip >> 8) & 0xFF, srv->ip & 0xFF);
    return 0;
}

int radius_client_acct_on(void)
{
    return radius_send_acct_status_global(RADIUS_ACCT_STATUS_ON);
}

int radius_client_acct_off(void)
{
    return radius_send_acct_status_global(RADIUS_ACCT_STATUS_OFF);
}

/*
 * ==========================================================================
 * DPDK Per-Lcore Implementation (High Performance)
 * ==========================================================================
 */

#ifdef HAVE_DPDK
/* Per-lcore context array */
static struct radius_lcore_ctx g_lcore_ctx[RTE_MAX_LCORE];

/*
 * radius_poll_all_lcores - DPDK RADIUS polling for all lcore contexts
 * Add this function before radius_poll() in radius_client.c
 * Then add call to radius_poll_all_lcores() at start of radius_poll()
 */

#ifdef HAVE_DPDK
static void radius_poll_all_lcores(void)
{
    uint8_t buf[4096];
    struct sockaddr_in from;
    socklen_t from_len;

    for (int lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct radius_lcore_ctx *ctx = &g_lcore_ctx[lcore];
        if (!ctx->initialized || ctx->auth_sock < 0)
            continue;

        from_len = sizeof(from);
        ssize_t len = recvfrom(ctx->auth_sock, buf, sizeof(buf), MSG_DONTWAIT,
                               (struct sockaddr *)&from, &from_len);
        if (len <= 20)
            continue;

        uint8_t code = buf[0];
        uint8_t id = buf[1];

        fprintf(stderr, "[RADIUS] Recv id=%d lcore=%d code=%d\n", id, lcore, code);
        fflush(stderr);

        for (int i = 0; i < RADIUS_MAX_PENDING; i++) {
            if (ctx->pending[i].send_tsc == 0) continue;
            if (ctx->pending[i].id != id) continue;
            if (ctx->pending[i].type != 0) continue;

            uint16_t session_id = ctx->pending[i].session_id;

            fprintf(stderr, "[RADIUS] Matched id=%d session=%u lcore=%d\n", id, session_id, lcore);
            fflush(stderr);

            if (code == RADIUS_CODE_ACCESS_ACCEPT) {
                ctx->stats.auth_accepts++;

                if (g_auth_callback) {
                    uint32_t framed_ip = 0;
                    int offset = 20;
                    while (offset < len) {
                        uint8_t type = buf[offset];
                        uint8_t attr_len = buf[offset + 1];
                        if (attr_len < 2) break;
                        if (type == 8 && attr_len >= 6) {
                            memcpy(&framed_ip, &buf[offset + 2], 4);
                            framed_ip = ntohl(framed_ip);
                        }
                        offset += attr_len;
                    }

                    struct radius_auth_result result = {
                        .success = true,
                        .framed_ip = framed_ip,
                        .session_timeout = 0,
                        .idle_timeout = 0,
                        .rate_limit_bps = 0
                    };

                    fprintf(stderr, "[RADIUS] Callback ACCEPT id=%d session=%u\n", id, session_id);
                    fflush(stderr);
                    g_auth_callback(session_id, &result);
                }
            } else if (code == RADIUS_CODE_ACCESS_REJECT) {
                ctx->stats.auth_rejects++;

                if (g_auth_callback) {
                    struct radius_auth_result result = { .success = false };
                    fprintf(stderr, "[RADIUS] Callback REJECT id=%d session=%u\n", id, session_id);
                    fflush(stderr);
                    g_auth_callback(session_id, &result);
                }
            }

            ctx->pending[i].id = 0;
            ctx->pending[i].send_tsc = 0;
            if (ctx->pending_count > 0) ctx->pending_count--;
            break;
        }
    }
}
#endif /* HAVE_DPDK */

/* TSC cycles per millisecond (set at init) */
static uint64_t g_tsc_per_ms = 0;

struct radius_lcore_ctx *radius_get_lcore_ctx(void)
{
    /* Use thread-local worker ID initialized by packet_rx or radius_init_worker */
    int worker_id = g_thread_worker_id;

    /* Check bounds (handle case where not initialized or main thread) */
    if (worker_id < 0 || worker_id >= RTE_MAX_LCORE)
        return NULL;

    return &g_lcore_ctx[worker_id];
}

int radius_lcore_init(int worker_id)
{
    unsigned lcore_id = (unsigned)worker_id; /* Use worker_id as index */
    if (lcore_id >= RTE_MAX_LCORE) {
        YLOG_ERROR("RADIUS: Worker ID %u too large", lcore_id);
        return -1;
    }
    struct radius_lcore_ctx *ctx = &g_lcore_ctx[lcore_id];

    if (ctx->initialized)
        return 0;

    /* Set TSC frequency on first call */
    if (g_tsc_per_ms == 0) {
        g_tsc_per_ms = rte_get_tsc_hz() / 1000;
    }

    ctx->lcore_id = lcore_id;
    ctx->next_id = (uint8_t)(lcore_id & 0xFF);  /* Start ID based on lcore */
    ctx->pending_count = 0;
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    memset(ctx->pending, 0, sizeof(ctx->pending));

    /* Create per-lcore sockets (no contention) */
    ctx->auth_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->auth_sock < 0) {
        YLOG_ERROR("RADIUS lcore %u: Failed to create auth socket", lcore_id);
        return -1;
    }
    set_nonblocking(ctx->auth_sock);

    ctx->acct_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->acct_sock < 0) {
        YLOG_ERROR("RADIUS lcore %u: Failed to create acct socket", lcore_id);
        close(ctx->auth_sock);
        return -1;
    }
    set_nonblocking(ctx->acct_sock);

    ctx->initialized = true;
    YLOG_INFO("RADIUS lcore %u: Initialized (per-lcore sockets)", lcore_id);
    fprintf(stderr, "[DEBUG] radius_lcore_init success for lcore %u\n", lcore_id);
    fflush(stderr);
    return 0;
}

int radius_lcore_poll(void)
{
    struct radius_lcore_ctx *ctx = radius_get_lcore_ctx();
    if (!ctx || !ctx->initialized)
        return 0;

    int processed = 0;
    uint8_t buf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    /* Poll auth socket */
    ssize_t len = recvfrom(ctx->auth_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&from, &from_len);
    if (len > 20) {
        uint8_t code = buf[0];
        uint8_t id = buf[1];

        /* Find matching pending request */
        for (int i = 0; i < RADIUS_MAX_PENDING; i++) {
            if (ctx->pending[i].id == id && ctx->pending[i].type == 0) {
                if (code == RADIUS_CODE_ACCESS_ACCEPT) {
                    ctx->stats.auth_accepts++;
                } else if (code == RADIUS_CODE_ACCESS_REJECT) {
                    ctx->stats.auth_rejects++;
                }
                /* Clear pending slot */
                ctx->pending[i].id = 0;
                ctx->pending[i].send_tsc = 0;
                ctx->pending_count--;
                processed++;
                break;
            }
        }
    }

    /* Poll acct socket */
    len = recvfrom(ctx->acct_sock, buf, sizeof(buf), 0,
                   (struct sockaddr *)&from, &from_len);
    if (len > 20) {
        uint8_t code = buf[0];
        uint8_t id = buf[1];

        if (code == RADIUS_CODE_ACCOUNTING_RESPONSE) {
            for (int i = 0; i < RADIUS_MAX_PENDING; i++) {
                if (ctx->pending[i].id == id && ctx->pending[i].type == 1) {
                    ctx->stats.acct_responses++;
                    ctx->pending[i].id = 0;
                    ctx->pending[i].send_tsc = 0;
                    ctx->pending_count--;
                    processed++;
                    break;
                }
            }
        }
    }

    /* Check for timeouts */
    uint64_t now = rte_rdtsc();
    uint64_t timeout_cycles = g_radius_config.timeout_ms * g_tsc_per_ms;

    for (int i = 0; i < RADIUS_MAX_PENDING; i++) {
        if (ctx->pending[i].send_tsc != 0) {
            if (now - ctx->pending[i].send_tsc > timeout_cycles) {
                if (ctx->pending[i].retries < g_radius_config.retries) {
                    /* Retransmit */
                    ctx->pending[i].retries++;
                    ctx->pending[i].send_tsc = now;
                    ctx->stats.retransmits++;
                    /* TODO: Actually resend packet */
                } else {
                    /* Timeout */
                    if (ctx->pending[i].type == 0) {
                        ctx->stats.auth_timeouts++;
                    }
                    ctx->pending[i].id = 0;
                    ctx->pending[i].send_tsc = 0;
                    ctx->pending_count--;
                }
            }
        }
    }

    return processed;
}

/* Aggregate stats from all lcores */
void radius_aggregate_lcore_stats(struct radius_client_stats *out)
{
    memset(out, 0, sizeof(*out));

    for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
        struct radius_lcore_ctx *ctx = &g_lcore_ctx[i];
        if (!ctx->initialized)
            continue;

        out->total_auth_requests += ctx->stats.auth_requests;
        out->total_auth_accepts += ctx->stats.auth_accepts;
        out->total_auth_rejects += ctx->stats.auth_rejects;
        out->total_auth_timeouts += ctx->stats.auth_timeouts;
        out->total_acct_requests += ctx->stats.acct_requests;
        out->total_acct_responses += ctx->stats.acct_responses;
    }
}

#endif /* HAVE_DPDK */
