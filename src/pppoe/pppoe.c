/**
 * @file pppoe.c
 * @brief PPPoE Server Implementation
 */

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hash Key: MAC (6) + SessionID (2) = 8 bytes */
struct session_key_id {
    struct rte_ether_addr mac;
    uint16_t session_id;
};
#include <rte_bitmap.h>
#include <rte_jhash.h>

#include "ppp_ipcp.h"
#include "ppp_lcp.h"
#include "pppoe.h"

extern void ppp_lcp_check_timeouts(struct pppoe_session *session);
#include "interface.h"
#include "log.h"
#include "packet.h"
#include "packet_rx.h"
#include "ppp_auth.h"
#include "pppoe_defs.h"
#include "pppoe_tx.h"

/* Forward declarations */
static void log_packet_hex(const char *type, struct pkt_buf *pkt);
static int pppoe_send_pads(struct pppoe_session *session, const uint8_t *host_uniq,
                           uint16_t host_uniq_len, const uint8_t *svc_name_req,
                           uint16_t svc_name_len);
#include "dpdk_init.h"

/* Helper to get DPDK port ID from interface */
static inline uint16_t interface_get_dpdk_port(struct interface *iface)
{
    if (!iface)
        return 0;

    /* For physical interfaces, extract port_id from flags */
    /* High bit (0x80000000) indicates DPDK port, lower bits are port_id */
    if (iface->flags & 0x80000000) {
        return (uint16_t)(iface->flags & 0x7FFFFFFF);
    }

    /* For VLAN sub-interfaces, get port from parent */
    if (iface->type == IF_TYPE_VLAN && iface->config.parent_ifindex > 0) {
        struct interface *parent = interface_find_by_index(iface->config.parent_ifindex);
        if (parent && (parent->flags & 0x80000000)) {
            return (uint16_t)(parent->flags & 0x7FFFFFFF);
        }
    }

    return 0; /* Fallback */
}
#include "ha.h"
#include "qos.h"
#include "radius.h"

/* Global PPPoE configuration/state */
struct pppoe_session *g_pppoe_session_slab = NULL;

/* PADI Rate Limiting (Per-MAC) */
#define MAX_PADI_TRACKERS 4096
struct padi_node {
    struct rte_ether_addr mac;
    struct token_bucket tb;
    uint64_t last_seen;
    bool used;
};
struct padi_node *g_padi_nodes = NULL;
struct rte_hash *g_padi_hash = NULL;
uint32_t g_padi_lru_clock = 0;

/* Multi-Profile: Map Interface/VLAN to Pool */
struct profile_entry {
    char iface_name[32];
    uint16_t vlan_id;
    char pool_name[32];
};
#define MAX_PROFILES 128
static struct profile_entry g_profiles[MAX_PROFILES];
static int g_num_profiles = 0;

static const char *pppoe_get_profile_pool(const char *iface_name, uint16_t vlan_id)
{
    /* 1. Exact Match */
    for (int i = 0; i < g_num_profiles; i++) {
        if (g_profiles[i].vlan_id == vlan_id &&
            strncmp(g_profiles[i].iface_name, iface_name, 32) == 0) {
            return g_profiles[i].pool_name;
        }
    }
    /* 2. Interface Match, VLAN Wildcard (vlan_id=0 in profile) */
    /* Implementation choice: 0 means any? Or specific 0? */
    /* Let's assume exact match only for now as requested. */
    /* Or wildcard if iface_name is "*" */
    return NULL;
}

void pppoe_add_profile(const char *iface_name, uint16_t vlan_id, const char *pool_name)
{
    if (g_num_profiles >= MAX_PROFILES)
        return;
    struct profile_entry *p = &g_profiles[g_num_profiles++];
    strncpy(p->iface_name, iface_name, sizeof(p->iface_name) - 1);
    p->vlan_id = vlan_id;
    strncpy(p->pool_name, pool_name, sizeof(p->pool_name) - 1);
    YLOG_INFO("Added Profile: Iface %s VLAN %u -> Pool %s", iface_name, vlan_id, pool_name);
}

static struct {
    struct rte_hash *session_id_hash;  /* Map {MAC, ID} -> Session Index */
    struct rte_hash *session_ip_hash;  /* Map {IP} -> Session Index */
    struct rte_bitmap *session_bitmap; /* Allocation bitmap */
    uint8_t *bitmap_mem;

    uint16_t next_session_id;
    char service_name[32];
    char ac_name[32];
} g_pppoe_ctx;

/* Global PPP Settings with defaults */
static struct pppoe_global_settings g_pppoe_settings = {.mtu = 1492,
                                                        .mru = 1492,
                                                        .lcp_echo_interval = 30,
                                                        .lcp_echo_failure = 3,
                                                        .idle_timeout = 0,
                                                        .session_timeout = 0,
                                                        .ac_name = "yesrouter",
                                                        .service_name = "yesrouter-pppoe"};

/* Global settings accessor */
struct pppoe_global_settings *pppoe_get_settings(void)
{
    return &g_pppoe_settings;
}

/* Global settings setters */
void pppoe_set_mtu(uint16_t mtu)
{
    g_pppoe_settings.mtu = mtu;
    YLOG_INFO("PPPoE MTU set to %u", mtu);
}

void pppoe_set_mru(uint16_t mru)
{
    g_pppoe_settings.mru = mru;
    YLOG_INFO("PPPoE MRU set to %u", mru);
}

void pppoe_set_lcp_echo_interval(uint16_t seconds)
{
    g_pppoe_settings.lcp_echo_interval = seconds;
    YLOG_INFO("PPPoE LCP Echo Interval set to %u seconds", seconds);
}

void pppoe_set_lcp_echo_failure(uint8_t count)
{
    g_pppoe_settings.lcp_echo_failure = count;
    YLOG_INFO("PPPoE LCP Echo Failure set to %u", count);
}

void pppoe_set_idle_timeout(uint32_t seconds)
{
    g_pppoe_settings.idle_timeout = seconds;
    YLOG_INFO("PPPoE Idle Timeout set to %u seconds", seconds);
}

void pppoe_set_session_timeout(uint32_t seconds)
{
    g_pppoe_settings.session_timeout = seconds;
    YLOG_INFO("PPPoE Session Timeout set to %u seconds", seconds);
}

void pppoe_set_pado_delay(uint16_t delay_ms)
{
    if (delay_ms > 2000)
        delay_ms = 2000; /* Max 2 seconds */
    g_pppoe_settings.pado_delay_ms = delay_ms;
    YLOG_INFO("PPPoE PADO delay set to %u ms", delay_ms);
}

void pppoe_set_padi_rate_limit(uint32_t rate_per_sec)
{
    g_pppoe_settings.padi_rate_limit = rate_per_sec;
    YLOG_INFO("PPPoE PADI rate limit set to %u/sec (0=unlimited)", rate_per_sec);
}

/* Forward declarations */
static void pppoe_auth_callback(uint16_t session_id, const struct radius_auth_result *result);

/**
 * Initialize PPPoE subsystem
 */
/**
 * Initialize PPPoE subsystem
 */
int pppoe_init(void)
{
    memset(&g_pppoe_ctx, 0, sizeof(g_pppoe_ctx));
    g_pppoe_ctx.next_session_id = 1;
    strncpy(g_pppoe_ctx.service_name, "yesrouter-pppoe", sizeof(g_pppoe_ctx.service_name) - 1);
    strncpy(g_pppoe_ctx.ac_name, "yesrouter", sizeof(g_pppoe_ctx.ac_name) - 1);

    /* 1. Allocate Session Slab (Hugepages) */
    YLOG_INFO("Allocating PPPoE Session Slab for %u sessions...", MAX_SESSIONS);
    g_pppoe_session_slab =
        rte_zmalloc("pppoe_slab", sizeof(struct pppoe_session) * MAX_SESSIONS, 64);
    if (!g_pppoe_session_slab) {
        YLOG_ERROR("Failed to allocate PPPoE session slab");
        return -1;
    }

    /* 2. Create Session ID Hash */
    struct rte_hash_parameters id_hash_params = {
        .name = "pppoe_id_hash",
        .entries = MAX_SESSIONS * 2, /* Load factor 0.5 */
        .key_len = sizeof(struct session_key_id),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    g_pppoe_ctx.session_id_hash = rte_hash_create(&id_hash_params);
    if (!g_pppoe_ctx.session_id_hash) {
        YLOG_ERROR("Failed to create Session ID hash");
        return -1;
    }

    /* 3. Create Session IP Hash */
    struct rte_hash_parameters ip_hash_params = {
        .name = "pppoe_ip_hash",
        .entries = MAX_SESSIONS * 2,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    g_pppoe_ctx.session_ip_hash = rte_hash_create(&ip_hash_params);
    if (!g_pppoe_ctx.session_ip_hash) {
        YLOG_ERROR("Failed to create Session IP hash");
        return -1;
    }

    /* 3.5 Create PADI Tracker Hash */
    struct rte_hash_parameters padi_hash_params = {
        .name = "pppoe_padi_hash",
        .entries = MAX_PADI_TRACKERS * 2,
        .key_len = sizeof(struct rte_ether_addr),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    g_padi_hash = rte_hash_create(&padi_hash_params);

    /* Alloc PADI Nodes */
    g_padi_nodes = rte_zmalloc("padi_nodes", sizeof(struct padi_node) * MAX_PADI_TRACKERS, 64);
    if (!g_padi_hash || !g_padi_nodes) {
        YLOG_ERROR("Failed to init PADI tracking");
        return -1;
    }

    /* 4. Initialize Bitmap Allocator */
    uint32_t bmp_bytes = rte_bitmap_get_memory_footprint(MAX_SESSIONS);
    g_pppoe_ctx.bitmap_mem = rte_zmalloc("pppoe_bmp", bmp_bytes, RTE_CACHE_LINE_SIZE);
    if (!g_pppoe_ctx.bitmap_mem)
        return -1;

    g_pppoe_ctx.session_bitmap = rte_bitmap_init(MAX_SESSIONS, g_pppoe_ctx.bitmap_mem, bmp_bytes);
    if (!g_pppoe_ctx.session_bitmap)
        return -1;

    /* Clear bitmap */
    rte_bitmap_reset(g_pppoe_ctx.session_bitmap);

    /* Register Callbacks */
    radius_set_coa_callback(pppoe_update_qos);
    radius_set_auth_callback(pppoe_auth_callback);
    /* Forward declaration for callback */
    void pppoe_disconnect_callback(const char *session_str, const uint8_t *mac, uint32_t ip);
    radius_set_disconnect_callback(pppoe_disconnect_callback);

    YLOG_INFO("PPPoE subsystem initialized (High Performance Mode)");
    return 0;
}

/**
 * Cleanup PPPoE subsystem
 */
void pppoe_cleanup(void)
{
    if (g_pppoe_session_slab) {
        rte_free(g_pppoe_session_slab);
        g_pppoe_session_slab = NULL;
    }
    if (g_pppoe_ctx.session_id_hash)
        rte_hash_free(g_pppoe_ctx.session_id_hash);
    if (g_pppoe_ctx.session_ip_hash)
        rte_hash_free(g_pppoe_ctx.session_ip_hash);
    if (g_pppoe_ctx.bitmap_mem)
        rte_free(g_pppoe_ctx.bitmap_mem);
}

void pppoe_set_ac_name(const char *name)
{
    if (name) {
        strncpy(g_pppoe_ctx.ac_name, name, sizeof(g_pppoe_ctx.ac_name) - 1);
        g_pppoe_ctx.ac_name[sizeof(g_pppoe_ctx.ac_name) - 1] = '\0'; // Ensure null termination
        YLOG_INFO("PPPoE AC-Name set to '%s'", g_pppoe_ctx.ac_name);
    }
}

void pppoe_set_service_name(const char *name)
{
    if (name) {
        strncpy(g_pppoe_ctx.service_name, name, sizeof(g_pppoe_ctx.service_name) - 1);
        g_pppoe_ctx.service_name[sizeof(g_pppoe_ctx.service_name) - 1] =
            '\0'; // Ensure null termination
        YLOG_INFO("PPPoE Service-Name set to '%s'", g_pppoe_ctx.service_name);
    }
}

/**
 * Find session by ID and MAC (O(1))
 */
static struct pppoe_session *pppoe_find_session(uint16_t session_id,
                                                const struct rte_ether_addr *mac);
static struct pppoe_session *pppoe_find_session(uint16_t session_id,
                                                const struct rte_ether_addr *mac)
{
    /* If MAC is NULL, do a linear search by session_id (slower but works for callbacks) */
    if (mac == NULL) {
        if (session_id == 0)
            return NULL;
        /* Linear search through session slab */
        for (uint32_t i = 0; i < MAX_SESSIONS; i++) {
            if (g_pppoe_session_slab[i].session_id == session_id &&
                g_pppoe_session_slab[i].state != PPPOE_STATE_INITIAL &&
                g_pppoe_session_slab[i].state != PPPOE_STATE_TERMINATED) {
                return &g_pppoe_session_slab[i];
            }
        }
        return NULL;
    }

    struct session_key_id key;
    rte_ether_addr_copy(mac, &key.mac);
    key.session_id = session_id;

    uint64_t idx = 0;
    int ret = rte_hash_lookup_data(g_pppoe_ctx.session_id_hash, &key, (void **)&idx);

    if (ret >= 0) {
        return &g_pppoe_session_slab[idx];
    }
    return NULL;
}

struct pppoe_session *pppoe_find_session_by_ip(uint32_t ip)
{
    uint64_t idx = 0;
    int ret = rte_hash_lookup_data(g_pppoe_ctx.session_ip_hash, &ip, (void **)&idx);

    if (ret >= 0) {
        return &g_pppoe_session_slab[idx];
    }
    return NULL;
}

/**
 * Create new session
 */
static struct pppoe_session *pppoe_create_session(const struct rte_ether_addr *mac,
                                                  struct interface *iface, uint16_t vlan_id)
{
    /* 1. Allocate ID (Find free slot) */
    uint16_t id = g_pppoe_ctx.next_session_id;
    uint32_t attempts = 0;

    /* Loop until we find a free bit (0) */
    while (rte_bitmap_get(g_pppoe_ctx.session_bitmap, id)) {
        id++;
        if (id >= MAX_SESSIONS)
            id = 1;
        attempts++;
        if (attempts >= MAX_SESSIONS) {
            YLOG_ERROR("PPPoE: Max sessions reached (%u)", MAX_SESSIONS);
            return NULL;
        }
    }

    /* Mark as used */
    rte_bitmap_set(g_pppoe_ctx.session_bitmap, id);
    g_pppoe_ctx.next_session_id = id + 1;
    if (g_pppoe_ctx.next_session_id >= MAX_SESSIONS)
        g_pppoe_ctx.next_session_id = 1;

    /* 2. Init Slot */
    struct pppoe_session *session = &g_pppoe_session_slab[id];
    memset(session, 0, sizeof(*session)); /* Clear stale data */

    session->session_id = id;
    rte_ether_addr_copy(mac, &session->client_mac);
    session->vlan_id = vlan_id;

    /* Use VLAN sub-interface if vlan_id is set (for automatic VLAN tagging) */
    if (vlan_id > 0) {
        /* Build VLAN interface name: parent.vlan_id (e.g., eth1.100) */
        char vlan_iface_name[64];
        snprintf(vlan_iface_name, sizeof(vlan_iface_name), "%s.%u", iface->name, vlan_id);

        struct interface *vlan_iface = interface_find_by_name(vlan_iface_name);
        if (vlan_iface) {
            session->iface = vlan_iface;
            YLOG_INFO("PPPoE session %u using VLAN interface %s", id, vlan_iface_name);
        } else {
            /* Fallback to physical interface if VLAN interface not found */
            session->iface = iface;
            YLOG_WARNING("PPPoE session %u: VLAN interface %s not found, using %s", id,
                         vlan_iface_name, iface->name);
        }
    } else {
        session->iface = iface;
    }

    /* Profile Lookup */
    const char *pool = pppoe_get_profile_pool(iface->name, vlan_id);
    if (pool) {
        strncpy(session->pool_name, pool, sizeof(session->pool_name) - 1);
    }

    session->state = PPPOE_STATE_INITIAL;
    session->acct_interim_interval = radius_client_get_config()->interim_interval_sec;
    session->created_ts = time(NULL);

    /* 3. Add to ID Hash */
    struct session_key_id key;
    key.session_id = id;
    rte_ether_addr_copy(mac, &key.mac);

    int ret = rte_hash_add_key_data(g_pppoe_ctx.session_id_hash, &key, (void *)(uintptr_t)id);
    if (ret < 0) {
        YLOG_ERROR("PPPoE: Failed to add to ID hash");
        rte_bitmap_clear(g_pppoe_ctx.session_bitmap, id);
        return NULL;
    }

    /* Initialize Subsystems */
    ppp_lcp_init(session);
    ppp_auth_init(session);
    ppp_ipcp_init(session);

    session->acct_interim_interval = 600; /* Default 10 mins */
    qos_tb_init(&session->downlink_tb, 10 * 1000 * 1000 / 8, 1024 * 1024);

    /* HA Sync */
    ha_send_sync(HA_MSG_SESSION_ADD, session->session_id, session->client_mac.addr_bytes, 0,
                 session->state);

    return session;
}

/**
 * Send PADO (Offer) packet
 * FIXED: Uses pppoe_tx_send_discovery() to avoid double VLAN tagging bug
 */
static int pppoe_send_pado(struct interface *iface, const struct rte_ether_addr *dst_mac,
                           const uint8_t *host_uniq, uint16_t host_uniq_len,
                           const uint8_t *svc_name_req, uint16_t svc_name_len, uint16_t vlan_id)
{
    /* Build PPPoE header + tags in temporary buffer */
    uint8_t pppoe_buf[1500];
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)pppoe_buf;
    uint8_t *payload = pppoe_buf + sizeof(struct pppoe_hdr);
    uint16_t payload_len = 0;

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADO;
    pppoe->session_id = 0;

    /* Add AC-Name Tag */
    struct pppoe_tag *tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_AC_NAME);
    tag->length = rte_cpu_to_be_16(strlen(g_pppoe_ctx.ac_name));
    memcpy(tag->value, g_pppoe_ctx.ac_name, strlen(g_pppoe_ctx.ac_name));
    payload += sizeof(struct pppoe_tag) + strlen(g_pppoe_ctx.ac_name);
    payload_len += sizeof(struct pppoe_tag) + strlen(g_pppoe_ctx.ac_name);

    /* Add Service-Name Tag */
    tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_SERVICE_NAME);

    if (svc_name_len > 0 && svc_name_req) {
        /* Echo requested service name */
        tag->length = rte_cpu_to_be_16(svc_name_len);
        memcpy(tag->value, svc_name_req, svc_name_len);
        payload += sizeof(struct pppoe_tag) + svc_name_len;
        payload_len += sizeof(struct pppoe_tag) + svc_name_len;
    } else {
        /* Default Service Name */
        const char *def_svc =
            (g_pppoe_ctx.service_name[0]) ? g_pppoe_ctx.service_name : g_pppoe_ctx.ac_name;
        uint16_t def_len = strlen(def_svc);
        tag->length = rte_cpu_to_be_16(def_len);
        memcpy(tag->value, def_svc, def_len);
        payload += sizeof(struct pppoe_tag) + def_len;
        payload_len += sizeof(struct pppoe_tag) + def_len;
    }

    /* Add Host-Uniq Tag if present in PADI */
    if (host_uniq && host_uniq_len > 0) {
        tag = (struct pppoe_tag *)payload;
        tag->type = rte_cpu_to_be_16(PPPOE_TAG_HOST_UNIQ);
        tag->length = rte_cpu_to_be_16(host_uniq_len);
        memcpy(tag->value, host_uniq, host_uniq_len);
        payload += sizeof(struct pppoe_tag) + host_uniq_len;
        payload_len += sizeof(struct pppoe_tag) + host_uniq_len;
    }

    /* Add AC-Cookie Tag (required by RFC 2516 for stateless discovery) */
    {
#define COOKIE_LENGTH 24
        uint8_t cookie[COOKIE_LENGTH];
        uint32_t ts = (uint32_t)time(NULL);

        /* Simple hash: XOR MAC bytes with interface name and timestamp */
        memset(cookie, 0, COOKIE_LENGTH);
        for (int i = 0; i < 6; i++) {
            cookie[i] = dst_mac->addr_bytes[i] ^ ((ts >> (i * 4)) & 0xFF);
            cookie[i + 6] = dst_mac->addr_bytes[i] ^ iface->mac_addr[i];
        }
        cookie[12] = (ts >> 24) & 0xFF;
        cookie[13] = (ts >> 16) & 0xFF;
        cookie[14] = (ts >> 8) & 0xFF;
        cookie[15] = ts & 0xFF;
        cookie[16] = (vlan_id >> 8) & 0xFF;
        cookie[17] = vlan_id & 0xFF;
        cookie[18] = iface->ifindex & 0xFF;
        cookie[19] = (iface->ifindex >> 8) & 0xFF;
        cookie[20] = 'Y';
        cookie[21] = 'R';
        cookie[22] = 'C';
        cookie[23] = 'K';

        tag = (struct pppoe_tag *)payload;
        tag->type = rte_cpu_to_be_16(PPPOE_TAG_AC_COOKIE);
        tag->length = rte_cpu_to_be_16(COOKIE_LENGTH);
        memcpy(tag->value, cookie, COOKIE_LENGTH);
        payload += sizeof(struct pppoe_tag) + COOKIE_LENGTH;
        payload_len += sizeof(struct pppoe_tag) + COOKIE_LENGTH;
#undef COOKIE_LENGTH
    }

    pppoe->length = rte_cpu_to_be_16(payload_len);

    /* Get DPDK port and queue from interface */
    uint16_t port_id = interface_get_dpdk_port(iface);
    uint16_t queue_id = 0; /* Use queue 0 for control plane */

    YLOG_INFO("[PADO_TX] Sending on port=%u queue=%u vlan=%u (len=%u)", port_id, queue_id, vlan_id,
              (uint16_t)(sizeof(struct pppoe_hdr) + payload_len));

    /* Send using capability-aware TX function (fixes double VLAN tagging bug) */
    return pppoe_tx_send_discovery(port_id, queue_id, dst_mac, iface->mac_addr, vlan_id, pppoe_buf,
                                   sizeof(struct pppoe_hdr) + payload_len);
}

/* Helper to dump packet hex */
static void log_packet_hex(const char *type, struct pkt_buf *pkt)
{
    if (!pkt || !pkt->mbuf)
        return;
    char buf[1024];
    char *ptr = buf;
    uint8_t *data = rte_pktmbuf_mtod(pkt->mbuf, uint8_t *);
    uint16_t len = pkt->len > 64 ? 64 : pkt->len; /* Log first 64 bytes */
    ptr += sprintf(ptr, "PPPoE %s (%u bytes): ", type, pkt->len);
    for (int i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02x ", data[i]);
    }
    YLOG_INFO("%s", buf);
}

/**
 * Send PADS (Session Confirmation) packet
 * FIXED: Uses pppoe_tx_send_discovery() to avoid double VLAN tagging bug
 */
static int pppoe_send_pads(struct pppoe_session *session, const uint8_t *host_uniq,
                           uint16_t host_uniq_len, const uint8_t *svc_name_req,
                           uint16_t svc_name_len)
{
    /* Build PPPoE header + tags in temporary buffer */
    uint8_t pppoe_buf[1500];
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)pppoe_buf;
    uint8_t *payload = pppoe_buf + sizeof(struct pppoe_hdr);
    uint16_t payload_len = 0;

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* Add Service-Name Tag */
    struct pppoe_tag *tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_SERVICE_NAME);

    if (svc_name_len > 0 && svc_name_req) {
        /* Echo requested service name from PADR */
        tag->length = rte_cpu_to_be_16(svc_name_len);
        memcpy(tag->value, svc_name_req, svc_name_len);
        payload += sizeof(struct pppoe_tag) + svc_name_len;
        payload_len += sizeof(struct pppoe_tag) + svc_name_len;
    } else {
        /* Default/Empty Service-Name */
        const char *def_svc = (g_pppoe_ctx.service_name[0])
                                  ? g_pppoe_ctx.service_name
                                  : (g_pppoe_ctx.ac_name[0] ? g_pppoe_ctx.ac_name : NULL);
        if (def_svc) {
            size_t slen = strlen(def_svc);
            tag->length = rte_cpu_to_be_16(slen);
            memcpy(tag->value, def_svc, slen);
            payload += sizeof(struct pppoe_tag) + slen;
            payload_len += sizeof(struct pppoe_tag) + slen;
        } else {
            tag->length = 0;
            payload += sizeof(struct pppoe_tag);
            payload_len += sizeof(struct pppoe_tag);
        }
    }

    /* Add Host-Uniq Tag if present */
    if (host_uniq && host_uniq_len > 0) {
        tag = (struct pppoe_tag *)payload;
        tag->type = rte_cpu_to_be_16(PPPOE_TAG_HOST_UNIQ);
        tag->length = rte_cpu_to_be_16(host_uniq_len);
        memcpy(tag->value, host_uniq, host_uniq_len);
        payload += sizeof(struct pppoe_tag) + host_uniq_len;
        payload_len += sizeof(struct pppoe_tag) + host_uniq_len;
    }

    pppoe->length = rte_cpu_to_be_16(payload_len);

    /* Get DPDK port and queue from interface */
    uint16_t port_id = interface_get_dpdk_port(session->iface);
    uint16_t queue_id = 0; /* Use queue 0 for control plane */

    YLOG_INFO("[PADS_TX] Sending session=%u on port=%u queue=%u vlan=%u (len=%u)",
              session->session_id, port_id, queue_id, session->vlan_id,
              (uint16_t)(sizeof(struct pppoe_hdr) + payload_len));

    /* Send using capability-aware TX function (fixes double VLAN tagging bug) */
    return pppoe_tx_send_discovery(port_id, queue_id, &session->client_mac,
                                   session->iface->mac_addr, session->vlan_id, pppoe_buf,
                                   sizeof(struct pppoe_hdr) + payload_len);
}

/**
 * Send PADT (Terminate Session) packet
 * FIXED: Uses pppoe_tx_send_discovery() to avoid double VLAN tagging bug
 */
int pppoe_send_padt(struct pppoe_session *session)
{
    if (!session || !session->iface)
        return -1;

    /* Build PPPoE header (no payload for PADT) */
    uint8_t pppoe_buf[sizeof(struct pppoe_hdr)];
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)pppoe_buf;

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADT;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);
    pppoe->length = 0; /* No tags for PADT */

    /* Get DPDK port and queue from interface */
    uint16_t port_id = interface_get_dpdk_port(session->iface);
    uint16_t queue_id = 0; /* Use queue 0 for control plane */

    YLOG_INFO("[PADT_TX] Sending session=%u on port=%u queue=%u vlan=%u", session->session_id,
              port_id, queue_id, session->vlan_id);

    /* Send using capability-aware TX function (fixes double VLAN tagging bug) */
    return pppoe_tx_send_discovery(port_id, queue_id, &session->client_mac,
                                   session->iface->mac_addr, session->vlan_id, pppoe_buf,
                                   sizeof(struct pppoe_hdr));
}

int pppoe_send_session_packet(struct pppoe_session *session, struct pkt_buf *pkt)
{
    /* We need to prepend PPPoE and PPP headers */
    /* pkt->data currently points to IP header (or Ethernet header if forwarded?) */
    /* forward_ipv4_packet passes a packet with Ethernet header, but we need to replace it */

    struct rte_mbuf *m = pkt->mbuf;

    /* QoS: Downlink Shaping */
    if (!qos_tb_conform(&session->downlink_tb, m->pkt_len)) {
        /* Drop packet */
        /* YLOG_DEBUG("PPPoE: Session %u rate limited", session->session_id); */
        /* Caller (interface_send?) usually frees if we return error?
           No, interface_send frees on error usually, but here we are before that.
           Wait, if we return -1, who frees?
           The caller of pppoe_send_session_packet is usually the forwarding engine.
           If we return -1, the forwarding engine should handle it.
           But let's look at pppoe_send_session_packet signature.
           It takes pkt_buf.
        */
        return -1; /* Drop */
    }

    /* Calculate required headroom */
    uint16_t pppoe_len = sizeof(struct pppoe_hdr) + 2; /* PPPoE + PPP Proto */

    /* Check if we have enough headroom to just prepend PPPoE/PPP after Ethernet */
    /* But we need to update Ethernet header too */

    /* The packet passed from forward_ipv4_packet has Ethernet header at pkt->data */
    /* We can reuse the Ethernet header space and just expand */

    /* Move Ethernet header back to make room? No, we need to push data */

    /* Let's assume pkt->data points to Ethernet header */
    /* We need to insert PPPoE+PPP between Ethernet and IP */

    /* Current: [Eth][IP...] */
    /* Target:  [Eth][PPPoE][PPP][IP...] */

    /* We need to extend packet start by pppoe_len */
    if (rte_pktmbuf_prepend(m, pppoe_len) == NULL) {
        YLOG_ERROR("Not enough headroom for PPPoE encapsulation");
        return -1;
    }

    /* Now m->data_off is decreased by pppoe_len */
    /* Move Ethernet header to new start */
    struct rte_ether_hdr *new_eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Copy Ethernet header */
    /* Note: forward_ipv4_packet already set src/dst MACs, but for Ethernet forwarding */
    /* We need to fix them for PPPoE */
    rte_ether_addr_copy(&session->client_mac, &new_eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr,
                        &new_eth->src_addr);
    new_eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);

    /* Fill PPPoE Header */
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(new_eth + 1);
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_SESS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* IP packet length is total length - Eth - PPPoE - PPP */
    /* m->data_len includes everything now */
    uint16_t ip_len = m->data_len - sizeof(struct rte_ether_hdr) - sizeof(struct pppoe_hdr) - 2;
    pppoe->length = rte_cpu_to_be_16(ip_len + 2); /* +2 for PPP proto */

    /* Fill PPP Protocol */
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    *proto = rte_cpu_to_be_16(PPP_PROTO_IP);

    /* Update pkt_buf */
    pkt->data = (uint8_t *)new_eth;
    pkt->len = m->data_len;

    /* Send */
    return interface_send(session->iface, pkt);
}

/**
 * Process PPPoE Discovery packet
 */
int pppoe_process_discovery(struct pkt_buf *pkt, struct interface *iface)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    uint16_t vlan_id = 0;
    struct pppoe_hdr *pppoe;

    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xFFF;
        pppoe = (struct pppoe_hdr *)(vlan + 1);
        if (m->data_len <
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr) + sizeof(struct pppoe_hdr))
            return -1;
    } else {
        pppoe = (struct pppoe_hdr *)(eth + 1);
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr))
            return -1;
    }

    if (pppoe->ver != 1 || pppoe->type != 1) {
        return -1;
    }

    /* DEBUG: Log all PPPoE codes received */
    YLOG_INFO("PPPoE RX: code=0x%02x vlan=%u from %02x:%02x:%02x:%02x:%02x:%02x", pppoe->code,
              vlan_id, eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
              eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3], eth->src_addr.addr_bytes[4],
              eth->src_addr.addr_bytes[5]);

    /* Parse Tags to find Host-Uniq and Service-Name */
    uint8_t *payload = (uint8_t *)(pppoe + 1);
    uint16_t len = rte_be_to_cpu_16(pppoe->length);
    uint8_t *host_uniq = NULL;
    uint16_t host_uniq_len = 0;
    uint8_t *svc_name_req = NULL;
    uint16_t svc_name_len = 0;

    uint16_t offset = 0;
    while (offset + sizeof(struct pppoe_tag) <= len) {
        struct pppoe_tag *tag = (struct pppoe_tag *)(payload + offset);
        uint16_t tag_type = rte_be_to_cpu_16(tag->type);
        uint16_t tag_len = rte_be_to_cpu_16(tag->length);

        /* Bounds check: ensure tag value doesn't exceed packet */
        if (offset + sizeof(struct pppoe_tag) + tag_len > len) {
            YLOG_WARNING("PPPoE: Malformed tag (type=0x%04x len=%u exceeds packet bounds)",
                         tag_type, tag_len);
            break;
        }

        if (tag_type == PPPOE_TAG_HOST_UNIQ) {
            host_uniq = tag->value;
            host_uniq_len = tag_len;
        } else if (tag_type == PPPOE_TAG_SERVICE_NAME) {
            svc_name_req = tag->value;
            svc_name_len = tag_len;
            YLOG_INFO("PPPoE: PADI requested Service-Name: '%.*s'", svc_name_len, svc_name_req);
        }

        offset += sizeof(struct pppoe_tag) + tag_len;
    }

    switch (pppoe->code) {
    case PPPOE_CODE_PADI: {
        /* Per-MAC Rate Limiter */
        struct padi_node *node = NULL;
        int ret = rte_hash_lookup_data(g_padi_hash, &eth->src_addr, (void **)&node);

        if (ret < 0) {
            /* Alloc new node */
            /* Simple linear search for free/old slot (Optimized: use ring in production) */
            int free_idx = -1;
            /* Try specific range based on clock to avoid full scan? Or just scan 100 slots? */
            /* For now: Scan 32 slots starting from LRU clock */
            for (int i = 0; i < 32; i++) {
                int idx = (g_padi_lru_clock + i) % MAX_PADI_TRACKERS;
                if (!g_padi_nodes[idx].used || (time(NULL) - g_padi_nodes[idx].last_seen > 10)) {
                    free_idx = idx;
                    /* If used, remove old hash entry */
                    if (g_padi_nodes[idx].used) {
                        rte_hash_del_key(g_padi_hash, &g_padi_nodes[idx].mac);
                    }
                    break;
                }
            }
            g_padi_lru_clock = (g_padi_lru_clock + 1) % MAX_PADI_TRACKERS;

            if (free_idx >= 0) {
                node = &g_padi_nodes[free_idx];
                memset(node, 0, sizeof(*node));
                rte_ether_addr_copy(&eth->src_addr, &node->mac);
                node->used = true;
                // Limit: 100 PADI/sec per MAC, Burst 20 (production-grade for 50k+ subs)
                qos_tb_init(&node->tb, 100, 20);
                rte_hash_add_key_data(g_padi_hash, &node->mac, node);
            } else {
                /* Table full and no expired entries found in scan window */
                YLOG_WARNING("PPPoE: PADI Table Full, dropping packet from new MAC");
                return 0;
            }
        }

        node->last_seen = time(NULL);
        if (!qos_tb_conform(&node->tb, 1)) {
            static time_t last_log = 0;
            if (time(NULL) > last_log) {
                YLOG_WARNING("PPPoE: PADI Rate Limited for MAC %02x:%02x:...",
                             eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1]);
                last_log = time(NULL);
            }
            return 0;
        }

        YLOG_INFO("PPPoE: Received PADI from %02x:%02x:%02x:%02x:%02x:%02x",
                  eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                  eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                  eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);

        /* Send PADO with VLAN tag if received on VLAN */
        YLOG_INFO("PPPoE: Sending PADO to %02x:%02x:%02x:%02x:%02x:%02x vlan=%u",
                  eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                  eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                  eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5], vlan_id);
        int pado_ret = pppoe_send_pado(iface, &eth->src_addr, host_uniq, host_uniq_len,
                                       svc_name_req, svc_name_len, vlan_id);
        /* Debug: Log PADO result */
        if (pado_ret < 0)
            YLOG_ERROR("PPPoE: Failed to send PADO");
    } break;

    case PPPOE_CODE_PADR:
        YLOG_INFO("PPPoE: Received PADR from %02x:%02x:%02x:%02x:%02x:%02x",
                  eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                  eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                  eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);

        /* Parse Tags for PADR (Host-Uniq + Service-Name + AC-Cookie) */
        payload = (uint8_t *)(pppoe + 1);
        len = rte_be_to_cpu_16(pppoe->length);
        host_uniq = NULL;
        host_uniq_len = 0;
        svc_name_req = NULL;
        svc_name_len = 0;
        uint8_t *ac_cookie = NULL;
        uint16_t ac_cookie_len = 0;
        offset = 0;

        /* Bounds-checked tag parsing */
        while (offset + sizeof(struct pppoe_tag) <= len) {
            struct pppoe_tag *tag = (struct pppoe_tag *)(payload + offset);
            uint16_t tag_type = rte_be_to_cpu_16(tag->type);
            uint16_t tag_len = rte_be_to_cpu_16(tag->length);

            /* Bounds check: ensure tag value doesn't exceed packet */
            if (offset + sizeof(struct pppoe_tag) + tag_len > len) {
                YLOG_WARNING("PPPoE: PADR malformed tag (type=0x%04x len=%u exceeds packet)",
                             tag_type, tag_len);
                break;
            }

            if (tag_type == PPPOE_TAG_HOST_UNIQ) {
                host_uniq = tag->value;
                host_uniq_len = tag_len;
            } else if (tag_type == PPPOE_TAG_SERVICE_NAME) {
                svc_name_req = tag->value;
                svc_name_len = tag_len;
            } else if (tag_type == PPPOE_TAG_AC_COOKIE) {
                ac_cookie = tag->value;
                ac_cookie_len = tag_len;
            }
            offset += sizeof(struct pppoe_tag) + tag_len;
        }

/* Validate AC-Cookie (24 bytes, contains MAC+timestamp+signature) */
#define PPPOE_COOKIE_LENGTH 24
#define PPPOE_COOKIE_TIMEOUT 60
        if (!ac_cookie || ac_cookie_len != PPPOE_COOKIE_LENGTH) {
            YLOG_WARNING("PPPoE: PADR missing or invalid AC-Cookie (len=%u)", ac_cookie_len);
            break; /* Drop silently - DoS protection */
        }

        /* Validate cookie contents */
        {
            /* Extract timestamp from cookie bytes [12-15] */
            uint32_t cookie_ts = ((uint32_t)ac_cookie[12] << 24) | ((uint32_t)ac_cookie[13] << 16) |
                                 ((uint32_t)ac_cookie[14] << 8) | ac_cookie[15];
            uint32_t now = (uint32_t)time(NULL);

            /* Cookie expiry check */
            if (now - cookie_ts > PPPOE_COOKIE_TIMEOUT) {
                YLOG_WARNING("PPPoE: PADR cookie expired (age=%u sec)", now - cookie_ts);
                break;
            }

            /* Verify VLAN ID matches */
            uint16_t cookie_vlan = ((uint16_t)ac_cookie[16] << 8) | ac_cookie[17];
            if (cookie_vlan != vlan_id) {
                YLOG_WARNING("PPPoE: PADR cookie VLAN mismatch (%u vs %u)", cookie_vlan, vlan_id);
                break;
            }

            /* Verify ifindex matches */
            uint16_t cookie_ifindex = ac_cookie[18] | ((uint16_t)ac_cookie[19] << 8);
            if (cookie_ifindex != (iface->ifindex & 0xFFFF)) {
                YLOG_WARNING("PPPoE: PADR cookie ifindex mismatch");
                break;
            }

            /* Verify magic signature */
            if (ac_cookie[20] != 'Y' || ac_cookie[21] != 'R' || ac_cookie[22] != 'C' ||
                ac_cookie[23] != 'K') {
                YLOG_WARNING("PPPoE: PADR cookie signature invalid");
                break;
            }

            YLOG_DEBUG("PPPoE: PADR cookie validated (age=%u sec)", now - cookie_ts);
        }
#undef PPPOE_COOKIE_LENGTH
#undef PPPOE_COOKIE_TIMEOUT

        /* Create Session */
        struct pppoe_session *session = pppoe_create_session(&eth->src_addr, iface, vlan_id);
        if (session) {
            session->state = PPPOE_STATE_PADR_RCVD;
            YLOG_INFO("PPPoE: Session %u established. Sending PADS.", session->session_id);

            /* Send PADS (Echo Service-Name) */
            pppoe_send_pads(session, host_uniq, host_uniq_len, svc_name_req, svc_name_len);

            /* Start LCP Negotiation */
            ppp_lcp_open(session);
        }
        break;

    case PPPOE_CODE_PADT:
        YLOG_INFO("PPPoE: Received PADT");
        /* Terminate session */
        /* Find session by MAC */
        {
            struct pppoe_session *sess = pppoe_find_session(
                0, &eth->src_addr); /* ID 0 matches any? No, PADT has Session ID */
            /* PADT has Session ID in header */
            uint16_t sid = rte_be_to_cpu_16(pppoe->session_id);
            sess = pppoe_find_session(sid, &eth->src_addr);
            if (sess) {
                sess->state = PPPOE_STATE_TERMINATED;
                ha_send_sync(HA_MSG_SESSION_DEL, sess->session_id, sess->client_mac.addr_bytes, 0,
                             sess->state);
            }
        }
        break;

    default:
        YLOG_WARNING("PPPoE: Unknown code 0x%02x", pppoe->code);
        break;
    }

    return 0;
}

/**
 * Process PPPoE Session packet
 */
int pppoe_process_session(struct pkt_buf *pkt, struct interface *iface)
{
    (void)iface;
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    struct pppoe_hdr *pppoe;

    /* Handle VLAN tagged packets */
    if (ether_type == RTE_ETHER_TYPE_VLAN) {
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        pppoe = (struct pppoe_hdr *)(vlan + 1);
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr) +
                              sizeof(struct pppoe_hdr) + 2) {
            return -1;
        }
    } else {
        pppoe = (struct pppoe_hdr *)(eth + 1);
        if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + 2) {
            return -1;
        }
    }

    uint16_t *proto_ptr = (uint16_t *)(pppoe + 1);
    uint16_t proto = rte_be_to_cpu_16(*proto_ptr);
    uint8_t *payload = (uint8_t *)(proto_ptr + 1);
    uint16_t len = rte_be_to_cpu_16(pppoe->length);

    /* Find session */
    uint16_t session_id = rte_be_to_cpu_16(pppoe->session_id);
    struct pppoe_session *session = pppoe_find_session(session_id, &eth->src_addr);

    if (!session) {
        YLOG_INFO(
            "PPPoE: Dropped packet for unknown session ID %u from %02x:%02x:%02x:%02x:%02x:%02x",
            session_id, eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
            eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3], eth->src_addr.addr_bytes[4],
            eth->src_addr.addr_bytes[5]);
        return -1;
    }

    /* Update activity timestamp */
    session->last_activity_ts = time(NULL);

    if (session->debug) {
        YLOG_INFO("Session %u: Received Proto 0x%04x Len %u", session->session_id, proto, len);
    }

    /* Dispatch based on PPP Protocol */
    switch (proto) {
    case PPP_PROTO_LCP:
        return ppp_lcp_process_packet(session, payload, len - 2);

    case PPP_PROTO_IPCP:
        return ppp_ipcp_process_packet(session, payload, len - 2);

    case PPP_PROTO_PAP:
        return ppp_pap_process_packet(session, payload, len - 2);

    case PPP_PROTO_CHAP:
        return ppp_chap_process_packet(session, payload, len - 2);

    case PPP_PROTO_IP:
        /* Check for TCP SYN and Clamp MSS */
        {
            struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)payload;
            if (ipv4->next_proto_id == IPPROTO_TCP) {
                uint32_t ip_len = (ipv4->version_ihl & 0x0f) * 4;
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ipv4 + ip_len);
                if (tcp->tcp_flags & RTE_TCP_SYN_FLAG) {
                    uint32_t tcp_hdr_len = (tcp->data_off >> 4) * 4;
                    uint8_t *opts = (uint8_t *)(tcp + 1);
                    uint32_t opt_len = tcp_hdr_len - sizeof(struct rte_tcp_hdr);
                    uint32_t i = 0;
                    while (i < opt_len) {
                        uint8_t kind = opts[i];
                        if (kind == 0)
                            break; /* End */
                        if (kind == 1) {
                            i++;
                            continue;
                        } /* NOP */

                        if (i + 1 >= opt_len)
                            break;
                        uint8_t len = opts[i + 1];
                        if (len < 2 || i + len > opt_len)
                            break;

                        if (kind == 2 && len == 4) { /* MSS */
                            uint16_t mss = (opts[i + 2] << 8) | opts[i + 3];
                            if (mss > 1452) {
                                YLOG_INFO("PPPoE: Clamping MSS from %u to 1452 for Session %u", mss,
                                          session->session_id);
                                opts[i + 2] = (1452 >> 8) & 0xFF;
                                opts[i + 3] = 1452 & 0xFF;
                                /* Recalculate Checksum */
                                tcp->cksum = 0;
                                tcp->cksum = rte_ipv4_udptcp_cksum(ipv4, tcp);
                            }
                        }
                        i += len;
                    }
                }
            }
        }

        YLOG_DEBUG("PPPoE: Received IP packet");

        /* Decapsulate: Move Ethernet header forward to skip PPPoE/PPP */
        /* Current: [Eth][PPPoE][PPP][IP...] */
        /* Target:  [Eth][IP...] (Eth type = IPv4) */

        uint16_t strip_len = sizeof(struct pppoe_hdr) + 2;

        /* Copy Ethernet header to new position (overwriting PPPoE header) */
        struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)((uint8_t *)eth + strip_len);
        rte_ether_addr_copy(&eth->dst_addr, &new_eth->dst_addr);
        rte_ether_addr_copy(&eth->src_addr, &new_eth->src_addr);
        new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        /* Adjust mbuf */
        rte_pktmbuf_adj(m, strip_len);
        pkt->data = rte_pktmbuf_mtod(m, uint8_t *);
        pkt->len = m->data_len;

        /* Re-inject into packet processing */
        packet_rx_process_packet(pkt);
        break;

    default:
        YLOG_WARNING("PPPoE: Unknown PPP protocol 0x%04x", proto);
        /* TODO: Send LCP Protocol-Reject */
        break;
    }

    return 0;
}

void pppoe_terminate_session(struct pppoe_session *session, const char *reason)
{
    if (!session)
        return;
    (void)reason;

    YLOG_INFO("PPPoE: Terminating session %u (reason: %s)", session->session_id,
              reason ? reason : "unknown");

    /* Send PADT */
    pppoe_send_padt(session);

    /* Send RADIUS Accounting Stop */
    if (session->client_ip != 0) {
        radius_acct_request(RADIUS_ACCT_STATUS_STOP, session->session_id, NULL, session->client_ip);
    }

    /* HA Sync */
    ha_send_sync(HA_MSG_SESSION_DEL, session->session_id, session->client_mac.addr_bytes, 0,
                 session->state);

    /* Remove from Hash Tables */
    struct session_key_id key = {.session_id = session->session_id};
    rte_ether_addr_copy(&session->client_mac, &key.mac);

    rte_hash_del_key(g_pppoe_ctx.session_id_hash, &key);

    if (session->client_ip != 0) {
        rte_hash_del_key(g_pppoe_ctx.session_ip_hash, &session->client_ip);
    }

    /* Clear Bitmap (Free ID) */
    rte_bitmap_clear(g_pppoe_ctx.session_bitmap, session->session_id);

    session->state = PPPOE_STATE_TERMINATED;
}

#define PPPOE_ECHO_INTERVAL 30 /* Send echo every 30 seconds */
#define PPPOE_ECHO_MAX_FAILS 3 /* Max failures before terminate */

void pppoe_check_keepalives(void)
{
    struct rte_bitmap *bmp = g_pppoe_ctx.session_bitmap;
    uint32_t pos = 0;
    uint64_t mask = 0;
    uint64_t now = time(NULL);

    __rte_bitmap_scan_init(bmp);
    while (rte_bitmap_scan(bmp, &pos, &mask)) {
        for (int i = 0; i < 64; i++) {
            if (mask & (1ULL << i)) {
                struct pppoe_session *curr = &g_pppoe_session_slab[pos + i];

                if (curr->state == PPPOE_STATE_SESSION_ESTABLISHED) {
                    if (curr->lcp_state == LCP_STATE_OPENED) {
                        /* LCP Echo */
                        if (curr->last_echo_ts == 0 ||
                            (now - curr->last_echo_ts) >= PPPOE_ECHO_INTERVAL) {
                            if (curr->echo_failures >= PPPOE_ECHO_MAX_FAILS) {
                                pppoe_terminate_session(curr, "Echo timeout");
                                /* Continue to next bit? Session terminated. */
                            } else {
                                ppp_lcp_send_echo_request(curr);
                                curr->echo_failures++;
                                curr->last_echo_ts = now;
                            }
                        }
                    } else {
                        /* Check LCP Negotiation Timeouts */
                        ppp_lcp_check_timeouts(curr);
                    }

                    /* Session Timeout */
                    if (curr->session_timeout > 0 && curr->start_ts > 0) {
                        if (now - curr->start_ts >= curr->session_timeout) {
                            pppoe_terminate_session(curr, "Session timeout");
                        }
                    }

                    /* Idle Timeout */
                    if (curr->idle_timeout > 0) {
                        uint64_t last =
                            (curr->last_activity_ts > 0) ? curr->last_activity_ts : curr->start_ts;
                        if (now - last >= curr->idle_timeout) {
                            pppoe_terminate_session(curr, "Idle timeout");
                        }
                    }
                }
            }
        }
    }
}

void pppoe_check_accounting(void)
{
    struct rte_bitmap *bmp = g_pppoe_ctx.session_bitmap;
    uint32_t pos = 0;
    uint64_t mask = 0;
    uint64_t now = time(NULL);

    __rte_bitmap_scan_init(bmp);
    while (rte_bitmap_scan(bmp, &pos, &mask)) {
        for (int i = 0; i < 64; i++) {
            if (mask & (1ULL << i)) {
                struct pppoe_session *curr = &g_pppoe_session_slab[pos + i];

                if (curr->state == PPPOE_STATE_SESSION_ESTABLISHED &&
                    curr->acct_interim_interval > 0) {
                    if (now - curr->last_acct_ts >= curr->acct_interim_interval) {
                        radius_acct_request(RADIUS_ACCT_STATUS_INTERIM, curr->session_id,
                                            curr->username, curr->client_ip);
                        curr->last_acct_ts = now;
                    }
                }
            }
        }
    }
}

void pppoe_update_qos(const uint8_t *mac, uint64_t rate_bps)
{
    struct rte_bitmap *bmp = g_pppoe_ctx.session_bitmap;
    uint32_t pos = 0;
    uint64_t mask = 0;

    __rte_bitmap_scan_init(bmp);
    while (rte_bitmap_scan(bmp, &pos, &mask)) {
        for (int i = 0; i < 64; i++) {
            if (mask & (1ULL << i)) {
                struct pppoe_session *curr = &g_pppoe_session_slab[pos + i];

                if (rte_is_same_ether_addr(&curr->client_mac, (const struct rte_ether_addr *)mac)) {
                    uint64_t burst = rate_bps / 8;
                    if (burst < 1500)
                        burst = 1500;
                    qos_tb_init(&curr->downlink_tb, rate_bps / 8, burst);
                    YLOG_INFO("PPPoE: Updated QoS for logic %02x:%02x... to %lu bps", mac[0],
                              mac[1], rate_bps);
                    return;
                }
            }
        }
    }
    YLOG_WARNING("PPPoE: Session not found for QoS update");
}

static void pppoe_auth_callback(uint16_t session_id, const struct radius_auth_result *result)
{
    struct pppoe_session *session = pppoe_find_session(session_id, NULL);

    if (!session) {
        YLOG_WARNING("PPPoE: Auth response for unknown session %u", session_id);
        return;
    }

    /* CRITICAL: Atomic CAS to prevent duplicate auth processing from multiple lcores */
    uint8_t expected_state = PPPOE_STATE_PADR_RCVD;
    if (!__atomic_compare_exchange_n(&session->state, &expected_state,
                                     PPPOE_STATE_SESSION_ESTABLISHED, 0, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST)) {
        return;
    }

    if (result->success) {
        /* Only use RADIUS Framed-IP if provided, otherwise keep pool-allocated IP */
        uint32_t assigned_ip = (result->framed_ip != 0) ? result->framed_ip : session->client_ip;

        YLOG_INFO("PPPoE: Auth success for session %u, IP %u.%u.%u.%u (RADIUS: %u.%u.%u.%u)",
                  session_id, (assigned_ip >> 24) & 0xFF, (assigned_ip >> 16) & 0xFF,
                  (assigned_ip >> 8) & 0xFF, assigned_ip & 0xFF, (result->framed_ip >> 24) & 0xFF,
                  (result->framed_ip >> 16) & 0xFF, (result->framed_ip >> 8) & 0xFF,
                  result->framed_ip & 0xFF);

        /* Update session - keep pool IP if RADIUS didn't provide one */
        if (result->framed_ip != 0) {
            session->client_ip = result->framed_ip;
        }
        session->session_timeout = result->session_timeout;
        session->idle_timeout = result->idle_timeout;

        if (result->rate_limit_bps > 0) {
            session->rate_bps = result->rate_limit_bps;
            pppoe_update_qos(session->client_mac.addr_bytes, result->rate_limit_bps);
        }

        /* Send CHAP/PAP success or just proceed to IPCP */
        /* Implementation specific... assuming we send success here */

        /* Send Accounting Start if configured */
        radius_acct_request(RADIUS_ACCT_STATUS_START, session->session_id, session->username,
                            session->client_ip);
        session->last_acct_ts = time(NULL);

        /* Set start timestamp */
        session->start_ts = time(NULL);

        /* Send Success Packet */
        const char *msg = "Login OK";
        if (session->lcp_state == LCP_STATE_OPENED) {
            if (session->chap_challenge_len > 0) {
                ppp_auth_send(session, PPP_PROTO_CHAP, CHAP_CODE_SUCCESS,
                              session->next_lcp_identifier, (const uint8_t *)msg, strlen(msg));
            } else {
                uint8_t reply_data[256];
                reply_data[0] = strlen(msg);
                memcpy(reply_data + 1, msg, strlen(msg));
                ppp_auth_send(session, PPP_PROTO_PAP, PAP_CODE_AUTH_ACK,
                              session->next_lcp_identifier, reply_data, 1 + strlen(msg));
            }
        }

        /* State already transitioned by atomic CAS above */

        /* Start IPCP */
        ppp_ipcp_open(session);

        /* Send HA Sync */
        ha_send_sync(HA_MSG_SESSION_UPDATE, session->session_id, session->client_mac.addr_bytes, 0,
                     session->state);

    } else {
        YLOG_INFO("PPPoE: Session %u Auth Failure", session_id);

        /* Send Failure Packet */
        const char *msg = "Auth Failed";
        if (session->chap_challenge_len > 0) {
            ppp_auth_send(session, PPP_PROTO_CHAP, CHAP_CODE_FAILURE, session->next_lcp_identifier,
                          (const uint8_t *)msg, strlen(msg));
        } else {
            uint8_t reply_data[256];
            reply_data[0] = strlen(msg);
            memcpy(reply_data + 1, msg, strlen(msg));
            ppp_auth_send(session, PPP_PROTO_PAP, PAP_CODE_AUTH_NAK, session->next_lcp_identifier,
                          reply_data, 1 + strlen(msg));
        }

        /* Terminate */
        session->state = PPPOE_STATE_TERMINATED;
        ha_send_sync(HA_MSG_SESSION_DEL, session->session_id, session->client_mac.addr_bytes, 0,
                     session->state);
    }
}

void pppoe_print_sessions(void)
{
    struct rte_bitmap *bmp = g_pppoe_ctx.session_bitmap;
    if (!bmp) {
        printf("PPPoE not initialized or bitmap missing\n");
        return;
    }

    /* Print Header */
    /* Cols: ID(5) User(15) CallID(17) MAC(17) IP(15) State(6) Rate(8) Tx(10) Rx(10) Up(8) */
    printf("%-5s %-15s %-17s %-17s %-15s %-6s %-8s %-10s %-10s %-8s\n", "ID", "Username",
           "Called-SID", "MAC Address", "IP Address", "State", "Rate", "TxBytes", "RxBytes",
           "Uptime");
    printf("---------------------------------------------------------------------------------------"
           "-----------------------------------\n");

    uint32_t pos = 0;
    uint64_t mask = 0;
    uint32_t count = 0;
    uint64_t now = time(NULL);

    __rte_bitmap_scan_init(bmp);
    while (rte_bitmap_scan(bmp, &pos, &mask)) {
        for (int i = 0; i < 64; i++) {
            if (mask & (1ULL << i)) {
                struct pppoe_session *curr = &g_pppoe_session_slab[pos + i];

                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                         curr->client_mac.addr_bytes[0], curr->client_mac.addr_bytes[1],
                         curr->client_mac.addr_bytes[2], curr->client_mac.addr_bytes[3],
                         curr->client_mac.addr_bytes[4], curr->client_mac.addr_bytes[5]);

                char server_mac_str[18] = "N/A";
                if (curr->iface && curr->iface->mac_addr) {
                    const struct rte_ether_addr *smac =
                        (const struct rte_ether_addr *)curr->iface->mac_addr;
                    snprintf(server_mac_str, sizeof(server_mac_str),
                             "%02X:%02X:%02X:%02X:%02X:%02X", smac->addr_bytes[0],
                             smac->addr_bytes[1], smac->addr_bytes[2], smac->addr_bytes[3],
                             smac->addr_bytes[4], smac->addr_bytes[5]);
                }

                uint32_t ip = curr->client_ip;
                char ip_str[16];
                if (ip == 0)
                    strcpy(ip_str, "-");
                else
                    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", (ip >> 24) & 0xFF,
                             (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);

                const char *state_str = "UNK";
                switch (curr->state) {
                case PPPOE_STATE_INITIAL:
                    state_str = "INIT";
                    break;
                case PPPOE_STATE_PADI_RCVD:
                    state_str = "PADI";
                    break;
                case PPPOE_STATE_PADR_RCVD:
                    state_str = "PADR";
                    break;
                case PPPOE_STATE_SESSION_ESTABLISHED:
                    state_str = "ESTAB";
                    break;
                case PPPOE_STATE_TERMINATED:
                    state_str = "TERM";
                    break;
                }

                /* Uptime */
                uint64_t uptime = (curr->start_ts > 0) ? (now - curr->start_ts) : 0;
                char uptime_str[32];
                if (uptime < 60)
                    snprintf(uptime_str, sizeof(uptime_str), "%lus", uptime);
                else if (uptime < 3600)
                    snprintf(uptime_str, sizeof(uptime_str), "%lum", uptime / 60);
                else
                    snprintf(uptime_str, sizeof(uptime_str), "%luh", uptime / 3600);

                /* Truncate username */
                char user_str[16];
                strncpy(user_str, curr->username[0] ? curr->username : "-", 15);
                user_str[15] = '\0';

                /* Rate in Mbps or Kbps? bps. Print raw or K/M? */
                /* User asked for rate-limit. Raw bps is precise. */
                /* Use readable? */
                char rate_str[16];
                if (curr->rate_bps == 0)
                    strcpy(rate_str, "Unlim");
                else if (curr->rate_bps >= 1000000)
                    snprintf(rate_str, sizeof(rate_str), "%luM", curr->rate_bps / 1000000);
                else
                    snprintf(rate_str, sizeof(rate_str), "%luK", curr->rate_bps / 1000);

                printf("%-5u %-15s %-17s %-17s %-15s %-6s %-8s %-10lu %-10lu %-8s\n",
                       curr->session_id, user_str, server_mac_str, mac_str, ip_str, state_str,
                       rate_str, curr->bytes_in, curr->bytes_out, uptime_str);

                count++;
                if (count >= 100) {
                    printf("... (Truncated at 100 sessions)\n");
                    return;
                }
            }
        }
    }
    printf("Total Sessions: %u\n", count);
}

void pppoe_print_statistics(void)
{
    /* Count active sessions */
    uint32_t active = 0;
    for (uint32_t i = 0; i < MAX_SESSIONS; i++) {
        if (g_pppoe_session_slab[i].state == PPPOE_STATE_SESSION_ESTABLISHED) {
            active++;
        }
    }

    printf("PPPoE Statistics\n");
    printf("================\n");
    printf("  Active Sessions:    %u\n", active);
}

void pppoe_disconnect_callback(const char *session_str, const uint8_t *mac, uint32_t ip)
{
    struct pppoe_session *session = NULL;

    if (session_str) {
        uint16_t sid = atoi(session_str);
        if (sid > 0) {
            session = pppoe_find_session(sid, NULL);
        }
    }

    if (!session && ip != 0) {
        session = pppoe_find_session_by_ip(ip);
    }

    if (!session && mac) {
        /* Scan bitmap for MAC */
        struct rte_bitmap *bmp = g_pppoe_ctx.session_bitmap;
        uint32_t pos = 0;
        uint64_t mask = 0;
        __rte_bitmap_scan_init(bmp);
        while (rte_bitmap_scan(bmp, &pos, &mask)) {
            for (int i = 0; i < 64; i++) {
                if (mask & (1ULL << i)) {
                    struct pppoe_session *curr = &g_pppoe_session_slab[pos + i];
                    if (rte_is_same_ether_addr(&curr->client_mac,
                                               (const struct rte_ether_addr *)mac)) {
                        session = curr;
                        goto found;
                    }
                }
            }
        }
    }

found:
    if (session) {
        YLOG_INFO("PPPoE: Disconnect-Request for session %u", session->session_id);
        pppoe_terminate_session(session, "RADIUS Disconnect-Request");
    } else {
        YLOG_WARNING("PPPoE: Session not found for Disconnect-Request");
    }
}

void pppoe_set_session_debug(uint16_t session_id, bool enable)
{
    struct pppoe_session *session = pppoe_find_session(session_id, NULL);
    if (session) {
        session->debug = enable;
        YLOG_INFO("Session %u: Debug %s", session_id, enable ? "Enabled" : "Disabled");
    } else {
        YLOG_WARNING("Session %u not found for debug", session_id);
    }
}
