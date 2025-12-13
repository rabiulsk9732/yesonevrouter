/**
 * @file ipoe_session.c
 * @brief IPoE Session Management Implementation (DPDK)
 */

#include <ipoe_session.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mempool.h>

/*============================================================================
 * Global Session Manager
 *============================================================================*/

static struct ipoe_session_mgr g_sess_mgr = {0};
static uint32_t g_next_session_id = 1;

/*============================================================================
 * Utility Functions
 *============================================================================*/

static inline uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void ipoe_session_format_mac(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *ipoe_state_to_string(ipoe_session_state_t state)
{
    static const char *names[] = {
        "INIT", "AUTH_PENDING", "AUTH_REJECTED", "DHCP_PENDING",
        "IP_BOUND", "ACTIVE", "IDLE", "EXPIRED", "TERMINATING"
    };
    if (state >= IPOE_STATE_MAX) return "UNKNOWN";
    return names[state];
}

const char *ipoe_term_reason_to_string(ipoe_term_reason_t reason)
{
    static const char *names[] = {
        "NONE", "USER_REQUEST", "ADMIN", "RADIUS_DM", "LEASE_EXPIRE",
        "IDLE_TIMEOUT", "SESSION_TIMEOUT", "AUTH_FAILURE", "PORT_DOWN",
        "DUPLICATE_MAC", "ARP_CONFLICT"
    };
    if (reason >= IPOE_TERM_MAX) return "UNKNOWN";
    return names[reason];
}

/*============================================================================
 * Hash Functions for Lookup Tables
 *============================================================================*/

static inline uint32_t hash_mac(const uint8_t *mac)
{
    /* Simple FNV-1a hash for MAC addresses */
    uint32_t hash = 2166136261u;
    for (int i = 0; i < 6; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }
    return hash;
}

static inline uint32_t hash_vlan_mac(uint16_t svlan, uint16_t cvlan, const uint8_t *mac)
{
    uint32_t hash = 2166136261u;
    hash ^= svlan;
    hash *= 16777619u;
    hash ^= cvlan;
    hash *= 16777619u;
    for (int i = 0; i < 6; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }
    return hash;
}

/*============================================================================
 * Session Manager Initialization (DPDK)
 *============================================================================*/

int ipoe_session_mgr_init(uint32_t max_sessions)
{
    if (g_sess_mgr.session_pool) {
        fprintf(stderr, "ipoe: session manager already initialized\n");
        return -1;
    }

    /* Allocate session pool */
    g_sess_mgr.session_pool = calloc(max_sessions, sizeof(struct ipoe_session));
    if (!g_sess_mgr.session_pool) {
        fprintf(stderr, "ipoe: failed to allocate session pool\n");
        return -1;
    }

    g_sess_mgr.pool_size = max_sessions;
    g_sess_mgr.active_count = 0;

    /* Create DPDK lookup tables */
    struct rte_hash_parameters params = {
        .name = "ipoe_mac_table",
        .entries = IPOE_SESSION_HASH_ENTRIES,
        .key_len = sizeof(struct ipoe_mac_key),
        .hash_func = rte_jhash,
        .socket_id = 0,
    };
    g_sess_mgr.mac_table = rte_hash_create(&params);

    params.name = "ipoe_vlan_mac_table";
    params.key_len = sizeof(struct ipoe_vlan_mac_key);
    g_sess_mgr.vlan_mac_table = rte_hash_create(&params);

    params.name = "ipoe_ip_table";
    params.key_len = sizeof(uint32_t);
    g_sess_mgr.ip_table = rte_hash_create(&params);

    params.name = "ipoe_xid_table";
    params.key_len = sizeof(uint32_t);
    g_sess_mgr.xid_table = rte_hash_create(&params);

    /* Default configuration */
    g_sess_mgr.mode = IPOE_FLAG_L2_MODE;  /* Default to L2 */
    g_sess_mgr.mac_auth_enabled = true;
    g_sess_mgr.anti_spoof_enabled = true;
    g_sess_mgr.multi_ip_enabled = false;
    g_sess_mgr.default_lease_time = 3600;
    g_sess_mgr.default_session_timeout = 86400;
    g_sess_mgr.default_idle_timeout = 300;

    printf("ipoe: session manager initialized (max=%u sessions)\n", max_sessions);
    return 0;
}

void ipoe_session_mgr_cleanup(void)
{
    if (!g_sess_mgr.session_pool) return;

    free(g_sess_mgr.session_pool);
    g_sess_mgr.session_pool = NULL;

    /* Free DPDK hash tables */
    if (g_sess_mgr.mac_table) {
        rte_hash_free(g_sess_mgr.mac_table);
        g_sess_mgr.mac_table = NULL;
    }
    if (g_sess_mgr.vlan_mac_table) {
        rte_hash_free(g_sess_mgr.vlan_mac_table);
        g_sess_mgr.vlan_mac_table = NULL;
    }
    if (g_sess_mgr.ip_table) {
        rte_hash_free(g_sess_mgr.ip_table);
        g_sess_mgr.ip_table = NULL;
    }
    if (g_sess_mgr.xid_table) {
        rte_hash_free(g_sess_mgr.xid_table);
        g_sess_mgr.xid_table = NULL;
    }

    printf("ipoe: session manager cleanup complete\n");
}

/*============================================================================
 * Session Allocation (DPDK Lockless)
 *============================================================================*/

static struct ipoe_session *session_alloc(void)
{
    struct ipoe_session *sess = NULL;

    /* Use DPDK mempool if available */
    if (g_sess_mgr.session_mempool) {
        if (rte_mempool_get(g_sess_mgr.session_mempool, (void **)&sess) < 0) {
            return NULL;
        }
    } else {
        /* Fallback: linear scan in pre-allocated pool */
        for (uint32_t i = 0; i < g_sess_mgr.pool_size; i++) {
            struct ipoe_session *s = &g_sess_mgr.session_pool[i];
            uint8_t expected = 0;
            if (__atomic_compare_exchange_n(&s->in_use, &expected, 1, 0,
                                            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                sess = s;
                break;
            }
        }
    }

    if (sess) {
        memset(sess, 0, sizeof(*sess));
        sess->in_use = 1;
        sess->session_id = __atomic_fetch_add(&g_next_session_id, 1, __ATOMIC_RELAXED);
        sess->session_start = get_timestamp_ns();
        __atomic_fetch_add(&g_sess_mgr.active_count, 1, __ATOMIC_RELAXED);
    }

    return sess;
}

static void session_free(struct ipoe_session *sess)
{
    if (!sess) return;

    if (g_sess_mgr.session_mempool) {
        rte_mempool_put(g_sess_mgr.session_mempool, sess);
    } else {
        sess->in_use = 0;
    }
    __atomic_fetch_sub(&g_sess_mgr.active_count, 1, __ATOMIC_RELAXED);
}

/*============================================================================
 * Session Lifecycle
 *============================================================================*/

struct ipoe_session *ipoe_session_create(const uint8_t *mac, uint16_t svlan, uint16_t cvlan)
{
    if (!mac) return NULL;

    struct ipoe_session *sess = session_alloc();
    if (!sess) {
        fprintf(stderr, "ipoe: session pool exhausted\n");
        return NULL;
    }

    /* Copy identification */
    memcpy(sess->mac, mac, 6);
    sess->svlan = svlan;
    sess->cvlan = cvlan;
    sess->state = IPOE_STATE_INIT;
    sess->dhcp_state = DHCP_STATE_INIT;
    sess->aaa_state = AAA_STATE_NONE;

    /* Set mode flag */
    if (svlan == 0 && cvlan == 0) {
        sess->flags |= IPOE_FLAG_L2_MODE;
    } else {
        sess->flags |= IPOE_FLAG_L3_MODE;
    }

    /* Add to lookup tables */
#ifdef HAVE_DPDK
    struct ipoe_mac_key mac_key;
    memcpy(mac_key.mac, mac, 6);
    mac_key.pad = 0;
    rte_hash_add_key_data(g_sess_mgr.mac_table, &mac_key, sess);

    if (sess->flags & IPOE_FLAG_L3_MODE) {
        struct ipoe_vlan_mac_key vlan_key;
        memcpy(vlan_key.mac, mac, 6);
        vlan_key.svlan = svlan;
        vlan_key.cvlan = cvlan;
        vlan_key.pad = 0;
        rte_hash_add_key_data(g_sess_mgr.vlan_mac_table, &vlan_key, sess);
    }
#else
    hash_table_insert(g_sess_mgr.mac_table, mac, 6, sess);

    if (sess->flags & IPOE_FLAG_L3_MODE) {
        struct ipoe_vlan_mac_key vlan_key;
        memcpy(vlan_key.mac, mac, 6);
        vlan_key.svlan = svlan;
        vlan_key.cvlan = cvlan;
        vlan_key.pad = 0;
        hash_table_insert(g_sess_mgr.vlan_mac_table, &vlan_key, sizeof(vlan_key), sess);
    }
#endif

    g_sess_mgr.sessions_created++;

    char mac_str[18];
    ipoe_session_format_mac(mac, mac_str, sizeof(mac_str));
    printf("ipoe: session %u created for MAC %s (VLAN %u/%u)\n",
           sess->session_id, mac_str, svlan, cvlan);

    return sess;
}

int ipoe_session_destroy(struct ipoe_session *sess, ipoe_term_reason_t reason)
{
    if (!sess) return -1;

    sess->state = IPOE_STATE_TERMINATING;
    sess->term_reason = reason;

    /* Remove from lookup tables */
#ifdef HAVE_DPDK
    struct ipoe_mac_key mac_key;
    memcpy(mac_key.mac, sess->mac, 6);
    mac_key.pad = 0;
    rte_hash_del_key(g_sess_mgr.mac_table, &mac_key);

    if (sess->ip_addr != 0) {
        rte_hash_del_key(g_sess_mgr.ip_table, &sess->ip_addr);
    }

    if (sess->dhcp_xid != 0) {
        rte_hash_del_key(g_sess_mgr.xid_table, &sess->dhcp_xid);
    }
#else
    hash_table_remove(g_sess_mgr.mac_table, sess->mac, 6);

    if (sess->ip_addr != 0) {
        hash_table_remove(g_sess_mgr.ip_table, &sess->ip_addr, sizeof(sess->ip_addr));
    }
#endif

    char mac_str[18];
    ipoe_session_format_mac(sess->mac, mac_str, sizeof(mac_str));
    printf("ipoe: session %u destroyed for MAC %s (reason=%s)\n",
           sess->session_id, mac_str, ipoe_term_reason_to_string(reason));

    g_sess_mgr.sessions_destroyed++;
    session_free(sess);

    return 0;
}

void ipoe_session_update_state(struct ipoe_session *sess, ipoe_session_state_t new_state)
{
    if (!sess) return;

    ipoe_session_state_t old_state = sess->state;
    sess->state = new_state;

    printf("ipoe: session %u state %s -> %s\n",
           sess->session_id,
           ipoe_state_to_string(old_state),
           ipoe_state_to_string(new_state));
}

/*============================================================================
 * Lookup Functions
 *============================================================================*/

struct ipoe_session *ipoe_session_find_by_mac(const uint8_t *mac)
{
    if (!mac) return NULL;

#ifdef HAVE_DPDK
    struct ipoe_mac_key mac_key;
    memcpy(mac_key.mac, mac, 6);
    mac_key.pad = 0;

    void *data = NULL;
    if (rte_hash_lookup_data(g_sess_mgr.mac_table, &mac_key, &data) >= 0) {
        return (struct ipoe_session *)data;
    }
    return NULL;
#else
    return hash_table_lookup(g_sess_mgr.mac_table, mac, 6);
#endif
}

struct ipoe_session *ipoe_session_find_by_vlan_mac(uint16_t svlan, uint16_t cvlan, const uint8_t *mac)
{
    if (!mac) return NULL;

    struct ipoe_vlan_mac_key vlan_key;
    memcpy(vlan_key.mac, mac, 6);
    vlan_key.svlan = svlan;
    vlan_key.cvlan = cvlan;
    vlan_key.pad = 0;

#ifdef HAVE_DPDK
    void *data = NULL;
    if (rte_hash_lookup_data(g_sess_mgr.vlan_mac_table, &vlan_key, &data) >= 0) {
        return (struct ipoe_session *)data;
    }
    return NULL;
#else
    return hash_table_lookup(g_sess_mgr.vlan_mac_table, &vlan_key, sizeof(vlan_key));
#endif
}

struct ipoe_session *ipoe_session_find_by_ip(uint32_t ip)
{
    if (ip == 0) return NULL;

#ifdef HAVE_DPDK
    void *data = NULL;
    if (rte_hash_lookup_data(g_sess_mgr.ip_table, &ip, &data) >= 0) {
        return (struct ipoe_session *)data;
    }
    return NULL;
#else
    return hash_table_lookup(g_sess_mgr.ip_table, &ip, sizeof(ip));
#endif
}

struct ipoe_session *ipoe_session_find_by_xid(uint32_t xid)
{
    if (xid == 0) return NULL;

#ifdef HAVE_DPDK
    void *data = NULL;
    if (rte_hash_lookup_data(g_sess_mgr.xid_table, &xid, &data) >= 0) {
        return (struct ipoe_session *)data;
    }
    return NULL;
#else
    return hash_table_lookup(g_sess_mgr.xid_table, &xid, sizeof(xid));
#endif
}

struct ipoe_session *ipoe_session_find_by_id(uint32_t session_id)
{
    /* Linear search through pool - O(n) but rarely called */
    for (uint32_t i = 0; i < g_sess_mgr.pool_size; i++) {
        struct ipoe_session *sess = &g_sess_mgr.session_pool[i];
        if (sess->session_id == session_id && sess->state != IPOE_STATE_INIT) {
            return sess;
        }
    }
    return NULL;
}

/*============================================================================
 * IP Binding
 *============================================================================*/

int ipoe_session_bind_ip(struct ipoe_session *sess, uint32_t ip)
{
    if (!sess || ip == 0) return -1;

    sess->ip_addr = ip;

#ifdef HAVE_DPDK
    rte_hash_add_key_data(g_sess_mgr.ip_table, &ip, sess);
#else
    hash_table_insert(g_sess_mgr.ip_table, &ip, sizeof(ip), sess);
#endif

    char ip_str[16];
    struct in_addr addr = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    printf("ipoe: session %u bound to IP %s\n", sess->session_id, ip_str);

    return 0;
}

int ipoe_session_unbind_ip(struct ipoe_session *sess)
{
    if (!sess || sess->ip_addr == 0) return -1;

    uint32_t ip = sess->ip_addr;

#ifdef HAVE_DPDK
    rte_hash_del_key(g_sess_mgr.ip_table, &ip);
#else
    hash_table_remove(g_sess_mgr.ip_table, &ip, sizeof(ip));
#endif

    sess->ip_addr = 0;
    return 0;
}

/*============================================================================
 * XID Management (DHCP transaction tracking)
 *============================================================================*/

int ipoe_session_set_xid(struct ipoe_session *sess, uint32_t xid)
{
    if (!sess || xid == 0) return -1;

    sess->dhcp_xid = xid;

#ifdef HAVE_DPDK
    rte_hash_add_key_data(g_sess_mgr.xid_table, &xid, sess);
#else
    hash_table_insert(g_sess_mgr.xid_table, &xid, sizeof(xid), sess);
#endif

    return 0;
}

int ipoe_session_clear_xid(struct ipoe_session *sess)
{
    if (!sess || sess->dhcp_xid == 0) return -1;

    uint32_t xid = sess->dhcp_xid;

#ifdef HAVE_DPDK
    rte_hash_del_key(g_sess_mgr.xid_table, &xid);
#else
    hash_table_remove(g_sess_mgr.xid_table, &xid, sizeof(xid));
#endif

    sess->dhcp_xid = 0;
    return 0;
}

/*============================================================================
 * Iteration
 *============================================================================*/

void ipoe_session_iterate(ipoe_session_callback_t callback, void *ctx)
{
    if (!callback) return;

    for (uint32_t i = 0; i < g_sess_mgr.pool_size; i++) {
        struct ipoe_session *sess = &g_sess_mgr.session_pool[i];
        if (sess->state != IPOE_STATE_INIT && sess->state != IPOE_STATE_TERMINATING) {
            callback(sess, ctx);
        }
    }
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_session_get_stats(uint64_t *active, uint64_t *created, uint64_t *destroyed)
{
    if (active) *active = g_sess_mgr.active_count;
    if (created) *created = g_sess_mgr.sessions_created;
    if (destroyed) *destroyed = g_sess_mgr.sessions_destroyed;
}

void ipoe_session_print_stats(void)
{
    printf("\nIPoE Session Statistics:\n");
    printf("  Pool size:         %u\n", g_sess_mgr.pool_size);
    printf("  Active sessions:   %u\n", g_sess_mgr.active_count);
    printf("  Sessions created:  %lu\n", g_sess_mgr.sessions_created);
    printf("  Sessions destroyed:%lu\n", g_sess_mgr.sessions_destroyed);
    printf("  Auth success:      %lu\n", g_sess_mgr.auth_success);
    printf("  Auth failures:     %lu\n", g_sess_mgr.auth_failures);
    printf("  DHCP discovers:    %lu\n", g_sess_mgr.dhcp_discovers);
    printf("  DHCP offers:       %lu\n", g_sess_mgr.dhcp_offers);
    printf("  DHCP ACKs:         %lu\n", g_sess_mgr.dhcp_acks);
    printf("  DHCP NAKs:         %lu\n", g_sess_mgr.dhcp_naks);
    printf("\n");
}

/*============================================================================
 * Lockless DPDK Session Allocation (Production Architecture)
 *============================================================================*/

#ifdef HAVE_DPDK

/*
 * Thread-local worker ID for per-worker statistics
 */
static __thread uint32_t g_worker_id = 0;

/**
 * Initialize lockless DPDK session manager
 * Creates per-worker rings and session mempool
 */
int ipoe_session_mgr_init_dpdk(uint32_t max_sessions, uint32_t num_workers)
{
    char ring_name[64];

    /* Create session mempool (NUMA-aware) */
    g_sess_mgr.session_mempool = rte_mempool_create(
        "ipoe_session_pool",
        IPOE_SESSION_MEMPOOL_SIZE,
        sizeof(struct ipoe_session),
        64,             /* Cache size */
        0,              /* Private data size */
        NULL, NULL,     /* mp_init */
        NULL, NULL,     /* obj_init */
        rte_socket_id(),
        MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET
    );

    if (!g_sess_mgr.session_mempool) {
        fprintf(stderr, "ipoe: failed to create session mempool\n");
        return -1;
    }

    /* Create per-worker event rings */
    g_sess_mgr.num_workers = num_workers;
    for (uint32_t i = 0; i < num_workers; i++) {
        snprintf(ring_name, sizeof(ring_name), "ipoe_worker_%u", i);
        g_sess_mgr.worker_rings[i] = rte_ring_create(
            ring_name,
            IPOE_WORKER_RING_SIZE,
            rte_socket_id(),
            RING_F_SP_ENQ | RING_F_SC_DEQ  /* Single producer/consumer */
        );

        if (!g_sess_mgr.worker_rings[i]) {
            fprintf(stderr, "ipoe: failed to create worker ring %u\n", i);
            return -1;
        }
    }

    /* Create TX response ring */
    g_sess_mgr.tx_ring = rte_ring_create(
        "ipoe_tx_ring",
        IPOE_TX_RING_SIZE,
        rte_socket_id(),
        RING_F_SC_DEQ  /* Single consumer (TX thread) */
    );

    if (!g_sess_mgr.tx_ring) {
        fprintf(stderr, "ipoe: failed to create TX ring\n");
        return -1;
    }

    printf("ipoe: DPDK lockless initialized (%u workers, %u sessions)\n",
           num_workers, max_sessions);

    return 0;
}

/**
 * Lockless session allocation from mempool
 */
struct ipoe_session *ipoe_session_alloc_lockless(void)
{
    struct ipoe_session *sess = NULL;

    if (rte_mempool_get(g_sess_mgr.session_mempool, (void **)&sess) != 0) {
        return NULL;
    }

    memset(sess, 0, sizeof(*sess));
    sess->session_id = __atomic_fetch_add(&g_next_session_id, 1, __ATOMIC_RELAXED);
    sess->session_start = get_timestamp_ns();

    /* Update per-worker stats (lockless) */
    __atomic_fetch_add(&g_sess_mgr.worker_stats[g_worker_id].sessions_created, 1, __ATOMIC_RELAXED);

    return sess;
}

/**
 * Lockless session free back to mempool
 */
void ipoe_session_free_lockless(struct ipoe_session *sess)
{
    if (!sess) return;

    __atomic_fetch_add(&g_sess_mgr.worker_stats[g_worker_id].sessions_destroyed, 1, __ATOMIC_RELAXED);
    rte_mempool_put(g_sess_mgr.session_mempool, sess);
}

/**
 * Enqueue DHCP event to worker ring (lockless)
 * Called from DPDK RX path
 */
int ipoe_enqueue_dhcp_event(uint32_t worker_id, struct rte_mbuf *mbuf)
{
    if (worker_id >= g_sess_mgr.num_workers) {
        return -1;
    }

    if (rte_ring_enqueue(g_sess_mgr.worker_rings[worker_id], mbuf) != 0) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    __atomic_fetch_add(&g_sess_mgr.worker_stats[worker_id].dhcp_rx, 1, __ATOMIC_RELAXED);
    return 0;
}

/**
 * Dequeue DHCP event from worker ring (lockless)
 * Called by worker thread
 */
struct rte_mbuf *ipoe_dequeue_dhcp_event(uint32_t worker_id)
{
    if (worker_id >= g_sess_mgr.num_workers) {
        return NULL;
    }

    struct rte_mbuf *mbuf = NULL;
    if (rte_ring_dequeue(g_sess_mgr.worker_rings[worker_id], (void **)&mbuf) != 0) {
        return NULL;
    }

    return mbuf;
}

/**
 * Enqueue DHCP response for TX (lockless)
 */
int ipoe_enqueue_dhcp_response(struct rte_mbuf *mbuf)
{
    if (rte_ring_enqueue(g_sess_mgr.tx_ring, mbuf) != 0) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }

    __atomic_fetch_add(&g_sess_mgr.worker_stats[g_worker_id].dhcp_tx, 1, __ATOMIC_RELAXED);
    return 0;
}

/**
 * TX burst - send DHCP responses (called from TX thread)
 */
uint32_t ipoe_tx_burst(uint16_t port_id, uint16_t queue_id, uint32_t max_burst)
{
    struct rte_mbuf *mbufs[32];
    uint32_t count = max_burst > 32 ? 32 : max_burst;

    uint32_t n_deq = rte_ring_dequeue_burst(g_sess_mgr.tx_ring, (void **)mbufs, count, NULL);
    if (n_deq == 0) {
        return 0;
    }

    uint32_t n_tx = rte_eth_tx_burst(port_id, queue_id, mbufs, n_deq);

    /* Free unsent packets */
    for (uint32_t i = n_tx; i < n_deq; i++) {
        rte_pktmbuf_free(mbufs[i]);
    }

    return n_tx;
}

/**
 * Set worker ID for current thread
 */
void ipoe_set_worker_id(uint32_t worker_id)
{
    g_worker_id = worker_id;
}

/**
 * Aggregate per-worker statistics
 */
void ipoe_aggregate_worker_stats(void)
{
    g_sess_mgr.sessions_created = 0;
    g_sess_mgr.sessions_destroyed = 0;
    g_sess_mgr.auth_success = 0;
    g_sess_mgr.auth_failures = 0;

    for (uint32_t i = 0; i < g_sess_mgr.num_workers; i++) {
        g_sess_mgr.sessions_created += g_sess_mgr.worker_stats[i].sessions_created;
        g_sess_mgr.sessions_destroyed += g_sess_mgr.worker_stats[i].sessions_destroyed;
        g_sess_mgr.auth_success += g_sess_mgr.worker_stats[i].auth_success;
        g_sess_mgr.auth_failures += g_sess_mgr.worker_stats[i].auth_failures;
    }
}

#endif /* HAVE_DPDK */
