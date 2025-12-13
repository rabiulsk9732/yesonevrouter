/**
 * @file nat_session.c
 * @brief NAT Session Table Implementation
 *
 * Hash-based session table with lockless read path using RCU
 */

#include "cpu_scheduler.h"
#include "dpdk_init.h"
#include "log.h"
#include "nat.h"
#include "nat_alg.h"
#include "nat_log.h"
#include "packet.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_DPDK
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>
#endif

/* Forward declarations */
static void init_tsc_freq(void);
static inline uint64_t get_timestamp_cycles(void);
static inline uint64_t get_timestamp_cycles(void);
void nat_session_delete(struct nat_session *session);
static inline void nat_hash_insert(struct nat_worker_data *worker, struct nat_hash_bucket *table,
                                   uint32_t signature, uint32_t session_idx);
static inline void nat_hash_delete(struct nat_worker_data *worker, struct nat_hash_bucket *table,
                                  uint32_t signature, uint32_t session_idx);

/* Global NAT session table (Inside -> Outside) */
static struct nat_session *session_table[NAT_SESSION_TABLE_SIZE];

/* Global NAT session table (Outside -> Inside) */
static struct nat_session *outside_session_table[NAT_SESSION_TABLE_SIZE];

/* Sharded Locks for Inside Table */
static pthread_rwlock_t session_table_locks[NAT_NUM_PARTITIONS];

/* Sharded Locks for Outside Table */
static pthread_rwlock_t outside_session_table_locks[NAT_NUM_PARTITIONS];

/* Global Session Slab (VPP-STYLE: Per-worker pools, NO GLOBAL LOCKS) */
struct nat_session *g_session_slab = NULL;
uint32_t g_max_sessions = NAT_SESSION_TABLE_SIZE;

/* Per-Worker data - declared early for use in alloc/free functions */
struct nat_worker_data g_nat_workers[NAT_MAX_WORKERS];
uint32_t g_num_workers = 1;

/**
 * Initialize NAT Session Slab - VPP-STYLE LOCKLESS
 */
int nat_session_slab_init(uint32_t max_sessions)
{
    g_max_sessions = max_sessions;

    /* Allocate global slab on hugepages */
#ifdef HAVE_DPDK
    g_session_slab = rte_zmalloc("nat_session_slab",
                                sizeof(struct nat_session) * g_max_sessions, 64);
#else
    g_session_slab = calloc(g_max_sessions, sizeof(struct nat_session));
#endif
    if (!g_session_slab) {
        YLOG_ERROR("Failed to allocate session slab");
        return -1;
    }

    YLOG_INFO("NAT Session Slab initialized: %u sessions (%lu MB)",
              g_max_sessions,
              ((uint64_t)g_max_sessions * sizeof(struct nat_session)) / (1024*1024));
    return 0;
}

/**
 * VPP-STYLE: Pure lockless per-worker session allocation
 * Each worker owns a range of session indices - ZERO LOCKS
 */
extern __thread int g_thread_worker_id;

struct nat_session *nat_session_alloc_slab(void)
{
    int worker_id = g_thread_worker_id;
    if (worker_id < 0 || worker_id >= (int)g_num_workers) {
        worker_id = 0;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* LOCKLESS: Each worker has dedicated pool */
    if (worker->session_pool.free_top > 0) {
        uint32_t idx = worker->session_pool.free_stack[--worker->session_pool.free_top];
        worker->session_pool.alloc_success++;
        struct nat_session *s = &g_session_slab[idx];
        memset(s, 0, sizeof(*s));
        s->session_index = idx;
        return s;
    }

    worker->session_pool.alloc_fail++;
    return NULL;  /* No fallback - worker pool exhausted */
}

/**
 * VPP-STYLE: Lockless session free - return to worker's pool
 */
void nat_session_free_slab(struct nat_session *s)
{
    if (!s || s->session_index == 0) return;

    int worker_id = g_thread_worker_id;
    if (worker_id < 0 || worker_id >= (int)g_num_workers) {
        worker_id = 0;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    uint32_t idx = s->session_index;

    /* LOCKLESS: Return to this worker's pool */
    if (worker->session_pool.free_top < worker->session_pool.capacity) {
        worker->session_pool.free_stack[worker->session_pool.free_top++] = idx;
    }
}

/* Helper to get lock index from hash (for legacy path) */
static inline uint32_t get_partition_id(uint32_t hash)
{
    return hash & NAT_PARTITION_MASK;
}

/* Helper to get worker ID from flow hash */
static inline uint32_t get_worker_id(uint32_t hash)
{
    if (g_num_workers == 0) {
        return 0;
    }
    return hash % g_num_workers;
}

/**
 * Initialize NAT session table - VPP-STYLE LOCKLESS
 */
int nat_session_init(void)
{
    /* VPP-STYLE: Per-worker hash tables - NO GLOBAL LOCKS */
    for (int i = 0; i < NAT_MAX_WORKERS; i++) {
        memset(&g_nat_workers[i], 0, sizeof(g_nat_workers[i]));

        uint32_t table_size = NAT_WORKER_TABLE_SIZE * 4;
        g_nat_workers[i].hash_mask = table_size - 1;

#ifdef HAVE_DPDK
        g_nat_workers[i].in2out_hash = rte_zmalloc_socket("nat_hash_in",
            sizeof(struct nat_hash_bucket) * table_size, 64, SOCKET_ID_ANY);
        g_nat_workers[i].out2in_hash = rte_zmalloc_socket("nat_hash_out",
            sizeof(struct nat_hash_bucket) * table_size, 64, SOCKET_ID_ANY);
#else
        g_nat_workers[i].in2out_hash = calloc(table_size, sizeof(struct nat_hash_bucket));
        g_nat_workers[i].out2in_hash = calloc(table_size, sizeof(struct nat_hash_bucket));
#endif
        if (!g_nat_workers[i].in2out_hash || !g_nat_workers[i].out2in_hash) {
            YLOG_ERROR("Failed to allocate NAT hash tables for worker %d", i);
            return -1;
        }
    }

    g_num_workers = 1;
    YLOG_INFO("NAT: VPP-style per-worker hash tables initialized (size %u)", NAT_WORKER_TABLE_SIZE * 4);

    /* Initialize session slab allocator */
    if (nat_session_slab_init(1000000) != 0) {
        YLOG_ERROR("Failed to initialize NAT session slab");
        return -1;
    }

    /* VPP-STYLE: Initialize per-worker session pools (LOCKLESS) */
    /* Use g_num_workers (set by nat_set_num_workers) for better distribution */
    uint32_t actual_workers = g_num_workers > 0 ? g_num_workers : 1;
    if (actual_workers > NAT_MAX_WORKERS) actual_workers = NAT_MAX_WORKERS;
    uint32_t sessions_per_worker = g_max_sessions / actual_workers;
    YLOG_INFO("NAT: Allocating %u sessions per worker (%u workers)", sessions_per_worker, actual_workers);
    for (int i = 0; i < NAT_MAX_WORKERS; i++) {
        g_nat_workers[i].session_pool.capacity = sessions_per_worker;
#ifdef HAVE_DPDK
        g_nat_workers[i].session_pool.free_stack = rte_zmalloc_socket("nat_worker_pool",
            sizeof(uint32_t) * sessions_per_worker, 64, SOCKET_ID_ANY);
#else
        g_nat_workers[i].session_pool.free_stack = calloc(sessions_per_worker, sizeof(uint32_t));
#endif
        if (!g_nat_workers[i].session_pool.free_stack) {
            YLOG_ERROR("Failed to allocate per-worker session pool %d", i);
            return -1;
        }
        /* Pre-fill with session indices from global slab */
        uint32_t start_idx = 1 + (i * sessions_per_worker);
        for (uint32_t j = 0; j < sessions_per_worker && (start_idx + j) < g_max_sessions; j++) {
            g_nat_workers[i].session_pool.free_stack[j] = start_idx + j;
        }
        g_nat_workers[i].session_pool.free_top = sessions_per_worker;
    }
    YLOG_INFO("NAT: VPP-style per-worker session pools (%u sessions/worker, LOCKLESS)", sessions_per_worker);

    /* Initialize TSC for fast timing */
    init_tsc_freq();

    return 0;
}

/* Session ID counter */
static uint64_t session_id_counter = 0;
static pthread_mutex_t session_id_lock = PTHREAD_MUTEX_INITIALIZER;

/* Statistics */
extern struct nat_config g_nat_config;

/**
 * Optimized hash function for session lookup
 * Uses fast XOR-based hash with mixing (faster than FNV-1a)
 * Based on MurmurHash3 finalizer for good distribution
 */
uint32_t nat_hash_inside(uint32_t ip, uint16_t port, uint8_t protocol)
{
    uint32_t hash = 2166136261u;

    hash ^= (ip >> 24) & 0xFF;
    hash *= 16777619;
    hash ^= (ip >> 16) & 0xFF;
    hash *= 16777619;
    hash ^= (ip >> 8) & 0xFF;
    hash *= 16777619;
    hash ^= ip & 0xFF;
    hash *= 16777619;

    hash ^= (port >> 8) & 0xFF;
    hash *= 16777619;
    hash ^= port & 0xFF;
    hash *= 16777619;

    hash ^= protocol;
    hash *= 16777619;

    return hash & NAT_SESSION_HASH_MASK;
}

static inline uint32_t nat_hash_outside(uint32_t ip, uint16_t port, uint8_t protocol)
{
    /* Use different seed for outside lookups to avoid collisions */
    uint64_t combined = ((uint64_t)ip << 24) | ((uint64_t)port << 8) | protocol;

    /* Different mixing constant for outside hash */
    uint32_t hash = (uint32_t)combined;
    hash ^= hash >> 15;
    hash *= 0x2c1b3c6d;
    hash ^= hash >> 12;
    hash *= 0x297a2d39;
    hash ^= hash >> 15;

    /* Mix in IP */
    hash ^= ip;
    hash ^= hash >> 15;
    hash *= 0x2c1b3c6d;
    hash ^= hash >> 12;

    /* Mix in port and protocol */
    hash ^= (uint32_t)port << 16 | protocol;
    hash ^= hash >> 15;

    return hash & NAT_SESSION_HASH_MASK;
}

/**
 * Fast session cache lookup (L1-cache resident hot path)
 * Returns 1 if found, 0 if miss. Outputs outside_ip/port on hit.
 * This is the ultra-fast path that avoids hash table lookup entirely.
 */
static inline uint32_t nat_cache_lookup(struct nat_worker_data *worker, uint32_t hash, uint32_t inside_ip,
                                   uint16_t inside_port, uint8_t protocol)
{
    /* Direct Map Cache (O(1)) */
    uint32_t idx = hash & (NAT_SESSION_CACHE_SIZE - 1);
    struct nat_session_cache_entry *e = &worker->session_cache[idx];

    if (e->valid && e->inside_ip == inside_ip && e->inside_port == inside_port &&
        e->protocol == protocol) {
        return e->session_index;
    }
    return 0; // 0 is invalid index (session 0 is dummy)
}

/**
 * Add session to per-worker cache
 * Uses circular buffer for LRU-like eviction when full
 */
static inline void nat_cache_add(struct nat_worker_data *worker, uint32_t hash, uint32_t inside_ip,
                                 uint16_t inside_port, uint32_t session_index,
                                 uint8_t protocol)
{
    /* Direct Map Replacement */
    uint32_t idx = hash & (NAT_SESSION_CACHE_SIZE - 1);

    struct nat_session_cache_entry *e = &worker->session_cache[idx];
    e->inside_ip = inside_ip;
    e->inside_port = inside_port;
    e->session_index = session_index;
    e->protocol = protocol;
    e->valid = 1;
}

/* Global TSC frequency */
static uint64_t g_tsc_hz = 0;

/**
 * Initialize TSC frequency
 */
static void init_tsc_freq(void)
{
    if (g_tsc_hz == 0) {
        g_tsc_hz = rte_get_timer_hz();
    }
}

/**
 * Get current timestamp in CPU cycles (Zero overhead)
 */
static inline uint64_t get_timestamp_cycles(void)
{
    return rte_rdtsc();
}

/**
 * Get current timestamp in nanoseconds using syscall
 * SLOW PATH ONLY - Do not use in packet processing loop
 */
static inline uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/**
 * VPP-style: Recycle one expired session to make room for new ones
 * Called before allocating new sessions (like VPP's nat_lru_free_one)
 */
static int nat_recycle_expired_session(uint8_t protocol)
{
    uint64_t now = get_timestamp_cycles();
    struct nat_session *session, *oldest = NULL;
    uint64_t oldest_age = 0;

    if (unlikely(g_tsc_hz == 0)) init_tsc_freq();

    /* Scan a portion of hash table for expired sessions */
    /* For efficiency, we check up to 64 buckets per call */
    static uint32_t scan_start = 0;
    uint32_t buckets_checked = 0;

    for (uint32_t i = 0; i < 64 && buckets_checked < NAT_SESSION_TABLE_SIZE; i++) {
        uint32_t idx = (scan_start + i) & NAT_SESSION_HASH_MASK;
        session = session_table[idx];

        while (session) {
            uint64_t age = now - session->last_used_ts;
            uint64_t timeout_cycles = (uint64_t)session->timeout * g_tsc_hz;

            /* Found expired session - delete it immediately */
            if (age > timeout_cycles) {
                struct nat_session *to_delete = session;
                session = session->next; /* Move to next before delete */
                nat_session_delete(to_delete);
                g_nat_config.stats.sessions_timeout++;
                scan_start = idx + 1;
                return 1; /* Freed one session */
            }

            /* Track oldest session for potential LRU eviction */
            if (age > oldest_age) {
                oldest_age = age;
                oldest = session;
            }

            session = session->next;
        }
        buckets_checked++;
    }

    scan_start += 64;

    /* If no expired sessions found but we have an old one, consider evicting it */
    /* Only evict if session is at least 10 seconds old and same protocol */
    if (oldest && oldest->protocol == protocol && oldest_age > 10000000000ULL) {
        nat_session_delete(oldest);
        g_nat_config.stats.sessions_timeout++;
        return 1;
    }

    return 0; /* No session freed */
}

/**
 * Allocate unique session ID
 */
static uint64_t allocate_session_id(void)
{
    /* LOCKLESS: Use atomic increment instead of mutex (VPP-style) */
    return __atomic_add_fetch(&session_id_counter, 1, __ATOMIC_RELAXED);
}

/**
 * Create a NAT session
 * VPP pattern: Try to recycle expired session before allocating new one
 */
struct nat_session *nat_session_create(uint32_t inside_ip, uint16_t inside_port,
                                       uint32_t outside_ip, uint16_t outside_port,
                                       uint8_t protocol, uint32_t dest_ip, uint16_t dest_port)
{
    struct nat_session *session;
    uint32_t hash_inside, hash_outside;
    uint32_t part_in, part_out;

    /* VPP pattern: Try to free an expired session first */
    nat_recycle_expired_session(protocol);

    /* Allocate session from mempool (fast) or fallback to malloc */
    /* Allocate session from slab (fast) */
#ifdef HAVE_DPDK
    session = nat_session_alloc_slab();
#else
    session = calloc(1, sizeof(*session));
#endif
    if (!session) {
        YLOG_ERROR("Failed to allocate NAT session");
        return NULL;
    }

    /* Session is already memset to 0 by alloc_slab */

    /* Fill in session data */
    session->inside_ip = inside_ip;
    session->inside_port = inside_port;
    session->outside_ip = outside_ip;
    session->outside_port = outside_port;
    session->protocol = protocol;
    session->dest_ip = dest_ip;       /* Store destination for NetFlow DELETE */
    session->dest_port = dest_port;

    /* Set session ID */
    session->session_id = allocate_session_id();
    session->subscriber_id = inside_ip; /* Simple subscriber ID = inside IP for now */

    /* Set timestamps */
    uint64_t now = get_timestamp_cycles();
    session->created_ts = now;
    session->last_used_ts = now;

    /* Set timeout based on protocol */
    switch (protocol) {
    case IPPROTO_TCP:
        session->timeout = NAT_TCP_TIMEOUT;
        break;
    case IPPROTO_UDP:
        session->timeout = NAT_UDP_TIMEOUT;
        break;
    case IPPROTO_ICMP:
        session->timeout = NAT_ICMP_TIMEOUT;
        break;
    default:
        session->timeout = NAT_UDP_TIMEOUT;
    }

    /* Default flags */
    if (g_nat_config.eim_enabled)
        session->flags |= NAT_SESSION_FLAG_EIM;
    if (g_nat_config.hairpinning_enabled)
        session->flags |= NAT_SESSION_FLAG_HAIRPIN;

    /* Calculate hash values */
    hash_inside = nat_hash_inside(inside_ip, inside_port, protocol);
    hash_outside = nat_hash_outside(outside_ip, outside_port, protocol);

    part_in = get_partition_id(hash_inside);
    part_out = get_partition_id(hash_outside);

    /* Insert into global hash tables (with locks) */
    /* Lock order: Inside Partition -> Outside Partition to prevent deadlock */
    pthread_rwlock_wrlock(&session_table_locks[part_in]);
    pthread_rwlock_wrlock(&outside_session_table_locks[part_out]);

    /* Insert into global inside hash table */
    session->next = session_table[hash_inside];
    session_table[hash_inside] = session;

    /* Check for collision in outside table */
    struct nat_session *existing = outside_session_table[hash_outside];
    while (existing) {
        if (existing->outside_ip == outside_ip && existing->outside_port == outside_port &&
            existing->protocol == protocol) {

            /* Collision detected! This shouldn't happen with proper port allocation,
             * but we must handle it to guarantee uniqueness. */
            pthread_rwlock_unlock(&outside_session_table_locks[part_out]);
            pthread_rwlock_unlock(&session_table_locks[part_in]);

            YLOG_ERROR("[NAT-COLLISION] duplicate session %u.%u.%u.%u:%u proto=%u",
                       (outside_ip >> 24) & 0xFF, (outside_ip >> 16) & 0xFF,
                       (outside_ip >> 8) & 0xFF, outside_ip & 0xFF, outside_port, protocol);

            /* Free the allocated session memory */
            /* Free the allocated session memory */
#ifdef HAVE_DPDK
             nat_session_free_slab(session);
#else
             free(session);
#endif
            return NULL;
        }
        existing = existing->next_outside;
    }

    /* Insert into global outside hash table */
    session->next_outside = outside_session_table[hash_outside];
    outside_session_table[hash_outside] = session;

    /* Also insert into per-worker table if multi-worker mode (as optimization) */
    /* Note: Sessions are in BOTH tables - worker table for fast lookup, global for cross-worker */
    uint32_t assigned_worker = get_worker_id(hash_inside);

    if (g_num_workers > 1 && assigned_worker < NAT_MAX_WORKERS) {
        /* Insert into assigned worker's table for lockless fast path */
        struct nat_worker_data *worker = &g_nat_workers[assigned_worker];
        __atomic_fetch_add(&worker->sessions_created, 1, __ATOMIC_RELAXED);

        /* Insert into Open Addressing Hash Tables */
        nat_hash_insert(worker, worker->in2out_hash, hash_inside, session->session_index);
        nat_hash_insert(worker, worker->out2in_hash, hash_outside, session->session_index);

        /* Add to fast cache for L1-resident lookups */
        /* Add to fast cache for L1-resident lookups */
        nat_cache_add(worker, hash_inside, inside_ip, inside_port, session->session_index, protocol);
    }

    /* Update statistics */
    __atomic_fetch_add(&g_nat_config.stats.total_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.sessions_created, 1, __ATOMIC_RELAXED);

    /* Note: NAT event logging is now done in nat_translate_snat() where we have
     * access to the packet's destination IP/port. This ensures complete NetFlow records.
     * The logging here is kept for backward compatibility but will be skipped if
     * already logged in nat_translate_snat().
     */

    pthread_rwlock_unlock(&outside_session_table_locks[part_out]);
    pthread_rwlock_unlock(&session_table_locks[part_in]);

    return session;
}

/**
 * Create NAT session - LOCKLESS PATH
 * Used when current worker matches assigned worker (via RSS)
 * Bypasses global locks, inserts only into per-worker tables
 *
 * @param worker_id Current worker ID (must match thread's assigned worker)
 * @param inside_ip Private IP
 * @param inside_port Private port
 * @param outside_ip Public IP (NAT)
 * @param outside_port Public port (NAT)
 * @param protocol Protocol
 * @param dest_ip Destination IP
 * @param dest_port Destination port
 * @return Session pointer or NULL on error
 */
struct nat_session *nat_session_create_lockless(uint32_t worker_id,
                                                 uint32_t inside_ip, uint16_t inside_port,
                                                 uint32_t outside_ip, uint16_t outside_port,
                                                 uint8_t protocol, uint32_t dest_ip, uint16_t dest_port)
{
    struct nat_session *session;
    uint32_t hash_inside, hash_outside;

    /* Validate worker ID */
    if (worker_id >= NAT_MAX_WORKERS || g_num_workers < 1) {
        /* Fall back to locked path */
        return nat_session_create(inside_ip, inside_port, outside_ip, outside_port,
                                  protocol, dest_ip, dest_port);
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* Allocate session from slab (still uses spinlock - future: per-worker pool) */
#ifdef HAVE_DPDK
    session = nat_session_alloc_slab();
#else
    session = calloc(1, sizeof(*session));
#endif
    if (!session) {
        return NULL;
    }

    /* Fill session data */
    session->inside_ip = inside_ip;
    session->inside_port = inside_port;
    session->outside_ip = outside_ip;
    session->outside_port = outside_port;
    session->protocol = protocol;
    session->dest_ip = dest_ip;
    session->dest_port = dest_port;

    /* Session ID - use atomic increment (no mutex) */
    session->session_id = __atomic_fetch_add(&session_id_counter, 1, __ATOMIC_RELAXED);
    session->subscriber_id = inside_ip;

    /* Timestamps */
    uint64_t now = get_timestamp_cycles();
    session->created_ts = now;
    session->last_used_ts = now;

    /* Set timeout */
    switch (protocol) {
    case IPPROTO_TCP:
        session->timeout = NAT_TCP_TIMEOUT;
        break;
    case IPPROTO_UDP:
        session->timeout = NAT_UDP_TIMEOUT;
        break;
    case IPPROTO_ICMP:
        session->timeout = NAT_ICMP_TIMEOUT;
        break;
    default:
        session->timeout = NAT_UDP_TIMEOUT;
    }

    /* Flags */
    if (g_nat_config.eim_enabled)
        session->flags |= NAT_SESSION_FLAG_EIM;
    if (g_nat_config.hairpinning_enabled)
        session->flags |= NAT_SESSION_FLAG_HAIRPIN;

    /* Calculate hashes */
    hash_inside = nat_hash_inside(inside_ip, inside_port, protocol);
    hash_outside = nat_hash_outside(outside_ip, outside_port, protocol);

    /* Insert into per-worker tables ONLY (no global locks!) */
    nat_hash_insert(worker, worker->in2out_hash, hash_inside, session->session_index);
    nat_hash_insert(worker, worker->out2in_hash, hash_outside, session->session_index);

    /* Add to session cache */
    nat_cache_add(worker, hash_inside, inside_ip, inside_port, session->session_index, protocol);

    /* Update per-worker stats (no atomics needed - single writer) */
    worker->sessions_created++;

    /* Update global stats with atomics */
    __atomic_fetch_add(&g_nat_config.stats.total_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.sessions_created, 1, __ATOMIC_RELAXED);

    return session;
}

/**
 * Lookup NAT session by inside (private) 5-tuple
 * VPP pattern: checks session validity and recycles expired sessions
 * Uses per-worker tables when available (lockless), falls back to global table (with locks)
 */
/**
 * Insert into Open Addressing Hash Table
 */
static inline void nat_hash_insert(struct nat_worker_data *worker, struct nat_hash_bucket *table,
                                   uint32_t signature, uint32_t session_idx)
{
    uint32_t mask = worker->hash_mask;
    uint32_t idx = signature & mask;

    /* Linear Probing */
    for (uint32_t i = 0; i < mask; i++) {
        if (table[idx].idx == 0) {
            /* Found empty slot */
            table[idx].sig = signature;
            table[idx].idx = session_idx;
            return;
        }
        idx = (idx + 1) & mask;
    }
    /* Table full? Should not happen with 0.25 load factor */
}

/* Delete from Open Addressing - Requires Backward Shifting */
static inline void nat_hash_delete(struct nat_worker_data *worker, struct nat_hash_bucket *table,
                                  uint32_t signature, uint32_t session_idx)
{
    uint32_t mask = worker->hash_mask;
    uint32_t idx = signature & mask;

    for (uint32_t i = 0; i < mask; i++) {
        if (table[idx].idx == session_idx) {
            /* Found it. Mark as empty. */
             table[idx].idx = 0;
             table[idx].sig = 0;

             /* Re-insert subsequent items until empty slot (Robin Hood / Backward Shift) */
             /* Simplified: Just leave gap? No, linear probing breaks with gaps. */
             /* Must shift back items that hashed to "idx" or before */
             /* For now, simplified SWAP: */

             /* Proper Backward Shift implementation */
             uint32_t hole = idx;
             uint32_t scan = (hole + 1) & mask;

             while (table[scan].idx != 0) {
                 /* uint32_t ideal = table[scan].sig & mask; */
                 /* Re-insert everyone in the cluster to be safe (simplified Robin Hood) */
                 /* Wrap-around logic: (ideal <= hole < scan) OR (scan < ideal <= hole) OR (hole < scan < ideal) */
                 /* simpler: distance from ideal */

                 /* If (scan - ideal) & mask >= (scan - hole) & mask */
                 /* No, let's keep it simple: Re-insert */

                 struct nat_hash_bucket temp = table[scan];
                 table[scan].idx = 0;
                 nat_hash_insert(worker, table, temp.sig, temp.idx);

                 scan = (scan + 1) & mask;
             }
             return;
        }
        if (table[idx].idx == 0) return; /* Not found */
        idx = (idx + 1) & mask;
    }
}

/**
 * PURE LOCKLESS session lookup - never falls back to global locks
 * Use when RSS guarantees flow affinity to current worker
 * Returns NULL if not found in worker's table (no global fallback)
 */
struct nat_session *nat_session_lookup_lockless(uint32_t inside_ip, uint16_t inside_port,
                                                uint8_t protocol, uint32_t worker_id)
{
    if (worker_id >= NAT_MAX_WORKERS) return NULL;

    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    uint32_t hash = nat_hash_inside(inside_ip, inside_port, protocol);

    /* L1 cache lookup */
    uint32_t cached_idx = nat_cache_lookup(worker, hash, inside_ip, inside_port, protocol);
    if (cached_idx != 0) {
        struct nat_session *s = &g_session_slab[cached_idx];
        if (likely(s->inside_ip == inside_ip && s->inside_port == inside_port &&
                   s->protocol == protocol && s->session_index != 0)) {
            s->last_used_ts = get_timestamp_cycles();
            return s;
        }
    }

    /* Per-worker hash table lookup (open addressing) */
    uint32_t mask = worker->hash_mask;
    uint32_t idx = hash & mask;

    for (int i = 0; i < 16; i++) {
        struct nat_hash_bucket *b = &worker->in2out_hash[idx];
        if (b->idx == 0) break;

        if (b->sig == hash) {
            struct nat_session *s = &g_session_slab[b->idx];
            if (s->inside_ip == inside_ip && s->inside_port == inside_port &&
                s->protocol == protocol && s->session_index != 0) {
                nat_cache_add(worker, hash, inside_ip, inside_port, b->idx, protocol);
                s->last_used_ts = get_timestamp_cycles();
                return s;
            }
        }
        idx = (idx + 1) & mask;
    }

    return NULL;  /* Not found - NO GLOBAL FALLBACK */
}

/**
 * Lookup NAT session by inside (private) 5-tuple
 */
struct nat_session *nat_session_lookup_inside(uint32_t inside_ip, uint16_t inside_port,
                                              uint8_t protocol)
{
    uint32_t hash = nat_hash_inside(inside_ip, inside_port, protocol);
    struct nat_session *session;

    /* Try per-worker fast path first */
    extern __thread int g_thread_worker_id;
    int worker_id = g_thread_worker_id;

    if (worker_id >= 0 && worker_id < NAT_MAX_WORKERS && g_num_workers > 1) {
        struct nat_worker_data *worker = &g_nat_workers[worker_id];

        /* FAST PATH: Check L1-resident session cache first */
        uint32_t cached_index = nat_cache_lookup(worker, hash, inside_ip, inside_port, protocol);

        if (likely(cached_index != 0)) {
            struct nat_session *s = &g_session_slab[cached_index];
            /* Double check validity (in case slab was recycled but cache not flushed) */
            /* This is rare but possible if we don't invalidate cache on free */
            if (likely(s->inside_ip == inside_ip && s->inside_port == inside_port &&
                       s->protocol == protocol)) {

                 /* Update timestamp and return */
                 uint64_t now = get_timestamp_cycles();
                 /* Check timeout */
                 if (unlikely(now - s->last_used_ts > (uint64_t)s->timeout * g_tsc_hz)) {
                      if (!(s->flags & NAT_SESSION_FLAG_STATIC)) {
                           /* Expired - let slow path handle deletion or just return NULL?
                              Better to fall through to slow path which handles lookup+expire logic?
                              Or just return NULL and let lookup logic handle it.
                              Actually, standard lookup below handles expiration.
                              Let's just fall through if expired?
                              Or replicate expiration logic? */
                           /* Replicating expiration logic for speed */
                           /* Wait, if it's expired in cache, it might be expired in table too.
                              We should not return it. */
                      } else {
                           s->last_used_ts = now;
                           __atomic_fetch_add(&worker->cache_hits, 1, __ATOMIC_RELAXED);
                           return s;
                      }
                 } else {
                     s->last_used_ts = now;
                     __atomic_fetch_add(&worker->cache_hits, 1, __ATOMIC_RELAXED);
                     return s;
                 }
            }
        }
        __atomic_fetch_add(&worker->cache_misses, 1, __ATOMIC_RELAXED);

        /* Open Addressing Lookup */
        uint32_t mask = worker->hash_mask;
        uint32_t idx = hash & mask;
        struct nat_hash_bucket *bucket;

        /* Max probes = 32 or until hit/empty */
        for (int i=0; i < 32; i++) {
             bucket = &worker->in2out_hash[idx];
             if (bucket->idx == 0) break; /* Not found */

             /* Check signature first (fast filter) */
             if (bucket->sig == hash) {
                 /* Potential Match - Fetch Session */
                 session = &g_session_slab[bucket->idx];
                 if (session->inside_ip == inside_ip && session->inside_port == inside_port &&
                     session->protocol == protocol) {

                     /* HIT */
                     /* Expiration Logic here (same as before) */
                     uint64_t now = get_timestamp_cycles();
                     if (unlikely(now - session->last_used_ts > (uint64_t)session->timeout * g_tsc_hz)) {
                          if (!(session->flags & NAT_SESSION_FLAG_STATIC)) {
                              /* Expired */
                              break;
                          }
                     }
                     session->last_used_ts = now;
                     __atomic_fetch_add(&worker->in2out_hits, 1, __ATOMIC_RELAXED);
                     return session;
                 }
             }
             idx = (idx + 1) & mask;
        }

        /* Not found in worker table - try global table as fallback */
        __atomic_fetch_add(&worker->in2out_misses, 1, __ATOMIC_RELAXED);
    }

    /* Fallback to global table (with locks) - for single worker or cross-worker access */
    uint32_t partition = get_partition_id(hash);
    pthread_rwlock_rdlock(&session_table_locks[partition]);

    session = session_table[hash];

    /* Prefetch next item */
    if (session) {
        __builtin_prefetch(session->next, 0, 1);
    }

    while (session) {
        if (session->inside_ip == inside_ip && session->inside_port == inside_port &&
            session->protocol == protocol) {

            /* VPP pattern: check if session has expired */
            uint64_t now = get_timestamp_cycles();
            uint64_t session_idle_cycles = now - session->last_used_ts;

            if (unlikely(g_tsc_hz == 0)) init_tsc_freq();
            uint64_t timeout_cycles = (uint64_t)session->timeout * g_tsc_hz;

            if (session_idle_cycles > timeout_cycles) {
                 /* Logic handled by global timeout */
            }

            /* Update last used timestamp */
            session->last_used_ts = now;
            /* Update global stats */
            __atomic_fetch_add(&g_nat_config.stats.in2out_hits, 1, __ATOMIC_RELAXED);
            pthread_rwlock_unlock(&session_table_locks[partition]);
            return session;
        }
        session = session->next;
        if (session)
            __builtin_prefetch(session->next, 0, 1);
    }

    /* Not found */
    __atomic_fetch_add(&g_nat_config.stats.in2out_misses, 1, __ATOMIC_RELAXED);
    pthread_rwlock_unlock(&session_table_locks[partition]);
    return NULL;
}

/**
 * Lookup NAT session by outside (public) 5-tuple
 * VPP pattern: checks session validity and recycles expired sessions
 */
struct nat_session *nat_session_lookup_outside(uint32_t outside_ip, uint16_t outside_port,
                                               uint8_t protocol)
{
    uint32_t hash = nat_hash_outside(outside_ip, outside_port, protocol);
    uint32_t partition = get_partition_id(hash);
    struct nat_session *session;

    /* Try per-worker fast path (Lockless) */
    /* Assuming symmetric RSS or software steering */
    extern __thread int g_thread_worker_id;
    int worker_id = g_thread_worker_id;

    if (worker_id >= 0 && worker_id < NAT_MAX_WORKERS && g_num_workers > 1) {
        struct nat_worker_data *worker = &g_nat_workers[worker_id];

        uint32_t mask = worker->hash_mask;
        uint32_t idx = hash & mask;
        struct nat_hash_bucket *bucket;

        /* Max probes = 32 */
        for (int i=0; i < 32; i++) {
             bucket = &worker->out2in_hash[idx];
             if (bucket->idx == 0) break;

             if (bucket->sig == hash) {
                 session = &g_session_slab[bucket->idx];
                 if (session->outside_ip == outside_ip && session->outside_port == outside_port &&
                     session->protocol == protocol) {

                     /* HIT */
                     uint64_t now = get_timestamp_cycles();
                     if (unlikely(now - session->last_used_ts > (uint64_t)session->timeout * g_tsc_hz)) {
                          if (!(session->flags & NAT_SESSION_FLAG_STATIC)) {
                              break; /* Expired */
                          }
                     }
                     session->last_used_ts = now;
                     __atomic_fetch_add(&worker->out2in_hits, 1, __ATOMIC_RELAXED);
                     return session;
                 }
             }
             idx = (idx + 1) & mask;
        }
        __atomic_fetch_add(&worker->out2in_misses, 1, __ATOMIC_RELAXED);
    }

    /* Fallback to global table (with locks) */
    pthread_rwlock_rdlock(&outside_session_table_locks[partition]);

    session = outside_session_table[hash];

    while (session) {
        if (session->outside_ip == outside_ip && session->outside_port == outside_port &&
            session->protocol == protocol) {

            /* VPP pattern: check if session has expired */
            uint64_t now = get_timestamp_cycles();
            uint64_t session_idle_cycles = now - session->last_used_ts;

            if (unlikely(g_tsc_hz == 0)) init_tsc_freq();
            uint64_t timeout_cycles = (uint64_t)session->timeout * g_tsc_hz;

            if (session_idle_cycles > timeout_cycles) {
                /* Session expired - delete it */
                pthread_rwlock_unlock(&outside_session_table_locks[partition]);
                nat_session_delete(session);
                g_nat_config.stats.sessions_timeout++;
                return NULL; /* Return NULL so DNAT lookup fails cleanly */
            }

            /* Update last used timestamp */
            session->last_used_ts = now;
            pthread_rwlock_unlock(&outside_session_table_locks[partition]);
            return session;
        }
        session = session->next_outside;
    }

    pthread_rwlock_unlock(&outside_session_table_locks[partition]);

    g_nat_config.stats.session_not_found++;
    return NULL;
}

/**
 * Delete a NAT session
 */
void nat_session_delete(struct nat_session *session)
{
    if (!session)
        return;

    uint32_t hash_in = nat_hash_inside(session->inside_ip, session->inside_port, session->protocol);

    /* Release resources (IP and Port) */
    struct nat_pool *pool = nat_pool_get_by_ip(session->outside_ip);
    if (pool) {
        /* Release port first (if not ICMP) */
        if (session->protocol != IPPROTO_ICMP) {
            nat_release_port(pool, session->outside_ip, session->outside_port, session->protocol);
        }
        /* Release IP (decrement refcount) */
        nat_pool_release_ip(pool, session->outside_ip);
    }
    uint32_t hash_out =
        nat_hash_outside(session->outside_ip, session->outside_port, session->protocol);

    /* Log Delete Event before freeing */
    extern void nat_logger_log_event(
        uint8_t event_type, uint32_t original_ip, uint16_t original_port, uint32_t translated_ip,
        uint16_t translated_port, uint32_t dest_ip, uint16_t dest_port, uint8_t protocol);

    /* 2=DELETE */
    nat_logger_log_event(2, session->inside_ip, session->inside_port, session->outside_ip,
                         session->outside_port, 0, 0, session->protocol);

    /* Remove from global inside hash table */

    uint32_t part_in = get_partition_id(hash_in);
    uint32_t part_out = get_partition_id(hash_out);

    struct nat_session **prev;

    /* Lock both tables */
    pthread_rwlock_wrlock(&session_table_locks[part_in]);
    pthread_rwlock_wrlock(&outside_session_table_locks[part_out]);

    /* Find and remove from inside hash table */
    prev = &session_table[hash_in];
    while (*prev) {
        if (*prev == session) {
            *prev = session->next;
            break;
        }
        prev = &(*prev)->next;
    }

    /* Remove from global outside hash table */
    prev = &outside_session_table[hash_out];
    while (*prev) {
        if (*prev == session) {
            *prev = session->next_outside;
            break;
        }
        prev = &(*prev)->next_outside;
    }

    /* Remove from per-worker hash tables if applicable */
    /* Note: We need to know which worker owns this session.
       Ideally session has a worker_id field or we recompute hash. */
    if (g_num_workers > 1) {
         uint32_t assigned_worker = get_worker_id(hash_in);
         if (assigned_worker < NAT_MAX_WORKERS) {
             struct nat_worker_data *worker = &g_nat_workers[assigned_worker];
             nat_hash_delete(worker, worker->in2out_hash, hash_in, session->session_index);
             nat_hash_delete(worker, worker->out2in_hash, hash_out, session->session_index);
         }
    }

    /* Update statistics */
    __atomic_fetch_sub(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.sessions_deleted, 1, __ATOMIC_RELAXED);

    pthread_rwlock_unlock(&outside_session_table_locks[part_out]);
    pthread_rwlock_unlock(&session_table_locks[part_in]);

    /* Release port/IP logic - DISABLED for now */
    /* With single-IP pool and EIM for ICMP, we don't need to release IP */
    /* The IP stays allocated as long as router is running */
    /* TODO: For multi-IP pools or port-block allocation, implement proper release */

    /* Log event using stored destination from session */
    nat_log_session_event(NAT_EVENT_DELETE, session->inside_ip, session->inside_port,
                          session->outside_ip, session->outside_port,
                          session->dest_ip, session->dest_port,
                          session->protocol, 0, 0);

    /* Free session memory */
    /* Free session memory */
#ifdef HAVE_DPDK
    nat_session_free_slab(session);
#else
    free(session);
#endif
}

/**
 * Timeout expired sessions
 */
/**
 * Timeout expired sessions
 * Optimized: Incremental scan by partition to avoid latency spikes
 */
int nat_session_timeout_check(void)
{
    static uint32_t current_scan_partition = 0;
    /* Process ~1.6% of table per call (16 partitions out of 1024)
     * At 10 calls/sec, full scan takes ~6.4 seconds.
     */
    const uint32_t partitions_to_scan = 16;

    uint64_t now = get_timestamp_cycles();
    int deleted = 0;

    if (unlikely(g_tsc_hz == 0)) init_tsc_freq();

    for (uint32_t count = 0; count < partitions_to_scan; count++) {
        uint32_t p = current_scan_partition++;
        if (current_scan_partition >= NAT_NUM_PARTITIONS) {
            current_scan_partition = 0;
        }

        /* Lock the partition */
        pthread_rwlock_wrlock(&session_table_locks[p]);

        /* Iterate all buckets belonging to this partition */
        /* Since hash mapping is modulo, buckets are strided by NUM_PARTITIONS */
        for (uint32_t i = p; i < NAT_SESSION_TABLE_SIZE; i += NAT_NUM_PARTITIONS) {
            struct nat_session **prev = &session_table[i];
            struct nat_session *session;

            while ((session = *prev) != NULL) {
                /* Check if session has timed out */
                uint64_t age = now - session->last_used_ts;
                uint64_t timeout_cycles = (uint64_t)session->timeout * g_tsc_hz;

                if (age > timeout_cycles) {
                    /* Need to remove from outside table too */
                    uint32_t hash_out = nat_hash_outside(session->outside_ip, session->outside_port,
                                                         session->protocol);
                    uint32_t part_out = get_partition_id(hash_out);

                    /* Lock outside partition */
                    /* POTENTIAL DEADLOCK WARNING: We hold locks[p] and try to verify
                     * locks[part_out] Correct order should be enforced or use trylock. For now,
                     * proceed as before but minimizing scope is safer. Ideally we should unlock[p],
                     * lock[part_out], lock[p] verify match. But that complexity is high. For now,
                     * this mimics original logic but on smaller scope.
                     */
                    pthread_rwlock_wrlock(&outside_session_table_locks[part_out]);

                    /* Remove from outside table */
                    struct nat_session **prev_out = &outside_session_table[hash_out];
                    while (*prev_out) {
                        if (*prev_out == session) {
                            *prev_out = session->next_outside;
                            break;
                        }
                        prev_out = &(*prev_out)->next_outside;
                    }

                    pthread_rwlock_unlock(&outside_session_table_locks[part_out]);

                    /* Remove from inside list already covered by locks[p] */
                    *prev = session->next;

                    /* Return IP to pool */
                    if (g_nat_config.num_pools > 0) {
                        nat_pool_release_ip(&g_nat_config.pools[0], session->outside_ip);
                    }

                    /* Log event */
                    nat_log_session_event(NAT_EVENT_DELETE, session->inside_ip,
                                          session->inside_port, session->outside_ip,
                                          session->outside_port, 0,
                                          0, /* Dest info not stored in SNAT session */
                                          session->protocol, 0, 0);

                    /* Update statistics */
                    __atomic_fetch_sub(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&g_nat_config.stats.sessions_timeout, 1, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&g_nat_config.stats.sessions_deleted, 1, __ATOMIC_RELAXED);

            /* Free the allocated session memory */
#ifdef HAVE_DPDK
             nat_session_free_slab(session);
#else
             free(session);
#endif
                    deleted++;
                } else {
                    prev = &session->next;
                }
            }
        }

        pthread_rwlock_unlock(&session_table_locks[p]);
    }

    return deleted;
}

/**
 * Clear all NAT sessions
 */
void nat_clear_sessions(void)
{
    for (uint32_t p = 0; p < NAT_NUM_PARTITIONS; p++) {
        pthread_rwlock_wrlock(&session_table_locks[p]);
        pthread_rwlock_wrlock(&outside_session_table_locks[p]);

        for (uint32_t i = p; i < NAT_SESSION_TABLE_SIZE; i += NAT_NUM_PARTITIONS) {
            struct nat_session *session = session_table[i];
            while (session) {
                struct nat_session *next = session->next;
                free(session);
                session = next;
            }
            session_table[i] = NULL;
            outside_session_table[i] = NULL;
        }

        pthread_rwlock_unlock(&outside_session_table_locks[p]);
        pthread_rwlock_unlock(&session_table_locks[p]);
    }

    /* Reset statistics */
    __atomic_store_n(&g_nat_config.stats.active_sessions, 0, __ATOMIC_RELAXED);
}

/**
 * Print NAT sessions with enhanced details
 */
void nat_print_sessions(void)
{
    uint64_t now = get_timestamp_ns();

    /* Print header */
    printf("\n%-15s %-6s %-15s %-6s %-8s %-10s %-10s %-12s %-12s %-10s %-10s %-8s %-6s\n",
           "Inside IP", "Port", "Outside IP", "Port", "Proto", "Pkts In", "Pkts Out", "Bytes In",
           "Bytes Out", "Age (s)", "Timeout (s)", "Last Act", "Flags");
    printf("%-15s %-6s %-15s %-6s %-8s %-10s %-10s %-12s %-12s %-10s %-10s %-8s %-6s\n",
           "----------", "----", "-----------", "----", "------", "--------", "---------",
           "----------", "-----------", "--------", "----------", "--------", "-----");

    uint32_t session_count = 0;

    for (uint32_t p = 0; p < NAT_NUM_PARTITIONS; p++) {
        pthread_rwlock_rdlock(&session_table_locks[p]);

        for (uint32_t i = p; i < NAT_SESSION_TABLE_SIZE; i += NAT_NUM_PARTITIONS) {
            struct nat_session *session = session_table[i];
            while (session) {
                char inside_ip[16], outside_ip[16];
                struct in_addr addr;

                addr.s_addr = htonl(session->inside_ip);
                inet_ntop(AF_INET, &addr, inside_ip, sizeof(inside_ip));
                addr.s_addr = htonl(session->outside_ip);
                inet_ntop(AF_INET, &addr, outside_ip, sizeof(outside_ip));

                /* Calculate session age (seconds) */
                uint64_t age_ns = now - session->created_ts;
                uint32_t age_sec = (uint32_t)(age_ns / 1000000000ULL);

                /* Calculate timeout remaining (seconds) */
                uint64_t idle_ns = now - session->last_used_ts;
                uint32_t idle_sec = (uint32_t)(idle_ns / 1000000000ULL);
                int32_t timeout_remaining = (int32_t)session->timeout - (int32_t)idle_sec;
                if (timeout_remaining < 0) {
                    timeout_remaining = 0;
                }

                /* Calculate last activity age (seconds) */
                uint64_t last_act_ns = now - session->last_used_ts;
                uint32_t last_act_sec = (uint32_t)(last_act_ns / 1000000000ULL);

                /* Build flags string */
                char flags_str[16] = "";
                if (session->flags & NAT_SESSION_FLAG_EIM) {
                    strcat(flags_str, "E");
                }
                if (session->flags & NAT_SESSION_FLAG_HAIRPIN) {
                    strcat(flags_str, "H");
                }
                if (session->flags & NAT_SESSION_FLAG_DETERMINISTIC) {
                    strcat(flags_str, "D");
                }
                if (session->flags & NAT_SESSION_FLAG_STATIC) {
                    strcat(flags_str, "S");
                }
                if (flags_str[0] == '\0') {
                    strcpy(flags_str, "-");
                }

                const char *proto_str = session->protocol == IPPROTO_TCP    ? "TCP"
                                        : session->protocol == IPPROTO_UDP  ? "UDP"
                                        : session->protocol == IPPROTO_ICMP ? "ICMP"
                                                                            : "OTHER";

                printf("  %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%s) pkts=%lu/%lu bytes=%lu/%lu age=%u timeout=%d idle=%u flags=%s\n",
                       (session->inside_ip >> 24) & 0xFF, (session->inside_ip >> 16) & 0xFF,
                       (session->inside_ip >> 8) & 0xFF, session->inside_ip & 0xFF,
                       session->inside_port, (session->outside_ip >> 24) & 0xFF,
                       (session->outside_ip >> 16) & 0xFF, (session->outside_ip >> 8) & 0xFF,
                       session->outside_ip & 0xFF, session->outside_port, proto_str,
                       session->packets_in, session->packets_out, session->bytes_in,
                       session->bytes_out, age_sec, timeout_remaining, last_act_sec, flags_str);

                session = session->next;
                session_count++;
            }
        }

        pthread_rwlock_unlock(&session_table_locks[p]);
    }

    printf("\nTotal active sessions: %u\n", session_count);
    printf("Global active sessions counter: %lu\n", g_nat_config.stats.active_sessions);
}

/**
 * Iterate all NAT sessions with callback
 * Used by natexport for active timeout scanning (RFC 8158)
 * @param callback Function to call for each session
 * @param user_data User data passed to callback
 */
void nat_session_iterate(void (*callback)(struct nat_session *session, void *user_data),
                         void *user_data)
{
    if (!callback) {
        return;
    }

    for (uint32_t p = 0; p < NAT_NUM_PARTITIONS; p++) {
        pthread_rwlock_rdlock(&session_table_locks[p]);

        for (uint32_t i = p; i < NAT_SESSION_TABLE_SIZE; i += NAT_NUM_PARTITIONS) {
            struct nat_session *session = session_table[i];

            while (session) {
                /* Call callback with session */
                callback(session, user_data);
                session = session->next;
            }
        }

        pthread_rwlock_unlock(&session_table_locks[p]);
    }
}
