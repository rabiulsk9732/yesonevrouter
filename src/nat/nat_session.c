/**
 * @file nat_session.c
 * @brief NAT Session Table Implementation
 *
 * Hash-based session table with lockless read path using RCU
 */

#include "log.h"
#include "nat.h"
#include "packet.h"
#include "cpu_scheduler.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_DPDK
#include <rte_mempool.h>
#endif

/* Forward declarations */
static inline uint64_t get_timestamp_ns(void);
void nat_session_delete(struct nat_session *session);

/* Global NAT session table (Inside -> Outside) */
static struct nat_session *session_table[NAT_SESSION_TABLE_SIZE];

/* Global NAT session table (Outside -> Inside) */
static struct nat_session *outside_session_table[NAT_SESSION_TABLE_SIZE];

/* Sharded Locks for Inside Table */
static pthread_rwlock_t session_table_locks[NAT_NUM_PARTITIONS];

/* Sharded Locks for Outside Table */
static pthread_rwlock_t outside_session_table_locks[NAT_NUM_PARTITIONS];

/* Session memory pool for high-performance allocation */
#ifdef HAVE_DPDK
static struct rte_mempool *g_session_pool = NULL;
#define NAT_SESSION_POOL_SIZE 65536 /* 64K sessions */
#define NAT_SESSION_CACHE_SIZE 256  /* Per-core cache */
#endif

/*
 * Per-Worker Session Tables for Lockless Operation
 * Each worker has its own session table, eliminating lock contention.
 * Sessions are assigned to workers based on flow hash.
 * Struct definition moved to nat.h for external access.
 */

struct nat_worker_data g_nat_workers[NAT_MAX_WORKERS];
uint32_t g_num_workers = 1;

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
 * Initialize NAT session table
 */
int nat_session_init(void)
{
    for (int i = 0; i < NAT_NUM_PARTITIONS; i++) {
        if (pthread_rwlock_init(&session_table_locks[i], NULL) != 0) {
            return -1;
        }
        if (pthread_rwlock_init(&outside_session_table_locks[i], NULL) != 0) {
            return -1;
        }
    }

    /* Initialize per-worker session tables */
    for (int i = 0; i < NAT_MAX_WORKERS; i++) {
        memset(&g_nat_workers[i], 0, sizeof(g_nat_workers[i]));
    }
    
    /* Number of workers will be set dynamically based on RX threads */
    /* Default to 1 worker (legacy mode) */
    g_num_workers = 1;
    
    YLOG_INFO("NAT: Initialized per-worker session tables (max %d workers)", NAT_MAX_WORKERS);

#ifdef HAVE_DPDK
    /* Create session mempool for zero-malloc allocation */
    g_session_pool =
        rte_mempool_create("nat_session_pool", NAT_SESSION_POOL_SIZE, sizeof(struct nat_session),
                           NAT_SESSION_CACHE_SIZE, 0, NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
    if (!g_session_pool) {
        YLOG_ERROR("Failed to create NAT session mempool");
        return -1;
    }
    YLOG_INFO("NAT session mempool created: %u sessions", NAT_SESSION_POOL_SIZE);
#endif

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
static inline uint32_t nat_hash_inside(uint32_t ip, uint16_t port, uint8_t protocol)
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
 * Get current timestamp in nanoseconds
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
    uint64_t now = get_timestamp_ns();
    struct nat_session *session, *oldest = NULL;
    uint64_t oldest_age = 0;

    /* Scan a portion of hash table for expired sessions */
    /* For efficiency, we check up to 64 buckets per call */
    static uint32_t scan_start = 0;
    uint32_t buckets_checked = 0;

    for (uint32_t i = 0; i < 64 && buckets_checked < NAT_SESSION_TABLE_SIZE; i++) {
        uint32_t idx = (scan_start + i) & NAT_SESSION_HASH_MASK;
        session = session_table[idx];

        while (session) {
            uint64_t age_ns = now - session->last_used_ts;
            uint64_t timeout_ns = (uint64_t)session->timeout * 1000000000ULL;

            /* Found expired session - delete it immediately */
            if (age_ns > timeout_ns) {
                struct nat_session *to_delete = session;
                session = session->next; /* Move to next before delete */
                nat_session_delete(to_delete);
                g_nat_config.stats.sessions_timeout++;
                scan_start = idx + 1;
                return 1; /* Freed one session */
            }

            /* Track oldest session for potential LRU eviction */
            if (age_ns > oldest_age) {
                oldest_age = age_ns;
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
    uint64_t id;
    pthread_mutex_lock(&session_id_lock);
    id = ++session_id_counter;
    pthread_mutex_unlock(&session_id_lock);
    return id;
}

/**
 * Create a NAT session
 * VPP pattern: Try to recycle expired session before allocating new one
 */
struct nat_session *nat_session_create(uint32_t inside_ip, uint16_t inside_port,
                                       uint32_t outside_ip, uint16_t outside_port, uint8_t protocol)
{
    struct nat_session *session;
    uint32_t hash_inside, hash_outside;
    uint32_t part_in, part_out;

    /* VPP pattern: Try to free an expired session first */
    nat_recycle_expired_session(protocol);

    /* Allocate session from mempool (fast) or fallback to malloc */
#ifdef HAVE_DPDK
    if (g_session_pool && rte_mempool_get(g_session_pool, (void **)&session) == 0) {
        memset(session, 0, sizeof(*session));
    } else {
        session = calloc(1, sizeof(*session));
    }
#else
    session = calloc(1, sizeof(*session));
#endif
    if (!session) {
        YLOG_ERROR("Failed to allocate NAT session");
        return NULL;
    }

    /* Fill in session data */
    session->inside_ip = inside_ip;
    session->inside_port = inside_port;
    session->outside_ip = outside_ip;
    session->outside_port = outside_port;
    session->protocol = protocol;

    /* Set session ID */
    session->session_id = allocate_session_id();
    session->subscriber_id = inside_ip; /* Simple subscriber ID = inside IP for now */

    /* Set timestamps */
    uint64_t now = get_timestamp_ns();
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
    session->eim = g_nat_config.eim_enabled ? 1 : 0;
    session->hairpin = g_nat_config.hairpinning_enabled ? 1 : 0;

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

    /* Insert into global outside hash table */
    session->next_outside = outside_session_table[hash_outside];
    outside_session_table[hash_outside] = session;
    
    /* Also insert into per-worker table if multi-worker mode (as optimization) */
    /* Note: Sessions are in BOTH tables - worker table for fast lookup, global for cross-worker */
    uint32_t assigned_worker = get_worker_id(hash_inside);
    
    if (g_num_workers > 1 && assigned_worker < NAT_MAX_WORKERS) {
        /* Insert into assigned worker's table for lockless fast path */
        /* We'll use a separate pointer or duplicate the session reference */
        /* For Phase 1: Just track in worker stats, actual table insertion in Phase 2 */
        struct nat_worker_data *worker = &g_nat_workers[assigned_worker];
        __atomic_fetch_add(&worker->sessions_created, 1, __ATOMIC_RELAXED);
    }

    /* Update statistics */
    __atomic_fetch_add(&g_nat_config.stats.total_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&g_nat_config.stats.sessions_created, 1, __ATOMIC_RELAXED);

    pthread_rwlock_unlock(&outside_session_table_locks[part_out]);
    pthread_rwlock_unlock(&session_table_locks[part_in]);

    return session;
}

/**
 * Lookup NAT session by inside (private) 5-tuple
 * VPP pattern: checks session validity and recycles expired sessions
 * Uses per-worker tables when available (lockless), falls back to global table (with locks)
 */
struct nat_session *nat_session_lookup_inside(uint32_t inside_ip, uint16_t inside_port,
                                              uint8_t protocol)
{
    uint32_t hash = nat_hash_inside(inside_ip, inside_port, protocol);
    struct nat_session *session;
    
    /* Try per-worker table first (lockless) */
    extern __thread int g_thread_worker_id;
    int worker_id = g_thread_worker_id;
    
    if (worker_id >= 0 && worker_id < NAT_MAX_WORKERS && g_num_workers > 1) {
        /* Use per-worker table - lockless! */
        uint32_t worker_hash = hash & NAT_WORKER_TABLE_MASK;
        struct nat_worker_data *worker = &g_nat_workers[worker_id];
        
        session = worker->in2out_table[worker_hash];
        
        /* Prefetch next item */
        if (session) {
            __builtin_prefetch(session->next, 0, 1);
        }
        
        while (session) {
            if (session->inside_ip == inside_ip && session->inside_port == inside_port &&
                session->protocol == protocol) {
                
                /* Check if session has expired */
                uint64_t now = get_timestamp_ns();
                uint64_t session_age_ns = now - session->last_used_ts;
                uint64_t timeout_ns = (uint64_t)session->timeout * 1000000000ULL;
                
                if (session_age_ns > timeout_ns) {
                    /* Session expired - need to delete (requires lock) */
                    /* Fall through to delete via global table path */
                    break;
                }
                
                /* Update last used timestamp */
                session->last_used_ts = now;
                __atomic_fetch_add(&worker->in2out_hits, 1, __ATOMIC_RELAXED);
                return session;
            }
            session = session->next;
            if (session)
                __builtin_prefetch(session->next, 0, 1);
        }
        
        /* Not found in worker table - try global table as fallback */
        if (!session) {
            __atomic_fetch_add(&worker->in2out_misses, 1, __ATOMIC_RELAXED);
        }
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
            uint64_t now = get_timestamp_ns();
            uint64_t session_age_ns = now - session->last_used_ts;
            uint64_t timeout_ns = (uint64_t)session->timeout * 1000000000ULL;

            if (session_age_ns > timeout_ns) {
                /* Session expired - delete it (need write lock) */
                pthread_rwlock_unlock(&session_table_locks[partition]);
                nat_session_delete(session);
                g_nat_config.stats.sessions_timeout++;
                return NULL; /* Return NULL so caller creates new session */
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

    /* Read lock for lookup */
    pthread_rwlock_rdlock(&outside_session_table_locks[partition]);

    session = outside_session_table[hash];

    while (session) {
        if (session->outside_ip == outside_ip && session->outside_port == outside_port &&
            session->protocol == protocol) {

            /* VPP pattern: check if session has expired */
            uint64_t now = get_timestamp_ns();
            uint64_t session_age_ns = now - session->last_used_ts;
            uint64_t timeout_ns = (uint64_t)session->timeout * 1000000000ULL;

            if (session_age_ns > timeout_ns) {
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
    uint32_t hash_out =
        nat_hash_outside(session->outside_ip, session->outside_port, session->protocol);

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

    /* Find and remove from outside hash table */
    prev = &outside_session_table[hash_out];
    while (*prev) {
        if (*prev == session) {
            *prev = session->next_outside;
            break;
        }
        prev = &(*prev)->next_outside;
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

    /* Free session memory */
#ifdef HAVE_DPDK
    if (g_session_pool) {
        rte_mempool_put(g_session_pool, session);
    } else {
        free(session);
    }
#else
    free(session);
#endif
}

/**
 * Timeout expired sessions
 */
int nat_session_timeout_check(void)
{
    uint64_t now = get_timestamp_ns();
    int deleted = 0;

    /* Iterate over all partitions */
    for (uint32_t p = 0; p < NAT_NUM_PARTITIONS; p++) {
        pthread_rwlock_wrlock(&session_table_locks[p]);

        /* Iterate over buckets in this partition */
        /* Since partition = hash % NUM_PARTITIONS, we can iterate all buckets
           where bucket_index % NUM_PARTITIONS == p */
        /* Or simpler: just iterate chunks if we organized it that way.
           But our hash mapping is modulo. So we must iterate ALL buckets and check partition?
           No, that's inefficient.

           Actually, with modulo hashing, bucket 'i' belongs to partition 'i % NUM_PARTITIONS'.
           So we can just iterate i = p; i < SIZE; i += NUM_PARTITIONS.
        */

        for (uint32_t i = p; i < NAT_SESSION_TABLE_SIZE; i += NAT_NUM_PARTITIONS) {
            struct nat_session **prev = &session_table[i];
            struct nat_session *session;

            while ((session = *prev) != NULL) {
                /* Check if session has timed out */
                uint64_t age_ns = now - session->last_used_ts;
                uint64_t age_sec = age_ns / 1000000000ULL;

                if (age_sec > session->timeout) {
                    /* Need to remove from outside table too */
                    uint32_t hash_out = nat_hash_outside(session->outside_ip, session->outside_port,
                                                         session->protocol);
                    uint32_t part_out = get_partition_id(hash_out);

                    /* Lock outside partition */
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

                    /* Remove from inside list */
                    *prev = session->next;

                    /* Return IP to pool */
                    if (g_nat_config.num_pools > 0) {
                        nat_pool_release_ip(&g_nat_config.pools[0], session->outside_ip);
                    }

                    /* Update statistics */
                    __atomic_fetch_sub(&g_nat_config.stats.active_sessions, 1, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&g_nat_config.stats.sessions_timeout, 1, __ATOMIC_RELAXED);

                    /* Free session */
                    free(session);
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
           "Inside IP", "Port", "Outside IP", "Port", "Proto", "Pkts In", "Pkts Out",
           "Bytes In", "Bytes Out", "Age (s)", "Timeout (s)", "Last Act", "Flags");
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
                char flags[16] = "";
                if (session->eim) {
                    strcat(flags, "E");
                }
                if (session->hairpin) {
                    strcat(flags, "H");
                }
                if (session->deterministic) {
                    strcat(flags, "D");
                }
                if (flags[0] == '\0') {
                    strcpy(flags, "-");
                }

                const char *proto_str = session->protocol == IPPROTO_TCP    ? "TCP"
                                      : session->protocol == IPPROTO_UDP    ? "UDP"
                                      : session->protocol == IPPROTO_ICMP   ? "ICMP"
                                                                           : "OTHER";

                printf("%-15s %-6u %-15s %-6u %-8s %-10lu %-10lu %-12lu %-12lu %-10u %-10d %-8u %-6s\n",
                       inside_ip, session->inside_port, outside_ip, session->outside_port,
                       proto_str, session->packets_in, session->packets_out,
                       session->bytes_in, session->bytes_out,
                       age_sec, timeout_remaining, last_act_sec, flags);

                session = session->next;
                session_count++;
            }
        }

        pthread_rwlock_unlock(&session_table_locks[p]);
    }

    printf("\nTotal active sessions: %u\n", session_count);
    printf("Global active sessions counter: %lu\n", g_nat_config.stats.active_sessions);
}
