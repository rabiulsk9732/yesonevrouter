/**
 * @file nat_worker.c
 * @brief NAT Per-Worker Table Management
 *
 * VPP-STYLE LOCKLESS ARCHITECTURE:
 * - Per-worker session tables (no global fallback)
 * - Worker handoff rings for cross-worker packet routing
 * - Flow-to-worker mapping ensures same flow -> same worker
 */

#include "cpu_scheduler.h"
#include "nat.h"
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DPDK
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#endif

/* Access to internal worker data - defined in nat_session.c */
extern struct nat_worker_data g_nat_workers[];
extern uint32_t g_num_workers;

/**
 * Set number of NAT workers (called from RX thread initialization)
 */
void nat_set_num_workers(uint32_t num_workers)
{
    if (num_workers > 0 && num_workers <= NAT_MAX_WORKERS) {
        g_num_workers = num_workers;
    }
}

/**
 * Get number of NAT workers
 */
uint32_t nat_get_num_workers(void)
{
    return g_num_workers;
}

/**
 * Get per-worker statistics
 * Note: Returns pointer to worker data (not a copy) for efficiency
 */
struct nat_worker_data *nat_get_worker_stats_ptr(uint32_t worker_id)
{
    if (worker_id >= NAT_MAX_WORKERS) {
        return NULL;
    }
    return &g_nat_workers[worker_id];
}

/**
 * Initialize per-worker port pool for LOCKLESS allocation
 * Each worker gets its own NAT IP and port range
 */
void nat_worker_port_pool_init(uint32_t worker_id, uint32_t nat_ip, uint16_t port_min,
                               uint16_t port_max)
{
    if (worker_id >= NAT_MAX_WORKERS) {
        return;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* Set NAT IP for this worker */
    worker->port_pool.nat_ip = nat_ip;
    worker->port_pool.port_min = port_min > 0 ? port_min : 1024;
    worker->port_pool.port_max = port_max > 0 ? port_max : 65535;
    worker->port_pool.next_hint = worker->port_pool.port_min;
    worker->port_pool.ports_allocated = 0;
    worker->port_pool.alloc_success = 0;
    worker->port_pool.alloc_fail = 0;

    /* Clear bitmap (all ports free) */
    memset(worker->port_pool.port_bitmap, 0, sizeof(worker->port_pool.port_bitmap));

    /* Mark reserved ports (0-1023) as used */
    for (int i = 0; i < 32; i++) {
        worker->port_pool.port_bitmap[i] = 0xFFFFFFFF; /* Mark first 1024 ports as used */
    }
}

/**
 * Allocate port from worker's bitmap - LOCKLESS!
 * Uses atomic CAS for truly lock-free allocation
 * Preserves port parity (RFC 6888) when preferred_port is specified
 */
uint16_t nat_worker_alloc_port_lockless(uint32_t worker_id, uint16_t preferred_port)
{
    if (worker_id >= NAT_MAX_WORKERS) {
        return 0;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    uint16_t port_min = worker->port_pool.port_min;
    uint16_t port_max = worker->port_pool.port_max;
    uint16_t start_port;

    /* Try preferred port first (RFC 6888 parity preservation) */
    if (preferred_port >= port_min && preferred_port <= port_max) {
        uint32_t word = preferred_port / 32;
        uint32_t bit = preferred_port % 32;
        uint32_t mask = 1U << bit;

        /* FIXED: Use atomic CAS to prevent race conditions */
        uint64_t old_val = worker->port_pool.port_bitmap[word];
        uint64_t new_val = old_val | mask;

        if (!(old_val & mask)) {
            /* Try to atomically set the bit */
            if (__atomic_compare_exchange_n(&worker->port_pool.port_bitmap[word], &old_val, new_val,
                                            true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                /* Success! */
                __atomic_fetch_add(&worker->port_pool.ports_allocated, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&worker->port_pool.alloc_success, 1, __ATOMIC_RELAXED);
                return preferred_port;
            }
        }
        /* Preferred not available, try same parity */
        start_port = (preferred_port & 1) ? (port_min | 1) : (port_min & ~1);
    } else {
        start_port = worker->port_pool.next_hint;
        if (start_port < port_min)
            start_port = port_min;
    }

    /* Linear scan from hint (cache-friendly) */
    uint32_t range = port_max - port_min + 1;
    for (uint32_t i = 0; i < range; i++) {
        uint16_t port = port_min + ((start_port - port_min + i) % range);
        uint32_t word = port / 32;
        uint32_t bit = port % 32;
        uint32_t mask = 1U << bit;

        /* FIXED: Use atomic CAS to prevent race conditions */
        uint64_t old_val = worker->port_pool.port_bitmap[word];
        uint64_t new_val = old_val | mask;

        if (!(old_val & mask)) {
            /* Try to atomically set the bit */
            if (__atomic_compare_exchange_n(&worker->port_pool.port_bitmap[word], &old_val, new_val,
                                            true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                /* Success! */
                uint16_t next_hint = port + 1;
                if (next_hint > port_max) {
                    next_hint = port_min;
                }
                __atomic_store_n(&worker->port_pool.next_hint, next_hint, __ATOMIC_RELAXED);
                __atomic_fetch_add(&worker->port_pool.ports_allocated, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&worker->port_pool.alloc_success, 1, __ATOMIC_RELAXED);
                return port;
            }
        }
    }

    /* Exhausted */
    __atomic_fetch_add(&worker->port_pool.alloc_fail, 1, __ATOMIC_RELAXED);
    return 0;
}

/**
 * Free port back to worker's bitmap - LOCKLESS!
 * Uses atomic operations to prevent race conditions
 */
void nat_worker_free_port_lockless(uint32_t worker_id, uint16_t port)
{
    if (worker_id >= NAT_MAX_WORKERS || port < 1024) {
        return;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    uint32_t word = port / 32;
    uint32_t bit = port % 32;
    uint32_t mask = 1U << bit;

    /* FIXED: Use atomic CAS to prevent race conditions */
    uint64_t old_val = worker->port_pool.port_bitmap[word];
    uint64_t new_val = old_val & ~mask;

    if (old_val & mask) {
        /* Try to atomically clear the bit */
        __atomic_compare_exchange_n(&worker->port_pool.port_bitmap[word], &old_val, new_val, true,
                                    __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
        /* Decrement counter (safe to use fetch_add as it's just a statistic) */
        __atomic_fetch_sub(&worker->port_pool.ports_allocated, 1, __ATOMIC_RELAXED);
    }
}

/**
 * Initialize per-worker session pool for LOCKLESS allocation
 * Assigns a range of session indices from the global slab to this worker
 */
void nat_worker_session_pool_init(uint32_t worker_id, uint32_t start_index, uint32_t count)
{
    if (worker_id >= NAT_MAX_WORKERS || count == 0) {
        return;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* Allocate free stack */
    worker->session_pool.free_stack = calloc(count, sizeof(uint32_t));
    if (!worker->session_pool.free_stack) {
        return;
    }

    /* Initialize free stack with session indices (push all as free) */
    for (uint32_t i = 0; i < count; i++) {
        worker->session_pool.free_stack[i] = start_index + i;
    }

    worker->session_pool.free_top = count; /* All sessions are free */
    worker->session_pool.capacity = count;
    worker->session_pool.alloc_success = 0;
    worker->session_pool.alloc_fail = 0;
}

/**
 * Allocate session from worker's pool - LOCKLESS!
 * Uses stack-based allocation for O(1) performance
 */
struct nat_session *nat_worker_alloc_session_lockless(uint32_t worker_id)
{
    extern struct nat_session *g_session_slab;

    if (worker_id >= NAT_MAX_WORKERS) {
        return NULL;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* Check if pool is empty */
    if (worker->session_pool.free_top == 0) {
        worker->session_pool.alloc_fail++;
        return NULL;
    }

    /* Pop from stack (no locks!) */
    uint32_t session_idx = worker->session_pool.free_stack[--worker->session_pool.free_top];

    /* Get session from global slab */
    struct nat_session *session = &g_session_slab[session_idx];

    /* Clear session */
    memset(session, 0, sizeof(*session));
    session->session_index = session_idx;

    worker->session_pool.alloc_success++;
    return session;
}

/**
 * Free session back to worker's pool - LOCKLESS!
 */
void nat_worker_free_session_lockless(uint32_t worker_id, struct nat_session *session)
{
    if (worker_id >= NAT_MAX_WORKERS || !session) {
        return;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];

    /* Check if pool is full (shouldn't happen) */
    if (worker->session_pool.free_top >= worker->session_pool.capacity) {
        return;
    }

    /* Push to stack (no locks!) */
    worker->session_pool.free_stack[worker->session_pool.free_top++] = session->session_index;
}

#ifdef HAVE_DPDK
/**
 * VPP-STYLE: Initialize worker handoff rings
 * Each worker gets a ring for receiving packets from other workers
 * Ring is SP/SC (single producer from each sender, single consumer = this worker)
 */
int nat_worker_handoff_init(uint32_t num_workers)
{
    if (num_workers == 0 || num_workers > NAT_MAX_WORKERS) {
        return -1;
    }

    for (uint32_t i = 0; i < num_workers; i++) {
        char ring_name[32];
        snprintf(ring_name, sizeof(ring_name), "nat_handoff_%u", i);

        /* Create ring: 4096 entries, MP/SC (multiple producers, single consumer) */
        struct rte_ring *ring = rte_ring_create(ring_name, 4096, rte_socket_id(), RING_F_SC_DEQ);
        if (!ring) {
            /* Ring might already exist from previous run */
            ring = rte_ring_lookup(ring_name);
            if (!ring) {
                return -1;
            }
        }

        g_nat_workers[i].handoff_ring = ring;
        g_nat_workers[i].handoff_enqueue = 0;
        g_nat_workers[i].handoff_dequeue = 0;
    }

    return 0;
}

/**
 * VPP-STYLE: Map flow to worker ID using INSIDE TUPLE ONLY
 *
 * CRITICAL: This hash must be:
 * 1. Deterministic - same input always yields same worker
 * 2. Stable - never changes after NAT translation
 * 3. Based ONLY on inside (subscriber) tuple: (inside_ip, inside_port, proto)
 *
 * This ensures:
 * - Forward packet creates session on Worker X
 * - Reverse packet (via session->owner_worker) goes to Worker X
 * - Session owned by exactly ONE worker for lifetime
 *
 * DO NOT hash on outside (NAT) tuple - it changes after translation!
 */
uint32_t nat_flow_to_worker(uint32_t inside_ip, uint16_t inside_port, uint8_t proto)
{
    if (g_num_workers <= 1) {
        return 0;
    }

    /* VPP-STYLE: Hash ONLY the inside (subscriber) tuple
     * This is deterministic and never changes after NAT translation
     * Using same hash algorithm as nat_hash_5tuple for consistency
     */
    uint32_t hash = inside_ip ^ ((uint32_t)inside_port << 16) ^ proto;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash % g_num_workers;
}

/**
 * VPP-STYLE: Determine session owner from NAT outside port
 * Each worker has a non-overlapping port range:
 *   Worker 0: 1024 to 1024 + ports_per_worker - 1
 *   Worker 1: 1024 + ports_per_worker to 1024 + 2*ports_per_worker - 1
 *   ...
 * This allows DNAT to find the owner WITHOUT searching session tables
 */
uint32_t nat_port_to_worker(uint16_t outside_port)
{
    if (g_num_workers <= 1 || outside_port < 1024) {
        return 0;
    }

    uint16_t total_ports = 65535 - 1024;
    uint16_t ports_per_worker = total_ports / g_num_workers;

    if (ports_per_worker == 0) {
        return 0;
    }

    uint32_t worker = (outside_port - 1024) / ports_per_worker;

    /* Clamp to valid worker range */
    if (worker >= g_num_workers) {
        worker = g_num_workers - 1;
    }

    return worker;
}

/**
 * VPP-STYLE: Enqueue packet to target worker's handoff ring
 * Returns 0 on success, -1 if ring is full
 */
int nat_worker_handoff_enqueue(uint32_t target_worker, struct rte_mbuf *pkt)
{
    if (target_worker >= g_num_workers) {
        return -1;
    }

    struct nat_worker_data *target = &g_nat_workers[target_worker];
    if (!target->handoff_ring) {
        return -1;
    }

    int ret = rte_ring_enqueue(target->handoff_ring, pkt);
    if (ret == 0) {
        target->handoff_enqueue++;
    }
    return ret;
}

/**
 * VPP-STYLE: Dequeue packets from this worker's handoff ring
 * Returns number of packets dequeued
 */
uint16_t nat_worker_handoff_dequeue(uint32_t worker_id, struct rte_mbuf **pkts, uint16_t max_pkts)
{
    if (worker_id >= g_num_workers) {
        return 0;
    }

    struct nat_worker_data *worker = &g_nat_workers[worker_id];
    if (!worker->handoff_ring) {
        return 0;
    }

    uint16_t nb_rx = rte_ring_dequeue_burst(worker->handoff_ring, (void **)pkts, max_pkts, NULL);
    if (nb_rx > 0) {
        worker->handoff_dequeue += nb_rx;
    }
    return nb_rx;
}

/**
 * Print worker load balance statistics
 * Shows how sessions are distributed across workers
 */
void nat_worker_print_load_balance(void)
{
    printf("\n=== NAT Worker Load Balance (10M Sessions Target) ===\n");
    printf("%-8s %-15s %-15s %-15s %-15s %-15s\n", "Worker", "Sessions", "Sessions %", "Hash Size", "Load Factor", "Packets");
    printf("%-8s %-15s %-15s %-15s %-15s %-15s\n", "------", "---------", "----------", "---------", "----------", "--------");

    uint64_t total_sessions = 0;
    uint64_t total_packets = 0;

    for (uint32_t i = 0; i < g_num_workers && i < NAT_MAX_WORKERS; i++) {
        struct nat_worker_data *worker = &g_nat_workers[i];

        /* Estimate current sessions from allocations */
        uint64_t sessions = worker->session_pool.capacity - worker->session_pool.free_top;
        total_sessions += sessions;
        total_packets += worker->packets_translated;

        /* Calculate load factor */
        uint64_t hash_size = (uint64_t)NAT_WORKER_TABLE_SIZE * 4;
        double load_factor = (double)sessions / (double)hash_size;

        double percent = (double)sessions / 10000000.0 * 100.0;

        printf("Worker %-2u   %-15lu %-14.2f%% %-15lu %-14.4f %-15lu\n", i, sessions, percent,
               hash_size, load_factor, worker->packets_translated);
    }

    printf("%-8s %-15s %-15s %-15s %-15s %-15s\n", "------", "---------", "----------", "---------", "----------", "--------");
    printf("Total    %-15lu %-14.2f%%\n\n", total_sessions,
           (double)total_sessions / 10000000.0 * 100.0);

    /* Print handoff statistics */
    printf("=== Worker Handoff Statistics ===\n");
    printf("%-8s %-15s %-15s %-15s\n", "Worker", "Enqueued", "Dequeued", "Net");
    printf("%-8s %-15s %-15s %-15s\n", "------", "--------", "--------", "---");

    for (uint32_t i = 0; i < g_num_workers && i < NAT_MAX_WORKERS; i++) {
        struct nat_worker_data *worker = &g_nat_workers[i];
        int64_t net = (int64_t)worker->handoff_enqueue - (int64_t)worker->handoff_dequeue;
        printf("Worker %-2u   %-15lu %-15lu %-15ld\n", i, worker->handoff_enqueue,
               worker->handoff_dequeue, net);
    }
    printf("\n");
}
#endif /* HAVE_DPDK */
