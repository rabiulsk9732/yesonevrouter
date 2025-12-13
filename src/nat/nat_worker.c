/**
 * @file nat_worker.c
 * @brief NAT Per-Worker Table Management
 */

#include "nat.h"
#include "cpu_scheduler.h"
#include <string.h>
#include <stdlib.h>

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
void nat_worker_port_pool_init(uint32_t worker_id, uint32_t nat_ip,
                               uint16_t port_min, uint16_t port_max)
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
        worker->port_pool.port_bitmap[i] = 0xFFFFFFFF;  /* Mark first 1024 ports as used */
    }
}

/**
 * Allocate port from worker's bitmap - LOCKLESS!
 * Uses bitmap scanning for O(1) amortized allocation
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

        if (!(worker->port_pool.port_bitmap[word] & mask)) {
            /* Preferred port available! */
            worker->port_pool.port_bitmap[word] |= mask;
            worker->port_pool.ports_allocated++;
            worker->port_pool.alloc_success++;
            return preferred_port;
        }
        /* Preferred not available, try same parity */
        start_port = (preferred_port & 1) ? (port_min | 1) : (port_min & ~1);
    } else {
        start_port = worker->port_pool.next_hint;
        if (start_port < port_min) start_port = port_min;
    }

    /* Linear scan from hint (cache-friendly) */
    uint32_t range = port_max - port_min + 1;
    for (uint32_t i = 0; i < range; i++) {
        uint16_t port = port_min + ((start_port - port_min + i) % range);
        uint32_t word = port / 32;
        uint32_t bit = port % 32;
        uint32_t mask = 1U << bit;

        if (!(worker->port_pool.port_bitmap[word] & mask)) {
            /* Found free port! */
            worker->port_pool.port_bitmap[word] |= mask;
            worker->port_pool.next_hint = port + 1;
            if (worker->port_pool.next_hint > port_max) {
                worker->port_pool.next_hint = port_min;
            }
            worker->port_pool.ports_allocated++;
            worker->port_pool.alloc_success++;
            return port;
        }
    }

    /* Exhausted */
    worker->port_pool.alloc_fail++;
    return 0;
}

/**
 * Free port back to worker's bitmap - LOCKLESS!
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

    /* Clear bit (mark as free) */
    if (worker->port_pool.port_bitmap[word] & mask) {
        worker->port_pool.port_bitmap[word] &= ~mask;
        if (worker->port_pool.ports_allocated > 0) {
            worker->port_pool.ports_allocated--;
        }
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

    worker->session_pool.free_top = count;  /* All sessions are free */
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
