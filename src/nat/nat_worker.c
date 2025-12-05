/**
 * @file nat_worker.c
 * @brief NAT Per-Worker Table Management
 */

#include "nat.h"
#include "cpu_scheduler.h"
#include <string.h>

/* Access to internal worker data - defined in nat_session.c */
extern struct nat_worker_data g_nat_workers[];
extern uint32_t g_num_workers;

/**
 * Set number of NAT workers (called from RX thread initialization)
 */
void nat_set_num_workers(uint32_t num_workers)
{
    if (num_workers > 0 && num_workers <= 16) {
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
