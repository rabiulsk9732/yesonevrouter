/**
 * @file worker_manager.h
 * @brief Worker Process Management API
 */

#ifndef WORKER_MANAGER_H
#define WORKER_MANAGER_H

#include <stdint.h>

/* Worker function signature */
typedef void (*worker_func_t)(int worker_id, void *arg);

/**
 * Initialize worker manager
 */
int worker_manager_init(void);

/**
 * Cleanup worker manager
 */
void worker_manager_cleanup(void);

/**
 * Create a new worker
 * @param name Worker name for logging
 * @param func Worker function
 * @param arg Argument passed to worker function
 * @return Worker ID or -1 on failure
 */
int worker_create(const char *name, worker_func_t func, void *arg);

/**
 * Start a worker
 */
int worker_start(int worker_id);

/**
 * Stop a worker
 */
int worker_stop(int worker_id);

/**
 * Restart a worker
 */
void worker_restart(int worker_id);

/**
 * Reset respawn count (re-enable disabled worker)
 */
void worker_reset_respawn_count(int worker_id);

/**
 * Show worker status
 */
void worker_show_status(void);

#endif /* WORKER_MANAGER_H */
