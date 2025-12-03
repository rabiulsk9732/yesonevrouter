/**
 * @file cpu_scheduler.h
 * @brief CPU Core Scheduling and Affinity Management
 */

#ifndef CPU_SCHEDULER_H
#define CPU_SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_LCORES 128

/* CPU core information */
struct cpu_core_info {
    uint32_t core_id;
    uint32_t socket_id;
    bool available;
    bool in_use;
};

/* CPU scheduler configuration */
struct cpu_scheduler_config {
    uint32_t num_cores;
    struct cpu_core_info cores[MAX_LCORES];
};

/**
 * Initialize CPU scheduler
 * @return 0 on success, -1 on failure
 */
int cpu_scheduler_init(void);

/**
 * Allocate a CPU core for a worker thread
 * @param socket_id Preferred NUMA socket (-1 for any)
 * @return Core ID or -1 on failure
 */
int cpu_scheduler_allocate_core(int socket_id);

/**
 * Release a CPU core
 * @param core_id Core ID to release
 * @return 0 on success, -1 on failure
 */
int cpu_scheduler_release_core(uint32_t core_id);

/**
 * Set CPU affinity for current thread
 * @param core_id CPU core ID
 * @return 0 on success, -1 on failure
 */
int cpu_scheduler_set_affinity(uint32_t core_id);

/**
 * Get number of available CPU cores
 * @return Number of cores
 */
uint32_t cpu_scheduler_get_core_count(void);

/**
 * Print CPU topology information
 */
void cpu_scheduler_print_topology(void);

/**
 * Cleanup CPU scheduler
 */
void cpu_scheduler_cleanup(void);

#endif /* CPU_SCHEDULER_H */
