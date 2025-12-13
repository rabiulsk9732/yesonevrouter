#ifndef CPU_SCHEDULER_H
#define CPU_SCHEDULER_H

#include <pthread.h>

/**
 * Set CPU affinity for the current thread
 * @param core_id CPU core ID to pin to
 * @return 0 on success, -1 on failure
 */
int cpu_scheduler_set_affinity(int core_id);

int cpu_scheduler_init(void);
void cpu_scheduler_cleanup(void);

/**
 * Thread-local queue ID assigned to the current worker thread.
 * This determines which RX/TX queue the thread should use.
 */
extern __thread int g_thread_queue_id;

/**
 * Thread-local worker ID assigned to the current worker thread.
 * This determines which per-worker NAT session table to use.
 */
extern __thread int g_thread_worker_id;

#endif /* CPU_SCHEDULER_H */
