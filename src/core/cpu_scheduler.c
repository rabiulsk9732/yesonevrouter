#define _GNU_SOURCE
#include "cpu_scheduler.h"
#include "log.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

/* Thread-local queue ID definition */
__thread int g_thread_queue_id = 0;

/* Thread-local worker ID definition */
__thread int g_thread_worker_id = 0;

int cpu_scheduler_set_affinity(int core_id)
{
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        YLOG_ERROR("pthread_setaffinity_np failed for core %d", core_id);
        return -1;
    }

    return 0;
}

int cpu_scheduler_init(void)
{
    return 0;
}

void cpu_scheduler_cleanup(void) {}
