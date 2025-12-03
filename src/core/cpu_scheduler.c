/**
 * @file cpu_scheduler.c
 * @brief CPU Core Scheduling Implementation
 */

#define _GNU_SOURCE
#include "cpu_scheduler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

static struct cpu_scheduler_config g_cpu_config;

int cpu_scheduler_init(void)
{
    long num_cpus;

    memset(&g_cpu_config, 0, sizeof(g_cpu_config));

    /* Get number of available CPUs */
    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) {
        fprintf(stderr, "Failed to get number of CPUs\n");
        return -1;
    }

    g_cpu_config.num_cores = (uint32_t)num_cpus;
    if (g_cpu_config.num_cores > MAX_LCORES) {
        g_cpu_config.num_cores = MAX_LCORES;
    }

    /* Initialize core information */
    for (uint32_t i = 0; i < g_cpu_config.num_cores; i++) {
        g_cpu_config.cores[i].core_id = i;
        g_cpu_config.cores[i].socket_id = 0;  /* Simplified: all cores on socket 0 */
        g_cpu_config.cores[i].available = true;
        g_cpu_config.cores[i].in_use = false;
    }

    printf("CPU Scheduler initialized: %u cores available\n", 
           g_cpu_config.num_cores);

    return 0;
}

int cpu_scheduler_allocate_core(int socket_id)
{
    (void)socket_id; /* Simplified: ignore socket preference for now */

    for (uint32_t i = 0; i < g_cpu_config.num_cores; i++) {
        if (g_cpu_config.cores[i].available && 
            !g_cpu_config.cores[i].in_use) {
            g_cpu_config.cores[i].in_use = true;
            return (int)i;
        }
    }

    fprintf(stderr, "No available CPU cores\n");
    return -1;
}

int cpu_scheduler_release_core(uint32_t core_id)
{
    if (core_id >= g_cpu_config.num_cores) {
        fprintf(stderr, "Invalid core ID: %u\n", core_id);
        return -1;
    }

    g_cpu_config.cores[core_id].in_use = false;
    return 0;
}

int cpu_scheduler_set_affinity(uint32_t core_id)
{
    cpu_set_t cpuset;
    pthread_t thread;

    if (core_id >= g_cpu_config.num_cores) {
        fprintf(stderr, "Invalid core ID: %u\n", core_id);
        return -1;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    thread = pthread_self();
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("pthread_setaffinity_np");
        return -1;
    }

    printf("Thread pinned to CPU core %u\n", core_id);
    return 0;
}

uint32_t cpu_scheduler_get_core_count(void)
{
    return g_cpu_config.num_cores;
}

void cpu_scheduler_print_topology(void)
{
    printf("\nCPU Topology:\n");
    printf("  Total cores: %u\n", g_cpu_config.num_cores);
    printf("  Core  Socket  Available  In-Use\n");
    printf("  ----  ------  ---------  ------\n");

    for (uint32_t i = 0; i < g_cpu_config.num_cores; i++) {
        printf("  %4u  %6u  %9s  %6s\n",
               g_cpu_config.cores[i].core_id,
               g_cpu_config.cores[i].socket_id,
               g_cpu_config.cores[i].available ? "yes" : "no",
               g_cpu_config.cores[i].in_use ? "yes" : "no");
    }
    printf("\n");
}

void cpu_scheduler_cleanup(void)
{
    printf("CPU Scheduler cleanup\n");
    memset(&g_cpu_config, 0, sizeof(g_cpu_config));
}
