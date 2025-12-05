/**
 * @file simulate_nat.c
 * @brief NAT Capacity and Performance Simulator
 *
 * Simulates NAT session table operations with 16 threads to estimate
 * throughput and memory capacity on the target hardware.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sched.h>

/* Mocking necessary parts from nat.h if we don't link full lib */
#define NAT_SESSION_TABLE_SIZE  (64 * 1024 * 1024) /* 64M Buckets */
#define NAT_SESSION_HASH_MASK   (NAT_SESSION_TABLE_SIZE - 1)

struct nat_session {
    uint32_t inside_ip;
    uint32_t outside_ip;
    uint16_t inside_port;
    uint16_t outside_port;
    uint8_t  protocol;
    uint8_t  pad1;
    uint64_t session_id;
    uint32_t subscriber_id;
    uint16_t port_block_id;
    uint16_t pad2;
    uint64_t created_ts;
    uint64_t last_used_ts;
    uint32_t timeout;
    uint32_t pad3;
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint8_t  flags;
    uint8_t  pad4[7];
    struct nat_session *next;
} __attribute__((aligned(64)));

static struct nat_session *session_table[NAT_SESSION_TABLE_SIZE];

/* Sharded Locks for Simulation */
#define NAT_NUM_PARTITIONS 1024
#define NAT_PARTITION_MASK (NAT_NUM_PARTITIONS - 1)
static pthread_rwlock_t session_table_locks[NAT_NUM_PARTITIONS];

static inline uint32_t get_partition_id(uint32_t hash) {
    return hash & NAT_PARTITION_MASK;
}

/* Simulation Parameters */
#define NUM_THREADS 16
#define DURATION_SEC 30
#define SESSIONS_TO_PREFILL 50000000 /* 50 Million Sessions (~7GB) */

static volatile bool running = true;
static uint64_t total_lookups = 0;
static uint64_t total_creations = 0;
static uint64_t total_deletions = 0;

/* Resource Usage Helpers */
long get_rss_kb() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    long rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

/* FNV-1a Hash */
static inline uint32_t nat_hash(uint32_t ip, uint16_t port, uint8_t proto)
{
    uint32_t hash = 2166136261u;
    hash ^= (ip >> 24) & 0xFF; hash *= 16777619;
    hash ^= (ip >> 16) & 0xFF; hash *= 16777619;
    hash ^= (ip >> 8) & 0xFF;  hash *= 16777619;
    hash ^= ip & 0xFF;         hash *= 16777619;
    hash ^= (port >> 8) & 0xFF; hash *= 16777619;
    hash ^= port & 0xFF;        hash *= 16777619;
    hash ^= proto;              hash *= 16777619;
    return hash & NAT_SESSION_HASH_MASK;
}

void *worker_thread(void *arg)
{
    int thread_id = *(int *)arg;
    uint64_t lookups = 0;
    uint64_t creations = 0;
    uint64_t deletions = 0;
    unsigned int seed = time(NULL) + thread_id;

    /* Bind to core */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(thread_id % 16, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    while (running) {
        /* Traffic Mix:
         * 80% Lookup (Existing flows)
         * 10% Create (New flows)
         * 10% Delete (Finished flows)
         * This stresses the RW lock significantly.
         */
        int op = rand_r(&seed) % 100;

        uint32_t ip = rand_r(&seed);
        uint16_t port = rand_r(&seed) & 0xFFFF;
        uint8_t proto = 6;
        uint32_t hash = nat_hash(ip, port, proto);
        uint32_t partition = get_partition_id(hash);

        if (op < 80) {
            /* Lookup */
            pthread_rwlock_rdlock(&session_table_locks[partition]);
            struct nat_session *s = session_table[hash];

            /* Prefetch */
            if (s) __builtin_prefetch(s->next, 0, 1);

            while (s) {
                if (s->inside_ip == ip && s->inside_port == port) {
                    break;
                }
                s = s->next;
                if (s) __builtin_prefetch(s->next, 0, 1);
            }
            pthread_rwlock_unlock(&session_table_locks[partition]);
            lookups++;
        } else if (op < 90) {
            /* Create */
            struct nat_session *s = malloc(sizeof(struct nat_session));
            if (s) {
                s->inside_ip = ip;
                s->inside_port = port;
                s->protocol = proto;

                pthread_rwlock_wrlock(&session_table_locks[partition]);
                s->next = session_table[hash];
                session_table[hash] = s;
                pthread_rwlock_unlock(&session_table_locks[partition]);
                creations++;
            }
        } else {
            /* Delete */
            pthread_rwlock_wrlock(&session_table_locks[partition]);
            struct nat_session *s = session_table[hash];
            if (s) {
                session_table[hash] = s->next;
                free(s);
                deletions++;
            }
            pthread_rwlock_unlock(&session_table_locks[partition]);
        }
    }

    __atomic_add_fetch(&total_lookups, lookups, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_creations, creations, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_deletions, deletions, __ATOMIC_RELAXED);
    return NULL;
}

int main()
{
    printf("EXTREME NAT Stress Test\n");
    printf("=======================\n");
    printf("Configuration:\n");
    printf("  Threads: %d\n", NUM_THREADS);
    printf("  Prefill Sessions: %d\n", SESSIONS_TO_PREFILL);
    printf("  Duration: %d seconds\n", DURATION_SEC);
    printf("  Traffic Mix: 80%% Lookup, 10%% Create, 10%% Delete\n");

    /* Prefill table */
    printf("\n[Phase 1] Initializing locks and prefilling memory...\n");
    for (int i = 0; i < NAT_NUM_PARTITIONS; i++) {
        pthread_rwlock_init(&session_table_locks[i], NULL);
    }
    long start_rss = get_rss_kb();

    for (int i = 0; i < SESSIONS_TO_PREFILL; i++) {
        struct nat_session *s = calloc(1, sizeof(struct nat_session));
        s->inside_ip = i;
        s->inside_port = i & 0xFFFF;
        uint32_t hash = nat_hash(s->inside_ip, s->inside_port, 6);
        s->next = session_table[hash];
        session_table[hash] = s;

        if (i % 1000000 == 0 && i > 0) {
            printf("  Filled %dM sessions...\r", i / 1000000);
            fflush(stdout);
        }
    }
    printf("  Filled %dM sessions. Done.\n", SESSIONS_TO_PREFILL / 1000000);

    long prefill_rss = get_rss_kb();
    printf("  Memory Used: %.2f GB\n", (prefill_rss - start_rss) / 1024.0 / 1024.0);

    /* Start Threads */
    printf("\n[Phase 2] Starting Stress Test...\n");
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]);
    }

    /* Monitor loop */
    for (int i = 0; i < DURATION_SEC; i++) {
        sleep(1);
        long current_rss = get_rss_kb();
        printf("  [%2d/%ds] RAM: %.2f GB | Lookups: %lu | Creates: %lu | Deletes: %lu\r",
               i+1, DURATION_SEC, current_rss / 1024.0 / 1024.0,
               total_lookups, total_creations, total_deletions);
        fflush(stdout);
    }
    running = false;

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    gettimeofday(&end, NULL);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    printf("\n\nResults:\n");
    printf("=======================\n");
    printf("Total Operations: %lu\n", total_lookups + total_creations + total_deletions);
    printf("  - Lookups: %lu\n", total_lookups);
    printf("  - Creates: %lu\n", total_creations);
    printf("  - Deletes: %lu\n", total_deletions);
    printf("Time Elapsed: %.2f s\n", elapsed);
    printf("Throughput: %.2f Mpps\n", (total_lookups + total_creations + total_deletions) / elapsed / 1000000.0);
    printf("Final RAM Usage: %.2f GB\n", get_rss_kb() / 1024.0 / 1024.0);

    return 0;
}
