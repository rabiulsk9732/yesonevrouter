/**
 * @file ipoe_pool_allocator.c
 * @brief IP Pool Allocator - Bitmap-based thread-safe allocation
 *
 * Production-grade IP address allocator for DHCP pools
 */

#include <ipoe_profile.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_DPDK
#include <rte_spinlock.h>
#endif

/*============================================================================
 * Pool Allocator State
 *============================================================================*/

#define IPOE_MAX_POOLS          64
#define IPOE_POOL_BITMAP_WORDS  8192    /* 8192 * 64 = 524288 IPs per pool */

struct ipoe_pool_state {
    char     name[32];
    uint32_t base_ip;           /* First IP in range */
    uint32_t size;              /* Number of IPs */
    uint64_t bitmap[IPOE_POOL_BITMAP_WORDS];  /* 1 = allocated */
    uint32_t next_hint;         /* Hint for next allocation */
    uint32_t allocated;         /* Count of allocated IPs */

#ifdef HAVE_DPDK
    rte_spinlock_t lock;
#else
    pthread_spinlock_t lock;
#endif
};

static struct {
    struct ipoe_pool_state pools[IPOE_MAX_POOLS];
    uint32_t num_pools;
} g_pool_alloc = {0};

/*============================================================================
 * Helper Functions
 *============================================================================*/

static int find_pool_state(const char *name)
{
    for (uint32_t i = 0; i < g_pool_alloc.num_pools; i++) {
        if (strcmp(g_pool_alloc.pools[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static inline int bit_get(uint64_t *bitmap, uint32_t idx)
{
    return (bitmap[idx / 64] >> (idx % 64)) & 1;
}

static inline void bit_set(uint64_t *bitmap, uint32_t idx)
{
    bitmap[idx / 64] |= (1ULL << (idx % 64));
}

static inline void bit_clear(uint64_t *bitmap, uint32_t idx)
{
    bitmap[idx / 64] &= ~(1ULL << (idx % 64));
}

/*============================================================================
 * Pool Allocator API
 *============================================================================*/

int ipoe_pool_alloc_init(const char *name, uint32_t start_ip, uint32_t end_ip)
{
    if (!name || g_pool_alloc.num_pools >= IPOE_MAX_POOLS) {
        return -1;
    }

    if (find_pool_state(name) >= 0) {
        return -1;  /* Already exists */
    }

    uint32_t size = end_ip - start_ip + 1;
    if (size > IPOE_POOL_BITMAP_WORDS * 64) {
        fprintf(stderr, "ipoe_pool: pool too large (%u IPs)\n", size);
        return -1;
    }

    struct ipoe_pool_state *pool = &g_pool_alloc.pools[g_pool_alloc.num_pools];
    memset(pool, 0, sizeof(*pool));
    strncpy(pool->name, name, sizeof(pool->name) - 1);
    pool->base_ip = start_ip;
    pool->size = size;
    pool->next_hint = 0;

#ifdef HAVE_DPDK
    rte_spinlock_init(&pool->lock);
#else
    pthread_spin_init(&pool->lock, PTHREAD_PROCESS_PRIVATE);
#endif

    g_pool_alloc.num_pools++;
    printf("ipoe_pool_alloc: initialized '%s' with %u IPs\n", name, size);

    return 0;
}

/**
 * Allocate IP from pool (thread-safe)
 * Returns: IP in host byte order, or 0 on failure
 */
uint32_t ipoe_pool_allocate_ip(const char *pool_name)
{
    int idx = find_pool_state(pool_name);
    if (idx < 0) return 0;

    struct ipoe_pool_state *pool = &g_pool_alloc.pools[idx];
    uint32_t result = 0;

#ifdef HAVE_DPDK
    rte_spinlock_lock(&pool->lock);
#else
    pthread_spin_lock(&pool->lock);
#endif

    /* Search from hint */
    uint32_t start = pool->next_hint;
    for (uint32_t i = 0; i < pool->size; i++) {
        uint32_t pos = (start + i) % pool->size;

        if (!bit_get(pool->bitmap, pos)) {
            /* Found free IP */
            bit_set(pool->bitmap, pos);
            pool->allocated++;
            pool->next_hint = (pos + 1) % pool->size;
            result = pool->base_ip + pos;
            break;
        }
    }

#ifdef HAVE_DPDK
    rte_spinlock_unlock(&pool->lock);
#else
    pthread_spin_unlock(&pool->lock);
#endif

    return result;
}

/**
 * Release IP back to pool (thread-safe)
 */
int ipoe_pool_release_ip(const char *pool_name, uint32_t ip)
{
    int idx = find_pool_state(pool_name);
    if (idx < 0) return -1;

    struct ipoe_pool_state *pool = &g_pool_alloc.pools[idx];

    /* Check if IP is in range */
    if (ip < pool->base_ip || ip >= pool->base_ip + pool->size) {
        return -1;
    }

    uint32_t pos = ip - pool->base_ip;

#ifdef HAVE_DPDK
    rte_spinlock_lock(&pool->lock);
#else
    pthread_spin_lock(&pool->lock);
#endif

    if (bit_get(pool->bitmap, pos)) {
        bit_clear(pool->bitmap, pos);
        pool->allocated--;
    }

#ifdef HAVE_DPDK
    rte_spinlock_unlock(&pool->lock);
#else
    pthread_spin_unlock(&pool->lock);
#endif

    return 0;
}

/**
 * Allocate specific IP if available
 */
int ipoe_pool_allocate_specific(const char *pool_name, uint32_t ip)
{
    int idx = find_pool_state(pool_name);
    if (idx < 0) return -1;

    struct ipoe_pool_state *pool = &g_pool_alloc.pools[idx];

    if (ip < pool->base_ip || ip >= pool->base_ip + pool->size) {
        return -1;
    }

    uint32_t pos = ip - pool->base_ip;
    int result = -1;

#ifdef HAVE_DPDK
    rte_spinlock_lock(&pool->lock);
#else
    pthread_spin_lock(&pool->lock);
#endif

    if (!bit_get(pool->bitmap, pos)) {
        bit_set(pool->bitmap, pos);
        pool->allocated++;
        result = 0;
    }

#ifdef HAVE_DPDK
    rte_spinlock_unlock(&pool->lock);
#else
    pthread_spin_unlock(&pool->lock);
#endif

    return result;
}

/**
 * Get pool statistics
 */
void ipoe_pool_get_stats(const char *pool_name, uint32_t *total,
                          uint32_t *used, uint32_t *free)
{
    int idx = find_pool_state(pool_name);
    if (idx < 0) {
        if (total) *total = 0;
        if (used) *used = 0;
        if (free) *free = 0;
        return;
    }

    struct ipoe_pool_state *pool = &g_pool_alloc.pools[idx];

    if (total) *total = pool->size;
    if (used) *used = pool->allocated;
    if (free) *free = pool->size - pool->allocated;
}

/**
 * Print all pool statistics
 */
void ipoe_pool_alloc_print_stats(void)
{
    printf("\nIP Pool Allocator Statistics:\n");
    printf("%-20s %10s %10s %10s %10s\n", "Pool", "Total", "Used", "Free", "Usage%");
    printf("----------------------------------------------------------\n");

    for (uint32_t i = 0; i < g_pool_alloc.num_pools; i++) {
        struct ipoe_pool_state *pool = &g_pool_alloc.pools[i];
        uint32_t free_ips = pool->size - pool->allocated;
        uint32_t usage = (pool->size > 0) ? (pool->allocated * 100 / pool->size) : 0;

        printf("%-20s %10u %10u %10u %9u%%\n",
               pool->name, pool->size, pool->allocated, free_ips, usage);
    }
    printf("\n");
}
