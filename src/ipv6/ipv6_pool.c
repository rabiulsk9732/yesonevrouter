/**
 * @file ipv6_pool.c
 * @brief IPv6 Pool Management Implementation
 */

#include "ipv6/ipv6.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

/* Global Pool List */
static struct ipv6_pool *g_pool_list = NULL;
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper: Address manipulation */
/* static functions removed to avoid -Werror=unused-function */

int ipv6_pool_init(void)
{
    g_pool_list = NULL;
    /* Mutex is statically initialized */
    YLOG_INFO("IPv6 Pool Manager initialized");
    return 0;
}

int ipv6_pool_create(const char *name, struct ipv6_addr *prefix, uint8_t len, uint8_t alloc_len)
{
    struct ipv6_pool *pool;
    struct ipv6_pool *curr;

    if (!name || !prefix || len > 128 || alloc_len > 128 || alloc_len < len) {
        return -1;
    }

    pthread_mutex_lock(&g_pool_mutex);

    /* Check duplicate name */
    curr = g_pool_list;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            pthread_mutex_unlock(&g_pool_mutex);
            YLOG_ERROR("IPv6 pool '%s' already exists", name);
            return -1;
        }
        curr = curr->next;
    }

    pool = calloc(1, sizeof(struct ipv6_pool));
    if (!pool) {
        pthread_mutex_unlock(&g_pool_mutex);
        return -1;
    }

    strncpy(pool->name, name, IPV6_POOL_NAME_LEN - 1);
    pool->base_prefix = *prefix;
    pool->prefix_len = len;
    pool->alloc_len = alloc_len;

    /* Calculate capacity: 2^(alloc_len - prefix_len) */
    /* Be careful with overflow */
    if (alloc_len - len >= 32) {
        pool->total_prefixes = 0xFFFFFFFF; /* Cap at UINT32_MAX */
    } else {
        pool->total_prefixes = 1U << (alloc_len - len);
    }
    pool->used_prefixes = 0;

    /* Insert at head */
    pool->next = g_pool_list;
    g_pool_list = pool;

    char pstr[64];
    inet_ntop(AF_INET6, prefix->addr, pstr, sizeof(pstr));
    YLOG_INFO("Created IPv6 Pool '%s': %s/%u (allocating /%u)",
              name, pstr, len, alloc_len);

    pthread_mutex_unlock(&g_pool_mutex);
    return 0;
}

struct ipv6_pool *ipv6_pool_get(const char *name)
{
    struct ipv6_pool *curr;

    /* Note: Unsafe if list changes, should be used with lock or RCU */
    /* This is just a lookup */
    pthread_mutex_lock(&g_pool_mutex);
    curr = g_pool_list;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            pthread_mutex_unlock(&g_pool_mutex);
            return curr;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_pool_mutex);
    return NULL;
}

int ipv6_pool_alloc(const char *pool_name, struct ipv6_addr *allocated_prefix)
{
    struct ipv6_pool *pool;

    if (!pool_name || !allocated_prefix) return -1;

    pthread_mutex_lock(&g_pool_mutex);

    /* Find pool */
    pool = g_pool_list;
    while (pool) {
        if (strcmp(pool->name, pool_name) == 0) break;
        pool = pool->next;
    }

    if (!pool) {
        pthread_mutex_unlock(&g_pool_mutex);
        return -1;
    }

    if (pool->used_prefixes >= pool->total_prefixes) {
        pthread_mutex_unlock(&g_pool_mutex);
        return -1; /* Exhausted */
    }

    /* Simple sequential allocation for now */
    /* TODO: Bitmap or free list for re-use */
    uint32_t idx = pool->used_prefixes;
    pool->used_prefixes++;

    /* Calculate address: base + (idx << (128 - alloc_len)) */
    /* Actually we need to shift idx 'relative' to the alloc size */
    /* The subnet ID is added to the base prefix */

    /* E.g. Base ::/48, Alloc /64. Gap = 16 bits.
       idx = 0 -> ::
       idx = 1 -> 0:0:0:1:: ...
    */

    *allocated_prefix = pool->base_prefix;

    /* Determine byte offset and bit shift for the index */
    /* Since we support up to 32-bit index, and standard alloc sizes (/64),
       we assume the index fits in the 'host' part of the parent prefix */

    /* Convert 32-bit index to 128-bit value shifted by (128 - alloc_len) */
    /* But ipv6_addr_inc adds to the lowest byte. */
    /* We effectively want to add 'idx' to the subnet field */

    /* Hard implementation:
       We treat the address as an array of bytes.
       The "increment unit" depends on alloc_len.
       If alloc_len is 64, we increment the 8th byte (index 7? no, 0-15).
       Indices 0-7 are /64 prefix. 8-15 are interface ID.
       Wait, if we allocate a /64, we increment the upper 64 bits?
       No, we increment the prefix part.

       Example pool: 2001:db8::/48
       Allocating /64s.
       Subnet bits are 64 - 48 = 16 bits. bits 48-63.
       This corresponds to bytes 6 and 7 (0-indexed).
    */

    /* Simplified Logic for Common Cases (/48 -> /64) */
    if (pool->prefix_len == 48 && pool->alloc_len == 64) {
        /* Modify bytes 6 and 7 */
        /* idx is 0..65535 */
        allocated_prefix->addr[6] |= (idx >> 8) & 0xFF;
        allocated_prefix->addr[7] |= (idx & 0xFF);
    } else if (pool->prefix_len == 56 && pool->alloc_len == 64) {
        /* Modify byte 7 */
        /* idx is 0..255 */
        allocated_prefix->addr[7] |= (idx & 0xFF);
    } else if (pool->prefix_len == 60 && pool->alloc_len == 64) {
         /* Modify byte 7 (lower nibble) */
         allocated_prefix->addr[7] |= (idx & 0x0F);
    } else {
        /* Fallback: just add idx to the very end (not technically correct for prefix math) */
        /* Or return error for unsupported generic math yet */
         pthread_mutex_unlock(&g_pool_mutex);
         YLOG_ERROR("Unsupported prefix/alloc length combination for simple math");
         return -1;
    }

    pthread_mutex_unlock(&g_pool_mutex);
    return 0;
}

int ipv6_pool_delete(const char *name)
{
    struct ipv6_pool *curr, *prev = NULL;

    pthread_mutex_lock(&g_pool_mutex);

    curr = g_pool_list;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                g_pool_list = curr->next;
            }
            free(curr);
            pthread_mutex_unlock(&g_pool_mutex);
            YLOG_INFO("Deleted IPv6 Pool '%s'", name);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&g_pool_mutex);
    return -1;
}

void ipv6_pool_free(const char *pool_name, struct ipv6_addr *prefix)
{
    /* Placeholder - decrement usage or update bitmap */
    (void)pool_name;
    (void)prefix;
}
