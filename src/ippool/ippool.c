/**
 * @file ippool.c
 * @brief IP Address Pool Management Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "ippool.h"
#include "log.h"

static struct ip_pool g_pools[IPPOOL_MAX_POOLS];
static int g_num_pools = 0;

int ippool_init(void)
{
    memset(g_pools, 0, sizeof(g_pools));
    g_num_pools = 0;
    return 0;
}

int ippool_create(const char *name, uint32_t start_ip, uint32_t end_ip)
{
    if (!name || start_ip > end_ip || g_num_pools >= IPPOOL_MAX_POOLS) {
        return -1;
    }

    /* Check for duplicate name */
    if (ippool_get_by_name(name)) {
        YLOG_ERROR("IP Pool '%s' already exists", name);
        return -1;
    }

    struct ip_pool *pool = &g_pools[g_num_pools];
    strncpy(pool->name, name, IPPOOL_NAME_LEN - 1);
    pool->start_ip = start_ip;
    pool->end_ip = end_ip;
    pool->total_ips = (end_ip - start_ip) + 1;
    pool->used_ips = 0;
    pool->next_alloc_idx = 0;
    pool->active = true;

    /* Allocate bitmap */
    /* 1 bit per IP. Size = (total_ips + 31) / 32 * 4 bytes */
    uint32_t bitmap_size = (pool->total_ips + 31) / 32;
    pool->bitmap = calloc(bitmap_size, sizeof(uint32_t));
    if (!pool->bitmap) {
        YLOG_ERROR("Failed to allocate bitmap for pool '%s'", name);
        return -1;
    }

    /* Allocate reservations */
    pool->reservations = calloc(pool->total_ips, sizeof(struct ip_reservation));
    if (!pool->reservations) {
        free(pool->bitmap);
        YLOG_ERROR("Failed to allocate reservations for pool '%s'", name);
        return -1;
    }

    g_num_pools++;
    YLOG_INFO("Created IP Pool '%s': %u IPs", name, pool->total_ips);
    return 0;
}

int ippool_delete(const char *name)
{
    for (int i = 0; i < g_num_pools; i++) {
        if (g_pools[i].active && strcmp(g_pools[i].name, name) == 0) {
            free(g_pools[i].bitmap);
            free(g_pools[i].reservations);
            g_pools[i].active = false;
            YLOG_INFO("Deleted IP Pool '%s'", name);
            return 0;
        }
    }
    return -1;
}

struct ip_pool *ippool_get_by_name(const char *name)
{
    for (int i = 0; i < g_num_pools; i++) {
        if (g_pools[i].active && strcmp(g_pools[i].name, name) == 0) {
            return &g_pools[i];
        }
    }
    return NULL;
}

uint32_t ippool_alloc_ip(const char *pool_name, const uint8_t *mac)
{
    fprintf(stderr, "[IPPOOL] ippool_alloc_ip called: pool='%s' g_num_pools=%d\n", pool_name, g_num_pools);
    fflush(stderr);

    struct ip_pool *pool = ippool_get_by_name(pool_name);
    if (!pool) {
        fprintf(stderr, "[IPPOOL] ERROR: pool '%s' not found!\n", pool_name);
        fflush(stderr);
        return 0;
    }

    fprintf(stderr, "[IPPOOL] Found pool '%s': total=%u used=%u\n", pool->name, pool->total_ips, pool->used_ips);
    fflush(stderr);

    if (pool->used_ips >= pool->total_ips) {
        fprintf(stderr, "[IPPOOL] ERROR: pool '%s' exhausted!\n", pool_name);
        fflush(stderr);
        return 0;
    }

    /* Sticky IP Check */
    if (mac) {
        for (uint32_t i = 0; i < pool->total_ips; i++) {
            if (memcmp(pool->reservations[i].mac, mac, 6) == 0) {
                /* Found previous reservation */
                uint32_t idx = i;
                uint32_t word_idx = idx / 32;
                uint32_t bit_idx = idx % 32;

                if (!(pool->bitmap[word_idx] & (1U << bit_idx))) {
                    /* IP is free, re-assign it */
                    pool->bitmap[word_idx] |= (1U << bit_idx);
                    pool->used_ips++;
                    pool->reservations[i].active = true;
                    pool->reservations[i].last_seen = 0; /* TODO: Get time */
                    YLOG_INFO("IP Pool '%s': Sticky IP %u allocated to %02x:%02x:%02x:%02x:%02x:%02x",
                              pool_name, pool->start_ip + idx,
                              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    return pool->start_ip + idx;
                } else {
                    /* IP is taken (shouldn't happen if logic is correct, unless conflict) */
                    /* Fallback to new allocation */
                }
            }
        }
    }

    /* Simple linear search from next_alloc_idx */
    /* TODO: Optimize wrapping and searching */
    for (uint32_t i = 0; i < pool->total_ips; i++) {
        uint32_t idx = (pool->next_alloc_idx + i) % pool->total_ips;
        uint32_t word_idx = idx / 32;
        uint32_t bit_idx = idx % 32;

        if (!(pool->bitmap[word_idx] & (1U << bit_idx))) {
            /* Found free IP */
            pool->bitmap[word_idx] |= (1U << bit_idx);
            pool->used_ips++;
            pool->next_alloc_idx = (idx + 1) % pool->total_ips;

            /* Record reservation */
            if (mac) {
                memcpy(pool->reservations[idx].mac, mac, 6);
                pool->reservations[idx].active = true;
                pool->reservations[idx].last_seen = 0; /* TODO: Get time */
            }

            return pool->start_ip + idx;
        }
    }

    return 0;
}

void ippool_free_ip(const char *pool_name, uint32_t ip)
{
    struct ip_pool *pool = ippool_get_by_name(pool_name);
    if (!pool) return;

    if (ip < pool->start_ip || ip > pool->end_ip) {
        return;
    }

    uint32_t idx = ip - pool->start_ip;
    uint32_t word_idx = idx / 32;
    uint32_t bit_idx = idx % 32;

    if (pool->bitmap[word_idx] & (1U << bit_idx)) {
        pool->bitmap[word_idx] &= ~(1U << bit_idx);
        pool->used_ips--;
        pool->reservations[idx].active = false;
    }
}

void ippool_print_all(void)
{
    printf("\nIP Pools:\n");
    for (int i = 0; i < g_num_pools; i++) {
        if (!g_pools[i].active) continue;

        char start[16], end[16];
        struct in_addr addr;

        addr.s_addr = htonl(g_pools[i].start_ip);
        inet_ntop(AF_INET, &addr, start, sizeof(start));
        addr.s_addr = htonl(g_pools[i].end_ip);
        inet_ntop(AF_INET, &addr, end, sizeof(end));

        printf("  %s: %s - %s (%u/%u used)\n",
               g_pools[i].name, start, end,
               g_pools[i].used_ips, g_pools[i].total_ips);
    }
}
