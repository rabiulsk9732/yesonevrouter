/**
 * @file nat_portblock.c
 * @brief NAT Port Block Allocation
 *
 * Implements dynamic port block allocation for Carrier-Grade NAT
 * Each subscriber gets a block of ports (default 64) from the public IP pool
 */

#include "nat.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>

/* Port block pool - global state */
static struct port_block_pool {
    struct port_block *blocks;     /* Array of port blocks */
    uint32_t max_blocks;           /* Maximum blocks */
    uint32_t num_blocks;           /* Currently allocated blocks */
    pthread_rwlock_t lock;         /* Read-write lock */
} g_port_block_pool;

/* External NAT config */
extern struct nat_config g_nat_config;

/**
 * Initialize port block pool
 */
int nat_portblock_init(uint32_t max_blocks)
{
    memset(&g_port_block_pool, 0, sizeof(g_port_block_pool));

    g_port_block_pool.blocks = calloc(max_blocks, sizeof(struct port_block));
    if (!g_port_block_pool.blocks) {
        YLOG_ERROR("Failed to allocate port block pool");
        return -1;
    }

    g_port_block_pool.max_blocks = max_blocks;
    g_port_block_pool.num_blocks = 0;

    pthread_rwlock_init(&g_port_block_pool.lock, NULL);

    YLOG_INFO("Port block pool initialized: %u max blocks", max_blocks);
    return 0;
}

/**
 * Cleanup port block pool
 */
void nat_portblock_cleanup(void)
{
    if (g_port_block_pool.blocks) {
        free(g_port_block_pool.blocks);
        g_port_block_pool.blocks = NULL;
    }

    pthread_rwlock_destroy(&g_port_block_pool.lock);
}

/**
 * Allocate a port block for a subscriber
 * @param subscriber_id Subscriber identifier
 * @param public_ip Public IP address (host byte order)
 * @param block_size Block size (e.g., 64 ports)
 * @return Port block ID, or -1 on error
 */
int nat_portblock_allocate(uint32_t subscriber_id, uint32_t public_ip, uint16_t block_size)
{
    int block_id = -1;

    pthread_rwlock_wrlock(&g_port_block_pool.lock);

    /* Check if subscriber already has a block */
    for (uint32_t i = 0; i < g_port_block_pool.num_blocks; i++) {
        if (g_port_block_pool.blocks[i].subscriber_id == subscriber_id &&
            g_port_block_pool.blocks[i].public_ip == public_ip) {
            /* Already allocated */
            block_id = i;
            pthread_rwlock_unlock(&g_port_block_pool.lock);
            return block_id;
        }
    }

    /* Allocate new block */
    if (g_port_block_pool.num_blocks >= g_port_block_pool.max_blocks) {
        YLOG_ERROR("Port block pool exhausted");
        pthread_rwlock_unlock(&g_port_block_pool.lock);
        return -1;
    }

    block_id = g_port_block_pool.num_blocks++;
    struct port_block *block = &g_port_block_pool.blocks[block_id];

    /* Calculate port range for this block
     * Port range: 1024-65535 (64512 ports)
     * Number of blocks possible: 64512 / 64 = 1008 blocks per IP
     */
    uint16_t block_start = 1024 + (block_id % 1008) * block_size;

    /* Initialize block */
    block->public_ip = public_ip;
    block->block_start = block_start;
    block->block_size = block_size;
    block->subscriber_id = subscriber_id;
    block->allocated_ts = time(NULL);
    block->port_bitmap = 0;  /* All ports free */

    /* Update statistics */
    g_nat_config.stats.port_blocks_allocated++;

    YLOG_INFO("Allocated port block %d: ports %u-%u for subscriber %u",
              block_id, block_start, block_start + block_size - 1, subscriber_id);

    pthread_rwlock_unlock(&g_port_block_pool.lock);
    return block_id;
}

/**
 * Allocate a port from subscriber's port block
 * @param subscriber_id Subscriber identifier
 * @param public_ip Public IP address
 * @param protocol Protocol (TCP/UDP)
 * @return Port number, or 0 on error
 */
uint16_t nat_portblock_allocate_port(uint32_t subscriber_id, uint32_t public_ip, uint8_t protocol)
{
    (void)protocol;  /* Reserved for future per-protocol allocation */

    pthread_rwlock_wrlock(&g_port_block_pool.lock);

    /* Find subscriber's port block */
    struct port_block *block = NULL;
    for (uint32_t i = 0; i < g_port_block_pool.num_blocks; i++) {
        if (g_port_block_pool.blocks[i].subscriber_id == subscriber_id &&
            g_port_block_pool.blocks[i].public_ip == public_ip) {
            block = &g_port_block_pool.blocks[i];
            break;
        }
    }

    if (!block) {
        /* Allocate new block for this subscriber */
        pthread_rwlock_unlock(&g_port_block_pool.lock);

        int block_id = nat_portblock_allocate(subscriber_id, public_ip, PORTS_PER_BLOCK);
        if (block_id < 0) {
            return 0;
        }

        pthread_rwlock_wrlock(&g_port_block_pool.lock);
        block = &g_port_block_pool.blocks[block_id];
    }

    /* Find free port in block using bitmap */
    for (uint16_t i = 0; i < block->block_size && i < 64; i++) {
        if (!(block->port_bitmap & (1ULL << i))) {
            /* Port is free - allocate it */
            block->port_bitmap |= (1ULL << i);
            uint16_t port = block->block_start + i;

            /* Update statistics */
            g_nat_config.stats.ports_allocated++;

            pthread_rwlock_unlock(&g_port_block_pool.lock);
            return port;
        }
    }

    /* No free ports in block */
    YLOG_WARNING("No free ports in block for subscriber %u", subscriber_id);
    pthread_rwlock_unlock(&g_port_block_pool.lock);

    g_nat_config.stats.no_port_available++;
    return 0;
}

/**
 * Release a port back to the pool
 * @param subscriber_id Subscriber identifier
 * @param public_ip Public IP address
 * @param port Port number
 */
void nat_portblock_release_port(uint32_t subscriber_id, uint32_t public_ip, uint16_t port)
{
    pthread_rwlock_wrlock(&g_port_block_pool.lock);

    /* Find subscriber's port block */
    for (uint32_t i = 0; i < g_port_block_pool.num_blocks; i++) {
        struct port_block *block = &g_port_block_pool.blocks[i];

        if (block->subscriber_id == subscriber_id &&
            block->public_ip == public_ip &&
            port >= block->block_start &&
            port < block->block_start + block->block_size) {

            /* Release port */
            uint16_t offset = port - block->block_start;
            if (offset < 64) {
                block->port_bitmap &= ~(1ULL << offset);
                g_nat_config.stats.ports_released++;
            }

            break;
        }
    }

    pthread_rwlock_unlock(&g_port_block_pool.lock);
}

/**
 * Get port block information for a subscriber
 * @param subscriber_id Subscriber identifier
 * @param public_ip Public IP address
 * @param block Output: port block info
 * @return 0 on success, -1 if not found
 */
int nat_portblock_get_info(uint32_t subscriber_id, uint32_t public_ip, struct port_block *block_out)
{
    if (!block_out) return -1;

    pthread_rwlock_rdlock(&g_port_block_pool.lock);

    for (uint32_t i = 0; i < g_port_block_pool.num_blocks; i++) {
        struct port_block *block = &g_port_block_pool.blocks[i];

        if (block->subscriber_id == subscriber_id && block->public_ip == public_ip) {
            memcpy(block_out, block, sizeof(*block_out));
            pthread_rwlock_unlock(&g_port_block_pool.lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&g_port_block_pool.lock);
    return -1;
}

/**
 * Print port block statistics
 */
void nat_portblock_print_stats(void)
{
    pthread_rwlock_rdlock(&g_port_block_pool.lock);

    printf("\nPort Block Allocation Statistics:\n");
    printf("  Total blocks: %u / %u\n", g_port_block_pool.num_blocks, g_port_block_pool.max_blocks);
    printf("  Blocks allocated: %lu\n", g_nat_config.stats.port_blocks_allocated);
    printf("  Blocks released: %lu\n", g_nat_config.stats.port_blocks_released);
    printf("  Ports allocated: %lu\n", g_nat_config.stats.ports_allocated);
    printf("  Ports released: %lu\n", g_nat_config.stats.ports_released);

    printf("\nActive Port Blocks:\n");
    printf("%-12s %-15s %-12s %-10s %-10s\n", "Block ID", "Public IP", "Port Range", "Subscriber", "Used Ports");
    printf("--------------------------------------------------------------------------------\n");

    for (uint32_t i = 0; i < g_port_block_pool.num_blocks; i++) {
        struct port_block *block = &g_port_block_pool.blocks[i];

        char ip_str[16];
        struct in_addr addr;
        addr.s_addr = htonl(block->public_ip);
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        /* Count used ports */
        int used_ports = __builtin_popcountll(block->port_bitmap);

        printf("%-12u %-15s %5u-%-5u %-10u %d/%u\n",
               i, ip_str,
               block->block_start, block->block_start + block->block_size - 1,
               block->subscriber_id,
               used_ports, block->block_size);
    }

    pthread_rwlock_unlock(&g_port_block_pool.lock);
}
