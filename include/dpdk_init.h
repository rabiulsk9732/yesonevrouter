/**
 * @file dpdk_init.h
 * @brief DPDK Initialization and Management
 *
 * Handles DPDK EAL initialization, memory pool setup, and core management.
 */

#ifndef DPDK_INIT_H
#define DPDK_INIT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#endif

/* DPDK Configuration */
#define DPDK_NUM_MBUFS 32767 - 1
#define DPDK_MBUF_CACHE_SIZE 250
#define DPDK_BURST_SIZE 32
#define DPDK_RX_RING_SIZE 1024
#define DPDK_TX_RING_SIZE 1024

/* Memory pool structure */
struct dpdk_mempool {
    void *pool; /* rte_mempool pointer */
    char name[32];
    uint32_t num_elements;
    uint32_t element_size;
    uint32_t cache_size;
};

/* DPDK configuration */
struct dpdk_config {
    bool enabled;                     /* DPDK enabled/disabled */
    uint32_t num_lcores;              /* Number of logical cores */
    uint32_t socket_id;               /* NUMA socket ID */
    uint32_t num_mbufs;               /* Number of mbufs in pool */
    struct dpdk_mempool *pkt_mempool; /* Packet memory pool */
};

/* Global DPDK state */
extern struct dpdk_config g_dpdk_config;

/**
 * Initialize DPDK EAL (Environment Abstraction Layer)
 * @param argc Argument count
 * @param argv Argument values
 * @return 0 on success, -1 on failure
 */
int dpdk_init(int argc, char *argv[]);

/**
 * Create packet memory pool
 * @param name Pool name
 * @param num_elements Number of elements in pool
 * @param socket_id NUMA socket ID
 * @return Pointer to memory pool or NULL on failure
 */
struct dpdk_mempool *dpdk_mempool_create(const char *name, uint32_t num_elements,
                                         uint32_t socket_id);

/**
 * Free memory pool
 * @param mp Memory pool to free
 */
void dpdk_mempool_free(struct dpdk_mempool *mp);

/**
 * Initialize CPU core affinity
 * @param lcore_id Logical core ID
 * @return 0 on success, -1 on failure
 */
int dpdk_set_lcore_affinity(uint32_t lcore_id);

/**
 * Get number of available logical cores
 * @return Number of logical cores
 */
uint32_t dpdk_get_lcore_count(void);

/**
 * Get NUMA socket ID for current lcore
 * @return Socket ID
 */
uint32_t dpdk_get_socket_id(void);

/**
 * Cleanup and shutdown DPDK
 */
void dpdk_cleanup(void);

/**
 * Check if DPDK is enabled and initialized
 * @return true if enabled, false otherwise
 */
bool dpdk_is_enabled(void);

/**
 * Get the global packet memory pool for mbuf allocation
 * @return rte_mempool pointer or NULL if DPDK not initialized
 */
struct rte_mempool *dpdk_get_mempool(void);

#endif /* DPDK_INIT_H */
