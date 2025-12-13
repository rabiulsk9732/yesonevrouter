/**
 * @file dpdk_numa.h
 * @brief NUMA-Aware Memory and Multi-Queue API
 */

#ifndef DPDK_NUMA_H
#define DPDK_NUMA_H

#include <stdint.h>

#ifdef HAVE_DPDK
#include <rte_mempool.h>
#endif

/**
 * Initialize NUMA subsystem
 */
int dpdk_numa_init(void);

/**
 * Cleanup NUMA resources
 */
void dpdk_numa_cleanup(void);

/**
 * Create mempool on specific NUMA node
 * @param numa_node NUMA node ID
 * @param name Pool name prefix
 * @param num_mbufs Number of mbufs
 * @param mbuf_size Data room size (0 for default)
 */
#ifdef HAVE_DPDK
struct rte_mempool *dpdk_numa_create_mempool(int numa_node, const char *name,
                                              uint32_t num_mbufs, uint16_t mbuf_size);
struct rte_mempool *dpdk_numa_create_jumbo_mempool(int numa_node, const char *name);
struct rte_mempool *dpdk_numa_get_mempool(int numa_node);
#else
void *dpdk_numa_create_mempool(int numa_node, const char *name,
                               uint32_t num_mbufs, uint16_t mbuf_size);
void *dpdk_numa_create_jumbo_mempool(int numa_node, const char *name);
void *dpdk_numa_get_mempool(int numa_node);
#endif

/**
 * Get NUMA socket for lcore
 */
int dpdk_numa_get_socket_for_lcore(unsigned int lcore_id);

/**
 * Configure port with multiple RX/TX queues
 */
#ifdef HAVE_DPDK
int dpdk_multiqueue_configure_port(uint16_t port_id, uint16_t num_rx_queues,
                                    uint16_t num_tx_queues, struct rte_mempool *pool);
#else
int dpdk_multiqueue_configure_port(uint16_t port_id, uint16_t num_rx_queues,
                                    uint16_t num_tx_queues, void *pool);
#endif

/**
 * Get configured queue count for port
 */
int dpdk_multiqueue_get_queue_count(uint16_t port_id, uint16_t *rx_queues, uint16_t *tx_queues);

/**
 * Enable jumbo frame support
 * @param max_frame_size Maximum frame size (default 9000)
 */
int dpdk_jumbo_frame_enable(uint16_t port_id, uint16_t max_frame_size);

#endif /* DPDK_NUMA_H */
