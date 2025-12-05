/**
 * @file tx_batch.h
 * @brief TX Batching API
 */

#ifndef TX_BATCH_H
#define TX_BATCH_H

#include <stdint.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#endif

/**
 * Initialize TX batching
 * @param num_ports Number of DPDK ports
 */
int tx_batch_init(int num_ports);

/**
 * Cleanup TX batching
 */
void tx_batch_cleanup(void);

/**
 * Enqueue packet for batched transmission
 * @param port_id DPDK port ID
 * @param mbuf Packet mbuf (ownership transferred)
 */
#ifdef HAVE_DPDK
int tx_batch_enqueue(uint16_t port_id, struct rte_mbuf *mbuf);
#else
int tx_batch_enqueue(uint16_t port_id, void *mbuf);
#endif

/**
 * Force flush a specific port's buffer
 */
void tx_batch_flush_port(uint16_t port_id);

/**
 * Force flush all port buffers
 */
void tx_batch_flush_all(void);

/**
 * Check for timeout-based flushes (call periodically)
 */
void tx_batch_check_timeouts(void);

#endif /* TX_BATCH_H */
