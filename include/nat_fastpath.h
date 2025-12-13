/**
 * @file nat_fastpath.h
 * @brief NAT44 Fast Path Architecture (V2)
 *
 * Implements a 2-stage prefetch pipeline with zero-allocation mechanics.
 * Optimized for Intel Xeon (AVX2-ready layout).
 */

#ifndef NAT_FASTPATH_H
#define NAT_FASTPATH_H

#include <stdint.h>
#include <stdbool.h>
#include "nat.h"

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#else
/* Stub for non-DPDK builds (testing) */
struct rte_mbuf;
#endif

/* Configuration Constants */
#define NAT_BURST_SIZE 64
#define NAT_PREFETCH_OFFSET 4

/**
 * process_burst_fast
 *
 * Main entry point for V2 Dataplane.
 * Processes a burst of packets using a pipelined loop.
 *
 * Pipeline Stages:
 * 1. Prefetch mbuf headers (Stage 0)
 * 2. Parse L3/L4 & Calculate Hash (Stage 1)
 * 3. Lookup Session (Fast Index or Hash) (Stage 2)
 * 4. Translate & Checksum (Stage 3)
 *
 * @param pkts Array of mbuf pointers
 * @param count Number of packets in burst
 * @param iface Incoming interface (optional context)
 * @return Number of packets processed
 */
uint16_t nat_fastpath_process_burst(struct rte_mbuf **pkts, uint16_t count, void *iface);

/**
 * Initialize Fast Path resources
 * (Pre-allocates any per-core scratchpads)
 */
int nat_fastpath_init(void);

#endif /* NAT_FASTPATH_H */
