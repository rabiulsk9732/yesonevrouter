/**
 * @file alg.h
 * @brief Application Level Gateway Framework
 */

#ifndef ALG_H
#define ALG_H

#include <stdbool.h>
#include <stdint.h>

/* Forward declarations */
struct pkt_buf;
struct rte_mbuf;

/**
 * ICMP ALG: Process ICMP error messages
 * @param m DPDK mbuf
 * @param outbound True if outbound (inside→outside), false if inbound
 * @return 0 on success, -1 on error
 */
int alg_icmp_process_error(struct rte_mbuf *m, bool outbound);

/**
 * Check if ICMP ALG is needed
 * @param pkt Packet buffer
 * @return True if ALG processing needed
 */
bool alg_icmp_is_needed(struct pkt_buf *pkt);

#endif /* ALG_H */
