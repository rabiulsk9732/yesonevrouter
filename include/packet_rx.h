/**
 * @file packet_rx.h
 * @brief Packet Reception API
 */

#ifndef PACKET_RX_H
#define PACKET_RX_H

#include "packet.h"

/**
 * Start packet reception thread
 * @return 0 on success, -1 on error
 */
int packet_rx_start(void);

/**
 * Stop packet reception thread
 */
void packet_rx_stop(void);

/**
 * Process a received packet (inject into pipeline)
 * @param pkt Packet buffer
 */
void packet_rx_process_packet(struct pkt_buf *pkt);

#endif /* PACKET_RX_H */
