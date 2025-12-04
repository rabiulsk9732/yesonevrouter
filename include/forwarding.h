/**
 * @file forwarding.h
 * @brief Packet Forwarding Subsystem
 */

#ifndef FORWARDING_H
#define FORWARDING_H

#include "packet.h"

/**
 * @brief Start packet reception thread
 * @return 0 on success, -1 on error
 */
int packet_rx_start(void);

/**
 * @brief Stop packet reception thread
 */
void packet_rx_stop(void);

/**
 * @brief Transmit a packet
 * @param pkt Packet to transmit
 * @return 0 on success, -1 on error
 */
int packet_tx(struct pkt_buf *pkt);

#endif /* FORWARDING_H */
