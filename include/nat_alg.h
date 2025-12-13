/**
 * @file nat_alg.h
 * @brief NAT Application Level Gateway (ALG) definitions
 */

#ifndef NAT_ALG_H
#define NAT_ALG_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"

/* Forward declaration */
struct nat_session;

/* ALG Types */
enum nat_alg_type {
    NAT_ALG_NONE = 0,
    NAT_ALG_FTP,
    NAT_ALG_SIP,
    NAT_ALG_ICMP, /* Handled separately */
    NAT_ALG_PPTP,
    NAT_ALG_RTSP,
    NAT_ALG_TFTP,
    NAT_ALG_H323,
    NAT_ALG_MAX
};

/**
 * Detect if a session requires ALG processing based on destination port
 * @param protocol L4 protocol
 * @param dst_port Destination port
 * @return ALG type or NAT_ALG_NONE
 */
uint8_t nat_alg_detect(uint8_t protocol, uint16_t dst_port);

/**
 * Process packet through ALG
 * @param session NAT session
 * @param pkt Packet buffer
 * @param is_in2out True if packet is LAN->WAN
 * @return 0 on success (modified or passed), -1 on drop
 */
int nat_alg_process(struct nat_session *session, struct pkt_buf *pkt, bool is_in2out);

#endif /* NAT_ALG_H */
