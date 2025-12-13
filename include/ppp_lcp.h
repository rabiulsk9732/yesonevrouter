/**
 * @file ppp_lcp.h
 * @brief PPP Link Control Protocol (LCP) Definitions
 */

#ifndef PPP_LCP_H
#define PPP_LCP_H

#include <stdint.h>
#include "pppoe.h"

/* LCP Header */
struct lcp_hdr {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t data[];
} __attribute__((packed));

/* LCP Option Header */
struct lcp_opt_hdr {
    uint8_t type;
    uint8_t length;
    uint8_t data[];
} __attribute__((packed));

/**
 * Initialize LCP for a session
 * @param session PPPoE session
 */
void ppp_lcp_init(struct pppoe_session *session);

/**
 * Open LCP connection (send Configure-Request)
 * @param session PPPoE session
 */
void ppp_lcp_open(struct pppoe_session *session);

/**
 * Close LCP connection (send Terminate-Request)
 * @param session PPPoE session
 */
void ppp_lcp_close(struct pppoe_session *session);

/**
 * Send LCP Echo-Request
 * @param session PPPoE session
 */
void ppp_lcp_send_echo_request(struct pppoe_session *session);

/**
 * Process LCP packet
 * @param session PPPoE session
 * @param packet LCP packet data (starting from Code)
 * @param len Length of LCP packet
 * @return 0 on success, -1 on error
 */
int ppp_lcp_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len);

#endif /* PPP_LCP_H */
