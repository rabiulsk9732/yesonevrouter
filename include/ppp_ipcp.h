/**
 * @file ppp_ipcp.h
 * @brief PPP IP Control Protocol (IPCP) Definitions
 */

#ifndef PPP_IPCP_H
#define PPP_IPCP_H

#include <stdint.h>
#include "pppoe.h"

/**
 * Initialize IPCP for a session
 * @param session PPPoE session
 */
void ppp_ipcp_init(struct pppoe_session *session);

/**
 * Open IPCP connection (send Configure-Request)
 * @param session PPPoE session
 */
void ppp_ipcp_open(struct pppoe_session *session);

/**
 * Close IPCP connection (send Terminate-Request)
 * @param session PPPoE session
 */
void ppp_ipcp_close(struct pppoe_session *session);

/**
 * Process IPCP packet
 * @param session PPPoE session
 * @param packet IPCP packet data (starting from Code)
 * @param len Length of IPCP packet
 * @return 0 on success, -1 on error
 */
int ppp_ipcp_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len);

#endif /* PPP_IPCP_H */
