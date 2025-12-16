/**
 * @file ppp_auth.h
 * @brief PPP Authentication Protocols (PAP/CHAP) Definitions
 */

#ifndef PPP_AUTH_H
#define PPP_AUTH_H

#include "pppoe.h"
#include <stdint.h>

/* PAP Codes */
#define PAP_CODE_AUTH_REQ 1 /* Authenticate-Request */
#define PAP_CODE_AUTH_ACK 2 /* Authenticate-Ack */
#define PAP_CODE_AUTH_NAK 3 /* Authenticate-Nak */

/* CHAP Codes */
#define CHAP_CODE_CHALLENGE 1 /* Challenge */
#define CHAP_CODE_RESPONSE 2  /* Response */
#define CHAP_CODE_SUCCESS 3   /* Success */
#define CHAP_CODE_FAILURE 4   /* Failure */

/**
 * Initialize Authentication for a session
 * @param session PPPoE session
 */
void ppp_auth_init(struct pppoe_session *session);

/**
 * Start authentication phase after LCP opens
 * Called when both sides have exchanged Config-Ack (RFC 1661)
 * For CHAP: Sends challenge to client
 * For PAP: Waits for client's Auth-Request
 * @param session PPPoE session
 */
void ppp_auth_start(struct pppoe_session *session);

/**
 * Process PAP packet
 * @param session PPPoE session
 * @param packet PAP packet data (starting from Code)
 * @param len Length of PAP packet
 * @return 0 on success, -1 on error
 */
int ppp_pap_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len);

/**
 * Process CHAP packet
 * @param session PPPoE session
 * @param packet CHAP packet data (starting from Code)
 * @param len Length of CHAP packet
 * @return 0 on success, -1 on error
 */
int ppp_chap_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len);

int ppp_auth_send(struct pppoe_session *session, uint16_t protocol, uint8_t code,
                  uint8_t identifier, const uint8_t *data, uint16_t len);

/**
 * Send CHAP Challenge
 * @param session PPPoE session
 */
void ppp_chap_send_challenge(struct pppoe_session *session);

#endif /* PPP_AUTH_H */
