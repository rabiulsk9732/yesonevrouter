/**
 * @file ppp_lcp.c
 * @brief PPP Link Control Protocol (LCP) Implementation
 */

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "log.h"
#include "packet.h"
#include "ppp_auth.h"
#include "ppp_lcp.h"
#include "pppoe.h"
#include "pppoe_defs.h"
#include "pppoe_tx.h"
#include <time.h>

/* Helper to send LCP packet - Uses pppoe_tx_send_session for proper VLAN handling */
static int ppp_lcp_send(struct pppoe_session *session, uint8_t code, uint8_t identifier,
                        const uint8_t *data, uint16_t len)
{
    /* Build PPPoE + PPP + LCP payload */
    uint8_t pppoe_buf[1500];
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)pppoe_buf;
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    struct lcp_hdr *lcp = (struct lcp_hdr *)(proto + 1);

    YLOG_INFO("LCP SEND: session=%u vlan_id=%u iface=%s code=%u", session->session_id,
              session->vlan_id, session->iface->name, code);

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_SESS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* PPP Protocol */
    *proto = rte_cpu_to_be_16(PPP_PROTO_LCP);

    /* LCP Header */
    lcp->code = code;
    lcp->identifier = identifier;
    lcp->length = rte_cpu_to_be_16(sizeof(struct lcp_hdr) + len);

    /* LCP Data */
    if (data && len > 0) {
        memcpy(lcp->data, data, len);
    }

    /* Set PPPoE length */
    uint16_t ppp_len = sizeof(uint16_t) + sizeof(struct lcp_hdr) + len;
    pppoe->length = rte_cpu_to_be_16(ppp_len);

    uint16_t payload_len = sizeof(struct pppoe_hdr) + ppp_len;

    /* Get port_id: For VLAN iface, get parent's DPDK port via parent_ifindex */
    /* For physical iface, port_id is in flags (lower 31 bits) */
    struct interface *phys_iface = session->iface;
    if (session->iface->type == IF_TYPE_VLAN && session->iface->config.parent_ifindex > 0) {
        phys_iface = interface_find_by_index(session->iface->config.parent_ifindex);
    }
    uint16_t port_id = (uint16_t)(phys_iface->flags & 0x7FFFFFFF);
    uint16_t queue_id = 0; /* Use queue 0 for control packets */

    /* Use pppoe_tx_send_session for proper VLAN handling */
    int result =
        pppoe_tx_send_session(port_id, queue_id, &session->client_mac, session->iface->mac_addr,
                              session->vlan_id, pppoe_buf, payload_len);
    if (result < 0) {
        YLOG_ERROR("LCP TX FAILED: session=%u code=%u result=%d", session->session_id, code,
                   result);
    } else {
        YLOG_DEBUG("LCP TX OK: session=%u code=%u port=%u vlan=%u len=%u", session->session_id,
                   code, port_id, session->vlan_id, payload_len);
    }
    return result;
}

/* Send Configure-Request */
static void ppp_lcp_send_conf_req(struct pppoe_session *session)
{
    uint8_t options[64];
    uint16_t len = 0;

    /* Option: Magic Number */
    struct lcp_opt_hdr *opt = (struct lcp_opt_hdr *)(options + len);
    opt->type = LCP_OPT_MAGIC_NUM;
    opt->length = 6;
    *(uint32_t *)(opt->data) = rte_cpu_to_be_32(session->magic_number);
    len += opt->length;

    /* Option: MRU */
    opt = (struct lcp_opt_hdr *)(options + len);
    opt->type = LCP_OPT_MRU;
    opt->length = 4;
    *(uint16_t *)(opt->data) = rte_cpu_to_be_16(1492); /* PPPoE MRU */
    len += opt->length;

    /* RFC 1661 Correct Approach:
     * - LCP negotiates link options (MRU, Magic) only
     * - DO NOT include Auth-Protocol in Configure-Request
     * - After LCP OPENS, WE (acting as NAS) initiate CHAP Challenge
     * - RADIUS verification happens after CHAP Response received
     *
     * If client wants auth negotiated, it will NAK and we adapt.
     * Most clients (including Mikrotik) open LCP without auth option,
     * then expect server to send CHAP Challenge after LCP OPENED.
     */
    YLOG_INFO("LCP: Configure-Request with MRU=1492, Magic (no Auth-Proto - auth after LCP opens)");

    ppp_lcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
    YLOG_INFO("LCP: Sent Configure-Request for session %u (state=%d)", session->session_id,
              session->lcp_state);

    /* Only update state if we haven't already sent ConfAck (ACK_SENT) */
    /* RFC 1661: If we're in ACK_SENT, we keep that state until we receive their ConfAck */
    if (session->lcp_state != LCP_STATE_ACK_SENT) {
        session->lcp_state = LCP_STATE_REQ_SENT;
    }
    session->last_conf_req_ts = time(NULL);
}

/* RFC 1661: Check if LCP should transition to OPENED state
 * Requires BOTH: we sent Config-Ack AND peer sent Config-Ack
 */
static void lcp_check_open(struct pppoe_session *session)
{
    YLOG_DEBUG(
        "LCP: check_open session=%u peer_acked_us=%d we_acked_peer=%d state=%d auth_started=%d",
        session->session_id, session->lcp_peer_acked_us, session->lcp_we_acked_peer,
        session->lcp_state, session->lcp_auth_started);

    if (session->lcp_peer_acked_us && session->lcp_we_acked_peer) {
        if (session->lcp_state != LCP_STATE_OPENED) {
            session->lcp_state = LCP_STATE_OPENED;
            YLOG_INFO("LCP Session %u OPENED (RFC 1661: bidirectional Config-Ack complete)",
                      session->session_id);

            /* Start authentication ONCE per session */
            if (!session->lcp_auth_started) {
                session->lcp_auth_started = 1;
                ppp_auth_start(session);
            }
        }
    }
}

static void ppp_lcp_send_conf_ack(struct pppoe_session *session, uint8_t identifier,
                                  const uint8_t *options, uint16_t len)
{
    YLOG_INFO("LCP: Sending Config-Ack with id=%u len=%u (echoing peer's options)", identifier,
              len);
    ppp_lcp_send(session, LCP_CODE_CONF_ACK, identifier, options, len);

    /* RFC 1661: Mark that we have sent Config-Ack to peer */
    session->lcp_we_acked_peer = 1;
    YLOG_INFO("LCP: Sent Config-Ack for session %u (we_acked_peer=1)", session->session_id);

    /* Update state to ACK_SENT if we haven't received peer's Ack yet */
    if (!session->lcp_peer_acked_us) {
        session->lcp_state = LCP_STATE_ACK_SENT;
    }

    /* Check if both conditions met for OPENED */
    lcp_check_open(session);
}

/* Send Configure-Reject */
static void ppp_lcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier,
                                  const uint8_t *options, uint16_t len) __attribute__((unused));
static void ppp_lcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier,
                                  const uint8_t *options, uint16_t len)
{
    ppp_lcp_send(session, LCP_CODE_CONF_REJ, identifier, options, len);
}

static void ppp_lcp_send_conf_nak(struct pppoe_session *session, uint8_t identifier,
                                  const uint8_t *options, uint16_t len)
{
    ppp_lcp_send(session, LCP_CODE_CONF_NAK, identifier, options, len);
}

/* Send Echo-Request */
void ppp_lcp_send_echo_request(struct pppoe_session *session)
{
    uint8_t data[4];
    *(uint32_t *)data = rte_cpu_to_be_32(session->magic_number);
    ppp_lcp_send(session, LCP_CODE_ECHO_REQ, ++session->next_lcp_identifier, data, 4);
}

void ppp_lcp_init(struct pppoe_session *session)
{
    session->lcp_state = LCP_STATE_INITIAL;
    session->magic_number = rand(); /* Simple random for now */
}

void ppp_lcp_open(struct pppoe_session *session)
{
    YLOG_INFO("LCP: Opening session %u", session->session_id);
    session->lcp_state = LCP_STATE_STARTING;

    /* Per accel-ppp pattern:
     * Server sends Configure-Request with Auth-Protocol option.
     * Client will ACK/NAK/REJ. After bidirectional ACK, LCP opens.
     */
    ppp_lcp_send_conf_req(session);
}

void ppp_lcp_close(struct pppoe_session *session)
{
    session->lcp_state = LCP_STATE_CLOSING;
    ppp_lcp_send(session, LCP_CODE_TERM_REQ, ++session->next_lcp_identifier, NULL, 0);
}

int ppp_lcp_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len)
{
    const struct lcp_hdr *lcp = (const struct lcp_hdr *)packet;
    if (len < sizeof(struct lcp_hdr))
        return -1;

    uint16_t lcp_len = rte_be_to_cpu_16(lcp->length);
    if (lcp_len > len)
        return -1;

    const uint8_t *data = lcp->data;
    uint16_t data_len = lcp_len - sizeof(struct lcp_hdr);

    YLOG_INFO("LCP RX: code=%u id=%u len=%u state=%d", lcp->code, lcp->identifier, lcp_len,
              session->lcp_state);
    switch (lcp->code) {
    case LCP_CODE_CONF_REQ: {
        YLOG_INFO("LCP: Received Configure-Request (State=%u, Retry=%u)", session->lcp_state,
                  session->conf_req_retries);

        uint8_t ack_options[1500];
        uint16_t ack_len = 0;
        uint8_t nak_options[1500];
        uint16_t nak_len = 0;
        uint8_t rej_options[1500];
        uint16_t rej_len = 0;

        uint16_t offset = 0;
        while (offset < data_len) {
            struct lcp_opt_hdr *opt = (struct lcp_opt_hdr *)(data + offset);
            /* Validate option length */
            if (offset + sizeof(struct lcp_opt_hdr) > data_len || opt->length < 2 ||
                offset + opt->length > data_len) {
                break;
            }

            bool handled = false;

            switch (opt->type) {
            case LCP_OPT_MRU:
                if (opt->length == 4) {
                    uint16_t mru = rte_be_to_cpu_16(*(uint16_t *)opt->data);
                    session->peer_mru = mru;
                    memcpy(ack_options + ack_len, opt, opt->length);
                    ack_len += opt->length;
                    handled = true;
                }
                break;

            case LCP_OPT_AUTH_PROTO:
                /* ACK the auth protocol to tell client we accept it
                 * Store the auth protocol for later use
                 */
                if (opt->length == 4) {
                    uint16_t auth_proto = rte_be_to_cpu_16(*(uint16_t *)opt->data);
                    session->auth_protocol = auth_proto;
                    YLOG_INFO("LCP: Client requested auth protocol 0x%04x", auth_proto);
                    memcpy(ack_options + ack_len, opt, opt->length);
                    ack_len += opt->length;
                }
                handled = true;
                break;

            case LCP_OPT_MAGIC_NUM:
                if (opt->length == 6) {
                    uint32_t magic = rte_be_to_cpu_32(*(uint32_t *)opt->data);
                    if (magic == session->magic_number) {
                        /* Loop detected - NAK with different value */
                        uint32_t sugg = ~magic;
                        struct lcp_opt_hdr *nak_opt = (struct lcp_opt_hdr *)(nak_options + nak_len);
                        nak_opt->type = LCP_OPT_MAGIC_NUM;
                        nak_opt->length = 6;
                        *(uint32_t *)nak_opt->data = rte_cpu_to_be_32(sugg);
                        nak_len += 6;
                    } else {
                        session->peer_magic_number = magic;
                        memcpy(ack_options + ack_len, opt, opt->length);
                        ack_len += opt->length;
                    }
                    handled = true;
                }
                break;
            }

            if (!handled) {
                /* Reject unknown/unsupported options (PFC, ACFC, etc) */
                memcpy(rej_options + rej_len, opt, opt->length);
                rej_len += opt->length;
            }

            offset += opt->length;
        }

        /* Decision Logic - Follow accel-ppp approach:
         * Just ACK what the client sends, don't try to negotiate auth during LCP
         * Auth is handled AFTER LCP opens (in ppp_auth_start)
         */
        if (rej_len > 0) {
            YLOG_INFO("LCP: Sending Config-Reject (len=%u)", rej_len);
            ppp_lcp_send_conf_rej(session, lcp->identifier, rej_options, rej_len);
        } else if (nak_len > 0) {
            YLOG_INFO("LCP: Sending Config-Nak (len=%u)", nak_len);
            ppp_lcp_send_conf_nak(session, lcp->identifier, nak_options, nak_len);
        } else {
            /* All options acceptable - ACK them
             * Don't check for auth protocol here - handled in auth layer
             */
            YLOG_INFO("LCP: Sending Config-Ack (len=%u)", ack_len);
            ppp_lcp_send_conf_ack(session, lcp->identifier, ack_options, ack_len);

            /* If client started LCP negotiation before us (passive open),
             * send our Configure-Request now after acking theirs.
             * This ensures proper sequencing for some clients that expect
             * server to acknowledge before server sends its own request.
             */
            if (session->lcp_state == LCP_STATE_STARTING ||
                session->lcp_state == LCP_STATE_INITIAL ||
                session->lcp_state == LCP_STATE_STOPPED) {
                YLOG_INFO("LCP: Sending our Configure-Request (passive open mode)");
                ppp_lcp_send_conf_req(session);
            }
        }

        break;
    }

    case LCP_CODE_CONF_ACK:
        YLOG_INFO("LCP: Received Configure-Ack for session %u", session->session_id);

        /* RFC 1661: Mark that peer ACKed our Configure-Request */
        session->lcp_peer_acked_us = 1;
        YLOG_INFO("LCP: Session %u peer_acked_us=1", session->session_id);

        /* Update state to ACK_RCVD if we haven't sent our Ack yet */
        if (!session->lcp_we_acked_peer) {
            session->lcp_state = LCP_STATE_ACK_RCVD;
        }

        /* Check if both conditions met for OPENED */
        lcp_check_open(session);
        break;

    case LCP_CODE_CONF_NAK:
        YLOG_INFO("LCP: Received Configure-Nak");
        /* Check if peer is suggesting PAP */
        /* Naive check: just resend REQ with PAP if we were trying CHAP */
        /* TODO: Parse NAK options properly */
        {
            uint8_t options[64];
            uint16_t len = 0;

            /* Option: Magic Number */
            struct lcp_opt_hdr *opt = (struct lcp_opt_hdr *)(options + len);
            opt->type = LCP_OPT_MAGIC_NUM;
            opt->length = 6;
            *(uint32_t *)(opt->data) = rte_cpu_to_be_32(session->magic_number);
            len += opt->length;

            /* Option: MRU */
            opt = (struct lcp_opt_hdr *)(options + len);
            opt->type = LCP_OPT_MRU;
            opt->length = 4;
            *(uint16_t *)(opt->data) = rte_cpu_to_be_16(1492);
            len += opt->length;

            /* Option: Auth Protocol (PAP) - Fallback */
            opt = (struct lcp_opt_hdr *)(options + len);
            opt->type = LCP_OPT_AUTH_PROTO;
            opt->length = 4;
            *(uint16_t *)(opt->data) = rte_cpu_to_be_16(PPP_PROTO_PAP);
            session->auth_protocol = PPP_PROTO_PAP;
            len += opt->length;

            ppp_lcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
        }
        break;

    case LCP_CODE_CONF_REJ:
        YLOG_INFO("LCP: Received Configure-Reject");
        /* TODO: Handle REJ (remove options and resend REQ) */
        break;

    case LCP_CODE_ECHO_REQ:
        YLOG_DEBUG("LCP: Received Echo-Request");
        /* Send Echo-Reply */
        /* Data: [Magic(4)] + [Payload...] */
        /* Reply must contain OUR Magic Number and SAME Payload */
        if (data_len >= 4) {
            uint8_t reply_data[1500];
            memcpy(reply_data, data, data_len);
            /* Overwrite Magic Number with ours */
            *(uint32_t *)reply_data = rte_cpu_to_be_32(session->magic_number);
            ppp_lcp_send(session, LCP_CODE_ECHO_REPLY, lcp->identifier, reply_data, data_len);
        }
        break;

    case LCP_CODE_ECHO_REPLY:
        YLOG_DEBUG("LCP: Received Echo-Reply");
        /* Reset Echo Failures */
        session->echo_failures = 0;
        session->last_echo_ts = time(NULL);
        break;

    case LCP_CODE_TERM_REQ:
        YLOG_INFO("LCP: Received Terminate-Request");
        /* Send Terminate-Ack */
        ppp_lcp_send(session, LCP_CODE_TERM_ACK, lcp->identifier, NULL, 0);
        /* Terminate Session */
        pppoe_terminate_session(session, "Peer Terminated");
        break;

    case LCP_CODE_TERM_ACK:
        YLOG_INFO("LCP: Received Terminate-Ack");
        session->lcp_state = LCP_STATE_CLOSED;
        break;

    case LCP_CODE_CODE_REJ:
    case LCP_CODE_PROTO_REJ:
        YLOG_WARNING("LCP: Received Rej (Code/Proto)");
        break;

    case LCP_CODE_DISC_REQ:
        YLOG_DEBUG("LCP: Received Discard-Request");
        break;

    default:
        YLOG_WARNING("LCP: Unknown code %d", lcp->code);
        /* Send Code-Reject */
        /* Payload: LCP Packet that was rejected */
        /* Truncate if necessary to fit MTU */
        ppp_lcp_send(session, LCP_CODE_CODE_REJ, ++session->next_lcp_identifier,
                     (const uint8_t *)lcp, lcp_len);
        break;
    }

    return 0;
}

void ppp_lcp_check_timeouts(struct pppoe_session *session)
{
    /* Retransmit Configure-Request in REQ_SENT, ACK_RCVD, and ACK_SENT states
     * We must keep trying until we receive their Config-Ack
     */
    if (session->lcp_state == LCP_STATE_REQ_SENT || session->lcp_state == LCP_STATE_ACK_RCVD ||
        session->lcp_state == LCP_STATE_ACK_SENT) {
        uint64_t now = time(NULL);
        if (now - session->last_conf_req_ts >= 3) {
            if (session->conf_req_retries >= 10) {
                pppoe_terminate_session(session, "LCP Negotiation Timeout");
            } else {
                session->conf_req_retries++;
                YLOG_INFO("LCP: Retransmitting Configure-Request (Attempt %u, state=%u)",
                          session->conf_req_retries, session->lcp_state);
                ppp_lcp_send_conf_req(session);
            }
        }
    }
}
