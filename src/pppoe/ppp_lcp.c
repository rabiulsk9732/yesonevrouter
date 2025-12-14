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
#include "ppp_lcp.h"
#include "pppoe.h"
#include "pppoe_defs.h"
#include <time.h>

/* Helper to send LCP packet */
static int ppp_lcp_send(struct pppoe_session *session, uint8_t code, uint8_t identifier,
                        const uint8_t *data, uint16_t len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt)
        return -1;

    YLOG_INFO("LCP SEND: session=%u vlan_id=%u iface=%s", session->session_id, session->vlan_id,
              session->iface->name);

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe;
    uint16_t *proto;
    struct lcp_hdr *lcp;
    uint8_t *payload;
    uint16_t hdr_len;

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);

    /* PPPoE Session ethertype - VLAN tagging handled by VLAN interface if session->iface is a VLAN
     * sub-interface */
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);
    pppoe = (struct pppoe_hdr *)(eth + 1);
    hdr_len = sizeof(struct rte_ether_hdr);

    proto = (uint16_t *)(pppoe + 1);
    lcp = (struct lcp_hdr *)(proto + 1);
    payload = lcp->data;

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
        memcpy(payload, data, len);
    }

    /* Lengths */
    uint16_t ppp_len = sizeof(uint16_t) + sizeof(struct lcp_hdr) + len;
    pppoe->length = rte_cpu_to_be_16(ppp_len);

    m->data_len = hdr_len + sizeof(struct pppoe_hdr) + ppp_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    /* Send via HQoS (hqos_run called immediately after enqueue) */
    int ret = interface_send(session->iface, pkt);
    if (ret != 0) {
        pkt_free(pkt);
    }
    return ret;
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

    /* Option: Auth Protocol (CHAP with MD5) */
    opt = (struct lcp_opt_hdr *)(options + len);
    opt->type = LCP_OPT_AUTH_PROTO;
    opt->length = 5; /* Type(1) + Len(1) + Proto(2) + Algo(1) */
    *(uint16_t *)(opt->data) = rte_cpu_to_be_16(PPP_PROTO_CHAP);
    session->auth_protocol = PPP_PROTO_CHAP;
    opt->data[2] = 0x05; /* MD5 */
    len += opt->length;

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

/* Send Configure-Ack */
static void ppp_lcp_send_conf_ack(struct pppoe_session *session, uint8_t identifier,
                                  const uint8_t *options, uint16_t len)
{
    ppp_lcp_send(session, LCP_CODE_CONF_ACK, identifier, options, len);

    /* RFC 1661 State Machine: Update state after sending Conf-Ack */
    if (session->lcp_state == LCP_STATE_ACK_RCVD) {
        /* We already received their Ack, now we sent ours -> OPENED */
        session->lcp_state = LCP_STATE_OPENED;
        YLOG_INFO("LCP Session %u Opened", session->session_id);
        ppp_auth_start(session); /* Start authentication ONCE here */
    } else {
        /* We sent Ack but haven't received theirs yet */
        session->lcp_state = LCP_STATE_ACK_SENT;
    }
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

    YLOG_DEBUG("LCP: code=%u state=%d", lcp->code, session->lcp_state);
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
                /* Server does not authenticate to Client */
                memcpy(rej_options + rej_len, opt, opt->length);
                rej_len += opt->length;
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

        /* Decision Logic */
        if (rej_len > 0) {
            YLOG_INFO("LCP: Sending Config-Reject (len=%u)", rej_len);
            ppp_lcp_send_conf_rej(session, lcp->identifier, rej_options, rej_len);
        } else if (nak_len > 0) {
            YLOG_INFO("LCP: Sending Config-Nak (len=%u)", nak_len);
            ppp_lcp_send_conf_nak(session, lcp->identifier, nak_options, nak_len);
        } else {
            /* All options acceptable */
            YLOG_INFO("LCP: Sending Config-Ack (len=%u)", ack_len);

            /* CRITICAL: Save state BEFORE ppp_lcp_send_conf_ack changes it */
            int saved_state = session->lcp_state;

            ppp_lcp_send_conf_ack(session, lcp->identifier, ack_options, ack_len);

            /* RFC 1661 State Machine: Send our own ConfReq if we haven't completed negotiation */
            /* Use saved_state since ppp_lcp_send_conf_ack changes session->lcp_state */
            if (saved_state == LCP_STATE_INITIAL || saved_state == LCP_STATE_STARTING ||
                saved_state == LCP_STATE_REQ_SENT) {
                /* We need to send our own Conf-Req too (or resend if lost) */
                ppp_lcp_send_conf_req(session);
            }
        }
        break;
    }

    case LCP_CODE_CONF_ACK:
        YLOG_INFO("LCP: Received Configure-Ack");
        if (session->lcp_state == LCP_STATE_REQ_SENT) {
            /* We sent Req, received Ack - waiting for their Req */
            session->lcp_state = LCP_STATE_ACK_RCVD;
        } else if (session->lcp_state == LCP_STATE_ACK_SENT) {
            /* We already sent Ack (to their Req), now received Ack -> OPENED */
            session->lcp_state = LCP_STATE_OPENED;
            YLOG_INFO("LCP Session %u Opened", session->session_id);
            ppp_auth_start(session); /* Start authentication ONCE here */
        }
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
    if (session->lcp_state == LCP_STATE_REQ_SENT || session->lcp_state == LCP_STATE_ACK_RCVD) {
        uint64_t now = time(NULL);
        if (now - session->last_conf_req_ts >= 3) {
            if (session->conf_req_retries >= 10) {
                pppoe_terminate_session(session, "LCP Negotiation Timeout");
            } else {
                session->conf_req_retries++;
                YLOG_INFO("LCP: Retransmitting Configure-Request (Attempt %u)",
                          session->conf_req_retries);
                ppp_lcp_send_conf_req(session);
            }
        }
    }
}
