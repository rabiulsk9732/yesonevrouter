/**
 * @file ppp_lcp.c
 * @brief PPP Link Control Protocol (LCP) Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "ppp_lcp.h"
#include "pppoe.h"
#include "pppoe_defs.h"
#include "packet.h"
#include "interface.h"
#include "log.h"
#include <time.h>

/* Helper to send LCP packet */
static int ppp_lcp_send(struct pppoe_session *session, uint8_t code, uint8_t identifier, const uint8_t *data, uint16_t len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    struct lcp_hdr *lcp = (struct lcp_hdr *)(proto + 1);
    uint8_t *payload = lcp->data;

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);

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

    m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + ppp_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    /* Send */
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
    opt->data[2] = 0x05; /* MD5 */
    len += opt->length;

    ppp_lcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
    session->lcp_state = LCP_STATE_REQ_SENT;
}

/* Send Configure-Ack */
static void ppp_lcp_send_conf_ack(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_lcp_send(session, LCP_CODE_CONF_ACK, identifier, options, len);
    if (session->lcp_state == LCP_STATE_ACK_RCVD) {
        session->lcp_state = LCP_STATE_OPENED;
        YLOG_INFO("LCP Session %u Opened", session->session_id);
    } else {
        session->lcp_state = LCP_STATE_ACK_SENT;
    }
}

/* Send Configure-Reject */
static void ppp_lcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len) __attribute__((unused));
static void ppp_lcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_lcp_send(session, LCP_CODE_CONF_REJ, identifier, options, len);
}

/* Send Terminate-Ack */
static void ppp_lcp_send_term_ack(struct pppoe_session *session, uint8_t identifier)
{
    ppp_lcp_send(session, LCP_CODE_TERM_ACK, identifier, NULL, 0);
}

/* Send Echo-Reply */
static void ppp_lcp_send_echo_reply(struct pppoe_session *session, uint8_t identifier, const uint8_t *data, uint16_t len)
{
    uint8_t reply_data[64];
    *(uint32_t *)reply_data = rte_cpu_to_be_32(session->magic_number);
    if (len > 4) {
        memcpy(reply_data + 4, data + 4, len - 4);
    }
    ppp_lcp_send(session, LCP_CODE_ECHO_REPLY, identifier, reply_data, len);
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
    if (len < sizeof(struct lcp_hdr)) return -1;

    uint16_t lcp_len = rte_be_to_cpu_16(lcp->length);
    if (lcp_len > len) return -1;

    const uint8_t *data = lcp->data;
    uint16_t data_len = lcp_len - sizeof(struct lcp_hdr);

    switch (lcp->code) {
    case LCP_CODE_CONF_REQ:
        YLOG_INFO("LCP: Received Configure-Request");
        /* For now, just ACK everything (naive implementation) */
        /* TODO: Parse options and NAK/REJ if needed */
        ppp_lcp_send_conf_ack(session, lcp->identifier, data, data_len);

        if (session->lcp_state == LCP_STATE_INITIAL || session->lcp_state == LCP_STATE_STARTING) {
            ppp_lcp_send_conf_req(session);
        }
        break;

    case LCP_CODE_CONF_ACK:
        YLOG_INFO("LCP: Received Configure-Ack");
        if (session->lcp_state == LCP_STATE_REQ_SENT) {
            session->lcp_state = LCP_STATE_ACK_RCVD;
        } else if (session->lcp_state == LCP_STATE_ACK_SENT) {
            session->lcp_state = LCP_STATE_OPENED;
            YLOG_INFO("LCP Session %u Opened", session->session_id);
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
            len += opt->length;

            ppp_lcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
        }
        break;

    case LCP_CODE_CONF_REJ:
        YLOG_INFO("LCP: Received Configure-Reject");
        /* TODO: Handle REJ (remove options and resend REQ) */
        break;

    case LCP_CODE_TERM_REQ:
        YLOG_INFO("LCP: Received Terminate-Request");
        ppp_lcp_send_term_ack(session, lcp->identifier);
        session->lcp_state = LCP_STATE_CLOSED;
        break;

    case LCP_CODE_TERM_ACK:
        YLOG_INFO("LCP: Received Terminate-Ack");
        session->lcp_state = LCP_STATE_CLOSED;
        break;

    case LCP_CODE_ECHO_REQ:
        YLOG_INFO("LCP: Received Echo-Request");
        ppp_lcp_send_echo_reply(session, lcp->identifier, data, data_len);
        break;

    case LCP_CODE_ECHO_REPLY:
        YLOG_DEBUG("LCP: Received Echo-Reply");
        session->echo_failures = 0;
        session->last_activity_ts = time(NULL);
        break;

    default:
        YLOG_WARNING("LCP: Unknown code %d", lcp->code);
        /* Send Code-Reject */
        break;
    }

    return 0;
}
