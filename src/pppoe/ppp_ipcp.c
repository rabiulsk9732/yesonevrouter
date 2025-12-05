/**
 * @file ppp_ipcp.c
 * @brief PPP IP Control Protocol (IPCP) Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <arpa/inet.h>

#include "ppp_ipcp.h"
#include "ppp_lcp.h" /* Reuse LCP header structs */
#include "pppoe.h"
#include "pppoe_defs.h"
#include "packet.h"
#include "interface.h"
#include "interface.h"
#include "log.h"
#include "ippool.h"

/* Helper to send IPCP packet */
static int ppp_ipcp_send(struct pppoe_session *session, uint8_t code, uint8_t identifier, const uint8_t *data, uint16_t len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    struct lcp_hdr *ipcp = (struct lcp_hdr *)(proto + 1);
    uint8_t *payload = ipcp->data;

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
    *proto = rte_cpu_to_be_16(PPP_PROTO_IPCP);

    /* IPCP Header */
    ipcp->code = code;
    ipcp->identifier = identifier;
    ipcp->length = rte_cpu_to_be_16(sizeof(struct lcp_hdr) + len);

    /* IPCP Data */
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
static void ppp_ipcp_send_conf_req(struct pppoe_session *session)
{
    uint8_t options[64];
    uint16_t len = 0;

    /* Option: IP Address */
    struct lcp_opt_hdr *opt = (struct lcp_opt_hdr *)(options + len);
    opt->type = IPCP_OPT_IP_ADDR;
    opt->length = 6;
    *(uint32_t *)(opt->data) = rte_cpu_to_be_32(session->server_ip);
    len += opt->length;

    ppp_ipcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
}

/* Send Configure-Ack */
static void ppp_ipcp_send_conf_ack(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_ipcp_send(session, LCP_CODE_CONF_ACK, identifier, options, len);
}

/* Send Configure-Nak (Propose IP) */
static void ppp_ipcp_send_conf_nak(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_ipcp_send(session, LCP_CODE_CONF_NAK, identifier, options, len);
}

/* Send Configure-Reject */
static void ppp_ipcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len) __attribute__((unused));
static void ppp_ipcp_send_conf_rej(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_ipcp_send(session, LCP_CODE_CONF_REJ, identifier, options, len);
}

void ppp_ipcp_init(struct pppoe_session *session)
{
    /* Assign IP from pool */
    uint32_t ip = ippool_alloc_ip("default", session->client_mac.addr_bytes);
    if (ip == 0) {
        YLOG_ERROR("IPCP: Failed to allocate IP from 'default' pool");
        /* Fallback or error handling needed */
        session->client_ip = 0;
    } else {
        session->client_ip = htonl(ip); /* Convert to network order for storage? No, struct uses network order usually.
                                           ippool returns host order.
                                           Let's check usage.
                                           rte_cpu_to_be_32(session->client_ip) is used in code.
                                           So session->client_ip should be in HOST order?
                                           Wait, previous code: session->client_ip = inet_addr("100.64.0.2");
                                           inet_addr returns Network Order.
                                           So session->client_ip stores Network Order.
                                           ippool_alloc_ip returns Host Order.
                                           So we need htonl(ip).
                                         */
    }

    session->server_ip = inet_addr("100.64.0.1"); /* Dummy Gateway */
}

void ppp_ipcp_open(struct pppoe_session *session)
{
    ppp_ipcp_send_conf_req(session);
}

void ppp_ipcp_close(struct pppoe_session *session)
{
    ppp_ipcp_send(session, LCP_CODE_TERM_REQ, ++session->next_lcp_identifier, NULL, 0);
}

int ppp_ipcp_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len)
{
    const struct lcp_hdr *ipcp = (const struct lcp_hdr *)packet;
    if (len < sizeof(struct lcp_hdr)) return -1;

    uint16_t ipcp_len = rte_be_to_cpu_16(ipcp->length);
    if (ipcp_len > len) return -1;

    const uint8_t *data = ipcp->data;
    uint16_t data_len = ipcp_len - sizeof(struct lcp_hdr);

    switch (ipcp->code) {
    case LCP_CODE_CONF_REQ:
        YLOG_INFO("IPCP: Received Configure-Request");

        /* Parse options */
        uint16_t offset = 0;
        bool nak_needed = false;
        uint8_t nak_options[64];
        uint16_t nak_len = 0;

        while (offset < data_len) {
            const struct lcp_opt_hdr *opt = (const struct lcp_opt_hdr *)(data + offset);
            if (opt->length < 2) break;

            if (opt->type == IPCP_OPT_IP_ADDR) {
                uint32_t requested_ip = *(const uint32_t *)opt->data;
                if (requested_ip != rte_cpu_to_be_32(session->client_ip)) {
                    /* NAK with correct IP */
                    nak_needed = true;
                    struct lcp_opt_hdr *nak_opt = (struct lcp_opt_hdr *)(nak_options + nak_len);
                    nak_opt->type = IPCP_OPT_IP_ADDR;
                    nak_opt->length = 6;
                    *(uint32_t *)(nak_opt->data) = rte_cpu_to_be_32(session->client_ip);
                    nak_len += nak_opt->length;
                }
            }
            offset += opt->length;
        }

        if (nak_needed) {
            ppp_ipcp_send_conf_nak(session, ipcp->identifier, nak_options, nak_len);
        } else {
            ppp_ipcp_send_conf_ack(session, ipcp->identifier, data, data_len);
            ppp_ipcp_send_conf_req(session); /* Send our request if not sent/acked */
        }
        break;

    case LCP_CODE_CONF_ACK:
        YLOG_INFO("IPCP: Received Configure-Ack");
        YLOG_INFO("IPCP Session Established: Client IP %u.%u.%u.%u",
                  (rte_be_to_cpu_32(session->client_ip) >> 24) & 0xFF,
                  (rte_be_to_cpu_32(session->client_ip) >> 16) & 0xFF,
                  (rte_be_to_cpu_32(session->client_ip) >> 8) & 0xFF,
                  rte_be_to_cpu_32(session->client_ip) & 0xFF);
        break;

    case LCP_CODE_CONF_NAK:
        YLOG_INFO("IPCP: Received Configure-Nak");
        /* TODO: Handle NAK */
        break;

    case LCP_CODE_CONF_REJ:
        YLOG_INFO("IPCP: Received Configure-Reject");
        break;

    case LCP_CODE_TERM_REQ:
        YLOG_INFO("IPCP: Received Terminate-Request");
        ppp_ipcp_send(session, LCP_CODE_TERM_ACK, ipcp->identifier, NULL, 0);
        break;

    case LCP_CODE_TERM_ACK:
        YLOG_INFO("IPCP: Received Terminate-Ack");
        break;

    default:
        YLOG_WARNING("IPCP: Unknown code %d", ipcp->code);
        /* Send Code-Reject */
        break;
    }

    return 0;
}
