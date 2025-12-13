/**
 * @file ppp_ipcp.c
 * @brief PPP IP Control Protocol (IPCP) Implementation - FIXED VERSION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <arpa/inet.h>

#include "ppp_ipcp.h"
#include "ppp_lcp.h"
#include "pppoe.h"
#include "pppoe_defs.h"
#include "packet.h"
#include "interface.h"
#include "log.h"
#include "ippool.h"

/* DNS Options (RFC 1877) */
#define IPCP_OPT_DNS1 129
#define IPCP_OPT_DNS2 131

/* Default DNS (Google DNS) - in HOST ORDER */
#define DEFAULT_DNS1 0x08080808 /* 8.8.8.8 */
#define DEFAULT_DNS2 0x08080404 /* 8.8.4.4 */

/* IPCP States */
#define IPCP_STATE_INITIAL    0
#define IPCP_STATE_REQ_SENT   1
#define IPCP_STATE_ACK_RCVD   2
#define IPCP_STATE_ACK_SENT   3
#define IPCP_STATE_OPENED     4

/* Helper to send IPCP packet - with VLAN support */
static int ppp_ipcp_send(struct pppoe_session *session, uint8_t code, uint8_t identifier, const uint8_t *data, uint16_t len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe;
    uint16_t *proto;
    struct lcp_hdr *ipcp;
    uint8_t *payload;
    uint16_t hdr_len;

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);

    /* Add VLAN tag if session has one */
    if (session->vlan_id > 0) {
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
        struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
        vlan->vlan_tci = rte_cpu_to_be_16(session->vlan_id);
        vlan->eth_proto = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);
        pppoe = (struct pppoe_hdr *)(vlan + 1);
        hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr);
    } else {
        eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);
        pppoe = (struct pppoe_hdr *)(eth + 1);
        hdr_len = sizeof(struct rte_ether_hdr);
    }

    proto = (uint16_t *)(pppoe + 1);
    ipcp = (struct lcp_hdr *)(proto + 1);
    payload = ipcp->data;

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

    m->data_len = hdr_len + sizeof(struct pppoe_hdr) + ppp_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    int ret = interface_send(session->iface, pkt);
    if (ret != 0) {
        pkt_free(pkt);
    }
    return ret;
}

/* Send Configure-Request - Server sends empty request (no options) or just gateway IP */
static void ppp_ipcp_send_conf_req(struct pppoe_session *session)
{
    /* Server typically doesn't request IP - just send empty Configure-Request */
    /* Or send our gateway IP if we want client to know it */
    uint8_t options[16];
    uint16_t len = 0;

    /* Option: Our (gateway) IP Address - client uses this as default gateway */
    struct lcp_opt_hdr *opt = (struct lcp_opt_hdr *)(options + len);
    opt->type = IPCP_OPT_IP_ADDR;
    opt->length = 6;
    /* server_ip stored in HOST order, convert to network */
    *(uint32_t *)(opt->data) = htonl(session->server_ip);
    len += opt->length;

    session->ipcp_state = IPCP_STATE_REQ_SENT;
    ppp_ipcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, options, len);
}

/* Send Configure-Ack */
static void ppp_ipcp_send_conf_ack(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_ipcp_send(session, LCP_CODE_CONF_ACK, identifier, options, len);

    /* Update state */
    if (session->ipcp_state == IPCP_STATE_ACK_RCVD) {
        session->ipcp_state = IPCP_STATE_OPENED;
        YLOG_INFO("IPCP: Session %u OPENED - IP %u.%u.%u.%u",
                  session->session_id,
                  (session->client_ip >> 24) & 0xFF,
                  (session->client_ip >> 16) & 0xFF,
                  (session->client_ip >> 8) & 0xFF,
                  session->client_ip & 0xFF);
    } else {
        session->ipcp_state = IPCP_STATE_ACK_SENT;
    }
}

/* Send Configure-Nak (Propose IP) */
static void ppp_ipcp_send_conf_nak(struct pppoe_session *session, uint8_t identifier, const uint8_t *options, uint16_t len)
{
    ppp_ipcp_send(session, LCP_CODE_CONF_NAK, identifier, options, len);
}

void ppp_ipcp_init(struct pppoe_session *session)
{
    YLOG_INFO("ppp_ipcp_init called for session %u", session->session_id);
    session->ipcp_state = IPCP_STATE_INITIAL;

    /* Get pool name from session or use default */
    const char *pool_name = (session->pool_name[0] != '\0') ? session->pool_name : "default";

    /* Assign IP from pool - returns HOST ORDER */
    uint32_t ip = ippool_alloc_ip(pool_name, session->client_mac.addr_bytes);
    if (ip == 0) {
        /* Try fallback to default pool */
        ip = ippool_alloc_ip("default", session->client_mac.addr_bytes);
    }

    if (ip == 0) {
        YLOG_ERROR("IPCP: Failed to allocate IP from pool '%s'", pool_name);
        session->client_ip = 0;
    } else {
        /* Store in HOST ORDER - convert to network order only when sending */
        session->client_ip = ip;
        YLOG_INFO("IPCP: Allocated IP %u.%u.%u.%u for session %u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                  (ip >> 8) & 0xFF, ip & 0xFF,
                  session->session_id);
    }

    /* Gateway IP in HOST order */
    session->server_ip = 0x64400001; /* 100.64.0.1 in host order */
}

void ppp_ipcp_open(struct pppoe_session *session)
{
    YLOG_DEBUG("IPCP: ppp_ipcp_open session=%u client_ip=0x%08x",
               session->session_id, session->client_ip);

    if (session->client_ip == 0) {
        YLOG_ERROR("IPCP: Cannot open - no IP allocated");
        return;
    }

    /* RFC 1661: Server waits for client Conf-Req first */
    session->ipcp_state = IPCP_STATE_INITIAL;
}

void ppp_ipcp_close(struct pppoe_session *session)
{
    ppp_ipcp_send(session, LCP_CODE_TERM_REQ, ++session->next_lcp_identifier, NULL, 0);
    session->ipcp_state = IPCP_STATE_INITIAL;
}

int ppp_ipcp_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len)
{
    const struct lcp_hdr *ipcp = (const struct lcp_hdr *)packet;
    if (len < sizeof(struct lcp_hdr)) return -1;

    uint16_t ipcp_len = rte_be_to_cpu_16(ipcp->length);
    if (ipcp_len > len) return -1;

    const uint8_t *data = ipcp->data;
    uint16_t data_len = ipcp_len - sizeof(struct lcp_hdr);

    YLOG_DEBUG("IPCP: RX code=%u id=%u len=%u state=%u",
                ipcp->code, ipcp->identifier, ipcp_len, session->ipcp_state);

    switch (ipcp->code) {
    case LCP_CODE_CONF_REQ: {
        YLOG_INFO("IPCP: Received Configure-Request");

        uint8_t ack_options[256];
        uint16_t ack_len = 0;
        uint8_t nak_options[256];
        uint16_t nak_len = 0;

        uint16_t offset = 0;

        while (offset < data_len) {
            const struct lcp_opt_hdr *opt = (const struct lcp_opt_hdr *)(data + offset);
            if (offset + 2 > data_len || opt->length < 2 || offset + opt->length > data_len) {
                break;
            }


            switch (opt->type) {
                case IPCP_OPT_IP_ADDR:
                    if (opt->length == 6) {
                        uint32_t req_ip = ntohl(*(const uint32_t *)opt->data);
                        YLOG_DEBUG("IPCP: Client requests IP %u.%u.%u.%u, we assign %u.%u.%u.%u",
                                   (req_ip >> 24) & 0xFF, (req_ip >> 16) & 0xFF,
                                   (req_ip >> 8) & 0xFF, req_ip & 0xFF,
                                   (session->client_ip >> 24) & 0xFF, (session->client_ip >> 16) & 0xFF,
                                   (session->client_ip >> 8) & 0xFF, session->client_ip & 0xFF);

                        if (req_ip == 0 || req_ip != session->client_ip) {
                            /* NAK with our assigned IP */
                            struct lcp_opt_hdr *nak_opt = (struct lcp_opt_hdr *)(nak_options + nak_len);
                            nak_opt->type = IPCP_OPT_IP_ADDR;
                            nak_opt->length = 6;
                            *(uint32_t *)nak_opt->data = htonl(session->client_ip);
                            nak_len += 6;
                        } else {
                            /* Client requested correct IP - ACK it */
                            memcpy(ack_options + ack_len, opt, opt->length);
                            ack_len += opt->length;
                        }
                    }
                    break;

                case IPCP_OPT_DNS1:
                    if (opt->length == 6) {
                        uint32_t req_dns = ntohl(*(const uint32_t *)opt->data);
                        if (req_dns == 0 || req_dns != DEFAULT_DNS1) {
                            struct lcp_opt_hdr *nak_opt = (struct lcp_opt_hdr *)(nak_options + nak_len);
                            nak_opt->type = IPCP_OPT_DNS1;
                            nak_opt->length = 6;
                            *(uint32_t *)nak_opt->data = htonl(DEFAULT_DNS1);
                            nak_len += 6;
                        } else {
                            memcpy(ack_options + ack_len, opt, opt->length);
                            ack_len += opt->length;
                        }
                    }
                    break;

                case IPCP_OPT_DNS2:
                    if (opt->length == 6) {
                        uint32_t req_dns = ntohl(*(const uint32_t *)opt->data);
                        if (req_dns == 0 || req_dns != DEFAULT_DNS2) {
                            struct lcp_opt_hdr *nak_opt = (struct lcp_opt_hdr *)(nak_options + nak_len);
                            nak_opt->type = IPCP_OPT_DNS2;
                            nak_opt->length = 6;
                            *(uint32_t *)nak_opt->data = htonl(DEFAULT_DNS2);
                            nak_len += 6;
                        } else {
                            memcpy(ack_options + ack_len, opt, opt->length);
                            ack_len += opt->length;
                        }
                    }
                    break;

                default:
                    /* Unknown option - just ACK it if client insists */
                    memcpy(ack_options + ack_len, opt, opt->length);
                    ack_len += opt->length;
                    break;
            }
            offset += opt->length;
        }

        if (nak_len > 0) {
            fprintf(stderr, "[IPCP] Sending NAK with %u bytes\n", nak_len);
            fflush(stderr);
            ppp_ipcp_send_conf_nak(session, ipcp->identifier, nak_options, nak_len);
        } else {
            fprintf(stderr, "[IPCP] Sending ACK with %u bytes\n", ack_len);
            fflush(stderr);
            ppp_ipcp_send_conf_ack(session, ipcp->identifier, ack_options, ack_len);

            /* RFC 1661: After ACKing client, NOW send our Configure-Request */
            if (session->ipcp_state == IPCP_STATE_INITIAL || session->ipcp_state == IPCP_STATE_ACK_SENT) {
                fprintf(stderr, "[IPCP] Now sending server Conf-Req\n");
                fflush(stderr);
                ppp_ipcp_send_conf_req(session);
            }
        }
        break;
    }

    case LCP_CODE_CONF_ACK:
        YLOG_INFO("IPCP: Received Configure-Ack");
        fprintf(stderr, "[IPCP] Received ACK - state=%u\n", session->ipcp_state);
        fflush(stderr);

        if (session->ipcp_state == IPCP_STATE_REQ_SENT) {
            session->ipcp_state = IPCP_STATE_ACK_RCVD;
        } else if (session->ipcp_state == IPCP_STATE_ACK_SENT) {
            session->ipcp_state = IPCP_STATE_OPENED;
            YLOG_INFO("IPCP: Session %u OPENED", session->session_id);
            fprintf(stderr, "[IPCP] SESSION %u FULLY ESTABLISHED\n", session->session_id);
            fflush(stderr);
        }
        break;

    case LCP_CODE_CONF_NAK:
        YLOG_INFO("IPCP: Received Configure-Nak");
        /* Peer didn't like our request - update and resend */
        /* For now just resend our request */
        /* RFC 1661: Server waits for client Conf-Req first */
    session->ipcp_state = IPCP_STATE_INITIAL;
        break;

    case LCP_CODE_CONF_REJ:
        YLOG_INFO("IPCP: Received Configure-Reject");
        /* Remove rejected options and resend */
        /* For server, we can send empty request */
        session->ipcp_state = IPCP_STATE_REQ_SENT;
        ppp_ipcp_send(session, LCP_CODE_CONF_REQ, ++session->next_lcp_identifier, NULL, 0);
        break;

    case LCP_CODE_TERM_REQ:
        YLOG_INFO("IPCP: Received Terminate-Request");
        ppp_ipcp_send(session, LCP_CODE_TERM_ACK, ipcp->identifier, NULL, 0);
        session->ipcp_state = IPCP_STATE_INITIAL;
        break;

    case LCP_CODE_TERM_ACK:
        YLOG_INFO("IPCP: Received Terminate-Ack");
        session->ipcp_state = IPCP_STATE_INITIAL;
        break;

    default:
        YLOG_WARNING("IPCP: Unknown code %d", ipcp->code);
        break;
    }

    return 0;
}
