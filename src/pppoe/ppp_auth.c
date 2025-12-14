/**
 * @file ppp_auth.c
 * @brief PPP Authentication Protocols (PAP/CHAP) Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "ppp_auth.h"
#include "radius.h"
#include "ppp_lcp.h" /* Reuse LCP header structs */
#include "pppoe.h"
#include "pppoe_defs.h"
#include "packet.h"
#include "interface.h"
#include "log.h"

/* Helper to send Auth packet - with VLAN support */
int ppp_auth_send(struct pppoe_session *session, uint16_t protocol, uint8_t code, uint8_t identifier, const uint8_t *data, uint16_t len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe;
    uint16_t *proto;
    struct lcp_hdr *auth;
    uint8_t *payload;
    uint16_t hdr_len;

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);

    /* PPPoE Session - VLAN tagging handled by VLAN interface */
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);
    pppoe = (struct pppoe_hdr *)(eth + 1);
    hdr_len = sizeof(struct rte_ether_hdr);

    proto = (uint16_t *)(pppoe + 1);
    auth = (struct lcp_hdr *)(proto + 1);
    payload = auth->data;

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_SESS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* PPP Protocol */
    *proto = rte_cpu_to_be_16(protocol);

    /* Auth Header */
    auth->code = code;
    auth->identifier = identifier;
    auth->length = rte_cpu_to_be_16(sizeof(struct lcp_hdr) + len);

    /* Auth Data */
    if (data && len > 0) {
        memcpy(payload, data, len);
    }

    /* Lengths */
    uint16_t ppp_len = sizeof(uint16_t) + sizeof(struct lcp_hdr) + len;
    pppoe->length = rte_cpu_to_be_16(ppp_len);

    m->data_len = hdr_len + sizeof(struct pppoe_hdr) + ppp_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    /* Send */
    int ret = interface_send(session->iface, pkt);
    if (ret != 0) {
        pkt_free(pkt);
    }
    return ret;
}

void ppp_auth_init(struct pppoe_session *session)
{
    /* Initialize auth state if needed */
    (void)session;
}

/* --- PAP Implementation --- */

int ppp_pap_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len)
{
    const struct lcp_hdr *pap = (const struct lcp_hdr *)packet;
    if (len < sizeof(struct lcp_hdr)) return -1;

    uint16_t pap_len = rte_be_to_cpu_16(pap->length);
    if (pap_len > len) return -1;

    const uint8_t *data = pap->data;
    /* uint16_t data_len = pap_len - sizeof(struct lcp_hdr); */

    switch (pap->code) {
    case PAP_CODE_AUTH_REQ:
        YLOG_INFO("PAP: Received Authenticate-Request");

        /* Parse Peer-ID and Password */
        uint8_t peer_id_len = data[0];
        char peer_id[256];
        memcpy(peer_id, data + 1, peer_id_len);
        peer_id[peer_id_len] = '\0';
        snprintf(session->username, sizeof(session->username), "%.63s", peer_id);

        uint8_t passwd_len = data[1 + peer_id_len];
        char passwd[256];
        memcpy(passwd, data + 1 + peer_id_len + 1, passwd_len);
        passwd[passwd_len] = '\0';

        YLOG_INFO("PAP: User='%s' Password='%s'", peer_id, passwd);

        YLOG_INFO("PAP: User='%s' Password='%s'", peer_id, passwd);

        /* Send to RADIUS */
        radius_auth_request(peer_id, passwd, session->session_id, session->client_mac.addr_bytes);

        /* Wait for RADIUS response (Async) */
        YLOG_INFO("PAP: Waiting for RADIUS response...");
        break;

    default:
        YLOG_WARNING("PAP: Unknown code %d", pap->code);
        break;
    }

    return 0;
}

/* --- CHAP Implementation --- */

void ppp_chap_send_challenge(struct pppoe_session *session)
{
    uint8_t data[256];
    uint8_t val_size = 16; /* Challenge size */

    /* Value Size */
    data[0] = val_size;

    /* Challenge Value (Random) */
    for (int i = 0; i < val_size; i++) {
        data[1 + i] = rand() % 256;
    }

    /* Store challenge for verification */
    memcpy(session->chap_challenge, data + 1, val_size);
    session->chap_challenge_len = val_size;

    /* Name (System Name) */
    const char *name = "yesrouter";
    memcpy(data + 1 + val_size, name, strlen(name));

    ppp_auth_send(session, PPP_PROTO_CHAP, CHAP_CODE_CHALLENGE, ++session->next_lcp_identifier,
                 data, 1 + val_size + strlen(name));
}

int ppp_chap_process_packet(struct pppoe_session *session, const uint8_t *packet, uint16_t len)
{
    const struct lcp_hdr *chap = (const struct lcp_hdr *)packet;
    if (len < sizeof(struct lcp_hdr)) return -1;

    uint16_t chap_len = rte_be_to_cpu_16(chap->length);
    if (chap_len > len) return -1;

    /* const uint8_t *data = chap->data; */

    switch (chap->code) {
    case CHAP_CODE_RESPONSE:
        YLOG_INFO("CHAP: Received Response");

        /* Parse Response */
        /* Data: [Value-Size] [Value] [Name] */
        const uint8_t *data = chap->data;
        uint8_t val_size = data[0];

        /* CHAP Password = Identifier + Value */
        uint8_t chap_password[256];
        chap_password[0] = chap->identifier;
        memcpy(chap_password + 1, data + 1, val_size);

        /* Name */
        char name[256];
        uint16_t name_len = chap_len - sizeof(struct lcp_hdr) - 1 - val_size;
        memcpy(name, data + 1 + val_size, name_len);
        name[name_len] = '\0';
        snprintf(session->username, sizeof(session->username), "%.63s", name);

        YLOG_INFO("CHAP: User='%s'", name);

        /* Send to RADIUS */
        radius_chap_auth_request(name, session->chap_challenge, session->chap_challenge_len,
                                chap_password, 1 + val_size,
                                session->session_id, session->client_mac.addr_bytes);

        /* Wait for RADIUS response (Async) */
        YLOG_INFO("CHAP: Waiting for RADIUS response...");
        break;

    case CHAP_CODE_SUCCESS:
        YLOG_INFO("CHAP: Received Success");
        break;

    case CHAP_CODE_FAILURE:
        YLOG_INFO("CHAP: Received Failure");
        break;

    default:
        YLOG_WARNING("CHAP: Unknown code %d", chap->code);
        break;
    }

    return 0;
}

/* --- ppp_auth_start Implementation --- */
/**
 * Start PPP authentication after LCP opens
 * For CHAP: Server sends challenge
 * For PAP: Server waits for client Auth-Request
 */
void ppp_auth_start(struct pppoe_session *session)
{
    YLOG_INFO("PPP Auth: Starting authentication (protocol=0x%04x)", session->auth_protocol); fprintf(stderr, "[AUTH DEBUG] ppp_auth_start: auth_protocol=0x%04x (PAP=0xC023 CHAP=0xC223)\n", session->auth_protocol); fflush(stderr);

    if (session->auth_protocol == PPP_PROTO_CHAP) {
        /* CHAP: Server initiates by sending challenge */
        YLOG_INFO("PPP Auth: Sending CHAP challenge");
        ppp_chap_send_challenge(session);
    } else if (session->auth_protocol == PPP_PROTO_PAP) {
        /* PAP: Client initiates - server waits for Auth-Request */
        YLOG_INFO("PPP Auth: Waiting for PAP Auth-Request from client");
        /* No action needed - ppp_pap_process_packet handles incoming PAP */
    } else {
        /* No auth negotiated - skip to IPCP (shouldn't happen in production) */
        YLOG_WARNING("PPP Auth: No auth protocol negotiated, skipping to IPCP");
        extern void ppp_ipcp_open(struct pppoe_session *session);
        ppp_ipcp_open(session);
    }
}
