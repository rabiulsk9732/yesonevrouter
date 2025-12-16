/**
 * @file ppp_auth.c
 * @brief PPP Authentication Protocols (PAP/CHAP) Implementation
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
#include "ppp_lcp.h" /* Reuse LCP header structs */
#include "pppoe.h"
#include "pppoe_defs.h"
#include "pppoe_tx.h"
#include "radius_lockless.h"

/* Helper to send Auth packet - with VLAN support */
/* Helper to send Auth packet - with VLAN support via pppoe_tx_send_session */
int ppp_auth_send(struct pppoe_session *session, uint16_t protocol, uint8_t code,
                  uint8_t identifier, const uint8_t *data, uint16_t len)
{
    /* Build PPPoE + PPP + Auth payload */
    uint8_t pppoe_buf[1500];
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)pppoe_buf;
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    struct lcp_hdr *auth = (struct lcp_hdr *)(proto + 1);

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
        memcpy(auth->data, data, len);
    }

    /* Lengths */
    uint16_t ppp_len = sizeof(uint16_t) + sizeof(struct lcp_hdr) + len;
    pppoe->length = rte_cpu_to_be_16(ppp_len);

    uint16_t payload_len = sizeof(struct pppoe_hdr) + ppp_len;

    /* Get port_id: For VLAN iface, get parent's DPDK port via parent_ifindex */
    struct interface *phys_iface = session->iface;
    if (session->iface->type == IF_TYPE_VLAN && session->iface->config.parent_ifindex > 0) {
        phys_iface = interface_find_by_index(session->iface->config.parent_ifindex);
    }
    uint16_t port_id = (uint16_t)(phys_iface->flags & 0x7FFFFFFF);
    uint16_t queue_id = 0;

    /* Use pppoe_tx_send_session for proper VLAN handling */
    return pppoe_tx_send_session(port_id, queue_id, &session->client_mac, session->iface->mac_addr,
                                 session->vlan_id, pppoe_buf, payload_len);
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
    if (len < sizeof(struct lcp_hdr))
        return -1;

    uint16_t pap_len = rte_be_to_cpu_16(pap->length);
    if (pap_len > len)
        return -1;

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

        YLOG_INFO("PAP: User='%s'", peer_id);

        /* Send to RADIUS via lockless DPDK interface */
        uint64_t req_id = radius_lockless_auth_pap(session->session_id, peer_id, passwd,
                                                   &session->client_mac, session->vlan_id,
                                                   session->iface ? session->iface->ifindex : 0);

        if (req_id > 0) {
            YLOG_INFO("PAP: Auth submitted to lockless RADIUS (req_id=%lu)", req_id);
        } else {
            YLOG_ERROR("PAP: Failed to submit auth request");
        }
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
    if (len < sizeof(struct lcp_hdr))
        return -1;

    uint16_t chap_len = rte_be_to_cpu_16(chap->length);
    if (chap_len > len)
        return -1;

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

        /* Send to RADIUS via lockless DPDK interface */
        extern uint64_t radius_lockless_auth_chap(
            uint16_t session_id, const char *username, uint8_t chap_id,
            const uint8_t *chap_challenge, uint8_t chap_challenge_len, const uint8_t *chap_response,
            uint8_t chap_response_len, const struct rte_ether_addr *client_mac, uint16_t vlan_id,
            uint32_t ifindex);

        uint64_t req_id = radius_lockless_auth_chap(
            session->session_id, name, chap->identifier, session->chap_challenge,
            session->chap_challenge_len, chap_password, 1 + val_size, &session->client_mac,
            session->vlan_id, session->iface ? session->iface->ifindex : 0);

        if (req_id > 0) {
            YLOG_INFO("CHAP: Auth submitted to lockless RADIUS (req_id=%lu)", req_id);
        } else {
            YLOG_ERROR("CHAP: Failed to submit auth request");
        }
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
 *
 * RFC 1661 Correct Flow:
 * 1. LCP opens (link established)
 * 2. NAS (us) initiates CHAP by sending Challenge
 * 3. Client responds with CHAP Response
 * 4. NAS verifies credentials via RADIUS
 *
 * Since LCP doesn't negotiate Auth-Protocol, we always use CHAP.
 */
void ppp_auth_start(struct pppoe_session *session)
{
    YLOG_INFO("PPP Auth: Starting authentication after LCP OPENED");
    fprintf(stderr, "[AUTH DEBUG] ppp_auth_start: Sending CHAP Challenge (NAS-initiated)\n");
    fflush(stderr);

    /* NAS always initiates CHAP after LCP opens
     * This is the correct PPP/RADIUS flow for vBNG
     */
    session->auth_protocol = PPP_PROTO_CHAP;
    YLOG_INFO("PPP Auth: Sending CHAP-MD5 Challenge");
    ppp_chap_send_challenge(session);
}
