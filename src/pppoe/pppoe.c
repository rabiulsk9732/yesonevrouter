/**
 * @file pppoe.c
 * @brief PPPoE Server Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#include "pppoe.h"
#include "ppp_lcp.h"
#include "ppp_ipcp.h"
#include "ppp_auth.h"
#include "packet.h"
#include "packet_rx.h"
#include "interface.h"
#include "log.h"
#include "dpdk_init.h"
#include "qos.h"
#include "qos.h"
#include "radius.h"
#include "ha.h"

/* Global PPPoE configuration/state */
static struct {
    struct pppoe_session *sessions; /* Linked list of sessions */
    uint16_t next_session_id;
    char service_name[32];
    char ac_name[32];
} g_pppoe_ctx;

/* Forward declarations */
static void pppoe_auth_callback(uint16_t session_id, bool success, uint32_t framed_ip, uint32_t session_timeout, uint32_t idle_timeout);

/**
 * Initialize PPPoE subsystem
 */
int pppoe_init(void)
{
    memset(&g_pppoe_ctx, 0, sizeof(g_pppoe_ctx));
    g_pppoe_ctx.next_session_id = 1;
    strncpy(g_pppoe_ctx.service_name, "yesrouter-pppoe", sizeof(g_pppoe_ctx.service_name) - 1);
    strncpy(g_pppoe_ctx.ac_name, "yesrouter", sizeof(g_pppoe_ctx.ac_name) - 1);

    strncpy(g_pppoe_ctx.service_name, "yesrouter-pppoe", sizeof(g_pppoe_ctx.service_name) - 1);
    strncpy(g_pppoe_ctx.ac_name, "yesrouter", sizeof(g_pppoe_ctx.ac_name) - 1);

    /* Register CoA callback */
    radius_set_coa_callback(pppoe_update_qos);

    /* Register Auth callback */
    radius_set_auth_callback(pppoe_auth_callback);

    YLOG_INFO("PPPoE subsystem initialized");
    return 0;
}

/**
 * Cleanup PPPoE subsystem
 */
void pppoe_cleanup(void)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    while (curr) {
        struct pppoe_session *next = curr->next;
        rte_free(curr);
        curr = next;
    }
    g_pppoe_ctx.sessions = NULL;
}

/**
 * Find session by ID and MAC
 */
static struct pppoe_session *pppoe_find_session(uint16_t session_id, const struct rte_ether_addr *mac);
static struct pppoe_session *pppoe_find_session(uint16_t session_id, const struct rte_ether_addr *mac)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    while (curr) {
        if (curr->session_id == session_id) {
            if (mac == NULL || rte_is_same_ether_addr(&curr->client_mac, mac)) {
                return curr;
            }
        }
        curr = curr->next;
    }
    return NULL;
}

struct pppoe_session *pppoe_find_session_by_ip(uint32_t ip)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    while (curr) {
        if (rte_be_to_cpu_32(curr->client_ip) == ip) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**
 * Create new session
 */
static struct pppoe_session *pppoe_create_session(const struct rte_ether_addr *mac, struct interface *iface)
{
    struct pppoe_session *session = rte_zmalloc("pppoe_session", sizeof(struct pppoe_session), 0);
    if (!session) {
        return NULL;
    }

    session->session_id = g_pppoe_ctx.next_session_id++;
    if (g_pppoe_ctx.next_session_id == 0) g_pppoe_ctx.next_session_id = 1;

    rte_ether_addr_copy(mac, &session->client_mac);
    session->iface = iface;
    session->state = PPPOE_STATE_INITIAL;
    session->state = PPPOE_STATE_INITIAL;
    session->created_ts = time(NULL);

    /* Initialize LCP */
    ppp_lcp_init(session);

    /* Initialize Auth */
    ppp_auth_init(session);

    /* Initialize IPCP */
    ppp_ipcp_init(session);

    session->acct_interim_interval = 600; /* Default 10 mins */

    /* Default QoS: 10 Mbps, 1MB burst */
    qos_tb_init(&session->downlink_tb, 10 * 1000 * 1000 / 8, 1024 * 1024);

    /* Add to list */
    session->next = g_pppoe_ctx.sessions;
    g_pppoe_ctx.sessions = session;

    /* HA Sync: Session Created */
    ha_send_sync(HA_MSG_SESSION_ADD, session->session_id, session->client_mac.addr_bytes, 0, session->state);

    return session;
}

/**
 * Send PADO (Offer) packet
 */
static int pppoe_send_pado(struct interface *iface, const struct rte_ether_addr *dst_mac, const uint8_t *host_uniq, uint16_t host_uniq_len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);
    uint8_t *payload = (uint8_t *)(pppoe + 1);
    uint16_t payload_len = 0;

    /* Ethernet Header */
    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)iface->mac_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADO;
    pppoe->session_id = 0;

    /* Add AC-Name Tag */
    struct pppoe_tag *tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_AC_NAME);
    tag->length = rte_cpu_to_be_16(strlen(g_pppoe_ctx.ac_name));
    memcpy(tag->value, g_pppoe_ctx.ac_name, strlen(g_pppoe_ctx.ac_name));
    payload += sizeof(struct pppoe_tag) + strlen(g_pppoe_ctx.ac_name);
    payload_len += sizeof(struct pppoe_tag) + strlen(g_pppoe_ctx.ac_name);

    /* Add Service-Name Tag (Empty for any service) */
    tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_SERVICE_NAME);
    tag->length = 0;
    payload += sizeof(struct pppoe_tag);
    payload_len += sizeof(struct pppoe_tag);

    /* Add Host-Uniq Tag if present in PADI */
    if (host_uniq && host_uniq_len > 0) {
        tag = (struct pppoe_tag *)payload;
        tag->type = rte_cpu_to_be_16(PPPOE_TAG_HOST_UNIQ);
        tag->length = rte_cpu_to_be_16(host_uniq_len);
        memcpy(tag->value, host_uniq, host_uniq_len);
        payload += sizeof(struct pppoe_tag) + host_uniq_len;
        payload_len += sizeof(struct pppoe_tag) + host_uniq_len;
    }

    pppoe->length = rte_cpu_to_be_16(payload_len);

    /* Set packet length */
    m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + payload_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    /* Send packet */
    int ret = interface_send(iface, pkt);
    if (ret != 0) {
        pkt_free(pkt);
    }
    return ret;
}

/**
 * Send PADS (Session Confirmation) packet
 */
static int pppoe_send_pads(struct pppoe_session *session, const uint8_t *host_uniq, uint16_t host_uniq_len)
{
    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);
    uint8_t *payload = (uint8_t *)(pppoe + 1);
    uint16_t payload_len = 0;

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* Add Service-Name Tag */
    struct pppoe_tag *tag = (struct pppoe_tag *)payload;
    tag->type = rte_cpu_to_be_16(PPPOE_TAG_SERVICE_NAME);
    tag->length = 0;
    payload += sizeof(struct pppoe_tag);
    payload_len += sizeof(struct pppoe_tag);

    /* Add Host-Uniq Tag if present */
    if (host_uniq && host_uniq_len > 0) {
        tag = (struct pppoe_tag *)payload;
        tag->type = rte_cpu_to_be_16(PPPOE_TAG_HOST_UNIQ);
        tag->length = rte_cpu_to_be_16(host_uniq_len);
        memcpy(tag->value, host_uniq, host_uniq_len);
        payload += sizeof(struct pppoe_tag) + host_uniq_len;
        payload_len += sizeof(struct pppoe_tag) + host_uniq_len;
    }

    pppoe->length = rte_cpu_to_be_16(payload_len);

    /* Set packet length */
    m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + payload_len;
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    /* Send packet */
    return interface_send(session->iface, pkt);
}

/**
 * Send PADT (Terminate Session) packet
 */
int pppoe_send_padt(struct pppoe_session *session)
{
    if (!session || !session->iface) return -1;

    struct pkt_buf *pkt = pkt_alloc();
    if (!pkt) return -1;

    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);

    /* Ethernet Header */
    rte_ether_addr_copy(&session->client_mac, &eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_DISC);

    /* PPPoE Header */
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_PADT;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);
    pppoe->length = 0;

    /* Set packet length */
    m->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr);
    m->pkt_len = m->data_len;
    pkt->len = m->data_len;

    YLOG_INFO("Sending PADT for session %u", session->session_id);

    /* Send packet */
    int ret = interface_send(session->iface, pkt);
    if (ret != 0) {
        pkt_free(pkt);
    }
    return ret;
}

int pppoe_send_session_packet(struct pppoe_session *session, struct pkt_buf *pkt)
{
    /* We need to prepend PPPoE and PPP headers */
    /* pkt->data currently points to IP header (or Ethernet header if forwarded?) */
    /* forward_ipv4_packet passes a packet with Ethernet header, but we need to replace it */

    struct rte_mbuf *m = pkt->mbuf;

    /* QoS: Downlink Shaping */
    if (!qos_tb_conform(&session->downlink_tb, m->pkt_len)) {
        /* Drop packet */
        /* YLOG_DEBUG("PPPoE: Session %u rate limited", session->session_id); */
        /* Caller (interface_send?) usually frees if we return error?
           No, interface_send frees on error usually, but here we are before that.
           Wait, if we return -1, who frees?
           The caller of pppoe_send_session_packet is usually the forwarding engine.
           If we return -1, the forwarding engine should handle it.
           But let's look at pppoe_send_session_packet signature.
           It takes pkt_buf.
        */
        return -1; /* Drop */
    }

    /* Calculate required headroom */
    uint16_t pppoe_len = sizeof(struct pppoe_hdr) + 2; /* PPPoE + PPP Proto */

    /* Check if we have enough headroom to just prepend PPPoE/PPP after Ethernet */
    /* But we need to update Ethernet header too */

    /* The packet passed from forward_ipv4_packet has Ethernet header at pkt->data */
    /* We can reuse the Ethernet header space and just expand */

    /* Move Ethernet header back to make room? No, we need to push data */

    /* Let's assume pkt->data points to Ethernet header */
    /* We need to insert PPPoE+PPP between Ethernet and IP */

    /* Current: [Eth][IP...] */
    /* Target:  [Eth][PPPoE][PPP][IP...] */

    /* We need to extend packet start by pppoe_len */
    if (rte_pktmbuf_prepend(m, pppoe_len) == NULL) {
        YLOG_ERROR("Not enough headroom for PPPoE encapsulation");
        return -1;
    }

    /* Now m->data_off is decreased by pppoe_len */
    /* Move Ethernet header to new start */
    struct rte_ether_hdr *new_eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Copy Ethernet header */
    /* Note: forward_ipv4_packet already set src/dst MACs, but for Ethernet forwarding */
    /* We need to fix them for PPPoE */
    rte_ether_addr_copy(&session->client_mac, &new_eth->dst_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)session->iface->mac_addr, &new_eth->src_addr);
    new_eth->ether_type = rte_cpu_to_be_16(ETH_P_PPPOE_SESS);

    /* Fill PPPoE Header */
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(new_eth + 1);
    pppoe->ver = 1;
    pppoe->type = 1;
    pppoe->code = PPPOE_CODE_SESS;
    pppoe->session_id = rte_cpu_to_be_16(session->session_id);

    /* IP packet length is total length - Eth - PPPoE - PPP */
    /* m->data_len includes everything now */
    uint16_t ip_len = m->data_len - sizeof(struct rte_ether_hdr) - sizeof(struct pppoe_hdr) - 2;
    pppoe->length = rte_cpu_to_be_16(ip_len + 2); /* +2 for PPP proto */

    /* Fill PPP Protocol */
    uint16_t *proto = (uint16_t *)(pppoe + 1);
    *proto = rte_cpu_to_be_16(PPP_PROTO_IP);

    /* Update pkt_buf */
    pkt->data = (uint8_t *)new_eth;
    pkt->len = m->data_len;

    /* Send */
    return interface_send(session->iface, pkt);
}

/**
 * Process PPPoE Discovery packet
 */
int pppoe_process_discovery(struct pkt_buf *pkt, struct interface *iface)
{
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);

    if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr)) {
        return -1;
    }

    if (pppoe->ver != 1 || pppoe->type != 1) {
        return -1;
    }

    /* Parse Tags to find Host-Uniq */
    uint8_t *payload = (uint8_t *)(pppoe + 1);
    uint16_t len = rte_be_to_cpu_16(pppoe->length);
    uint8_t *host_uniq = NULL;
    uint16_t host_uniq_len = 0;

    uint16_t offset = 0;
    while (offset < len) {
        struct pppoe_tag *tag = (struct pppoe_tag *)(payload + offset);
        uint16_t tag_type = rte_be_to_cpu_16(tag->type);
        uint16_t tag_len = rte_be_to_cpu_16(tag->length);

        if (tag_type == PPPOE_TAG_HOST_UNIQ) {
            host_uniq = tag->value;
            host_uniq_len = tag_len;
        }

        offset += sizeof(struct pppoe_tag) + tag_len;
    }

    switch (pppoe->code) {
    case PPPOE_CODE_PADI:
        {
            /* Global PADI Rate Limiter (e.g., 1000 PADI/sec) */
            static struct token_bucket global_padi_limiter = {0};
            static bool limiter_initialized = false;

            if (!limiter_initialized) {
                qos_tb_init(&global_padi_limiter, 1000, 100); /* 1000 pps, burst 100 */
                limiter_initialized = true;
            }

            if (!qos_tb_conform(&global_padi_limiter, 1)) {
                YLOG_WARNING("PPPoE: PADI flood detected, dropping packet");
                return 0;
            }

            YLOG_INFO("PPPoE: Received PADI from %02x:%02x:%02x:%02x:%02x:%02x",
                      eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                      eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                      eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);

            /* Send PADO */
            pppoe_send_pado(iface, &eth->src_addr, host_uniq, host_uniq_len);
        }
        break;

    case PPPOE_CODE_PADR:
        YLOG_INFO("PPPoE: Received PADR from %02x:%02x:%02x:%02x:%02x:%02x",
                  eth->src_addr.addr_bytes[0], eth->src_addr.addr_bytes[1],
                  eth->src_addr.addr_bytes[2], eth->src_addr.addr_bytes[3],
                  eth->src_addr.addr_bytes[4], eth->src_addr.addr_bytes[5]);

        /* Create Session */
        struct pppoe_session *session = pppoe_create_session(&eth->src_addr, iface);
        if (session) {
            session->state = PPPOE_STATE_SESSION_ESTABLISHED;
            YLOG_INFO("PPPoE: Session %u established", session->session_id);

            /* Send PADS */
            pppoe_send_pads(session, host_uniq, host_uniq_len);

            /* Start LCP Negotiation */
            ppp_lcp_open(session);
        }
        break;

    case PPPOE_CODE_PADT:
        YLOG_INFO("PPPoE: Received PADT");
        /* Terminate session */
        /* Find session by MAC */
        {
            struct pppoe_session *sess = pppoe_find_session(0, &eth->src_addr); /* ID 0 matches any? No, PADT has Session ID */
            /* PADT has Session ID in header */
            uint16_t sid = rte_be_to_cpu_16(pppoe->session_id);
            sess = pppoe_find_session(sid, &eth->src_addr);
            if (sess) {
                sess->state = PPPOE_STATE_TERMINATED;
                ha_send_sync(HA_MSG_SESSION_DEL, sess->session_id, sess->client_mac.addr_bytes, 0, sess->state);
            }
        }
        break;

    default:
        YLOG_WARNING("PPPoE: Unknown code 0x%02x", pppoe->code);
        break;
    }

    return 0;
}

/**
 * Process PPPoE Session packet
 */
int pppoe_process_session(struct pkt_buf *pkt, struct interface *iface)
{
    (void)iface;
    struct rte_mbuf *m = pkt->mbuf;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct pppoe_hdr *pppoe = (struct pppoe_hdr *)(eth + 1);
    uint16_t *proto_ptr = (uint16_t *)(pppoe + 1);
    uint16_t proto = rte_be_to_cpu_16(*proto_ptr);
    uint8_t *payload = (uint8_t *)(proto_ptr + 1);
    uint16_t len = rte_be_to_cpu_16(pppoe->length);

    if (m->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct pppoe_hdr) + 2) {
        return -1;
    }

    /* Find session */
    uint16_t session_id = rte_be_to_cpu_16(pppoe->session_id);
    struct pppoe_session *session = pppoe_find_session(session_id, &eth->src_addr);

    if (!session) {
        YLOG_WARNING("PPPoE: Unknown session ID %u", session_id);
        return -1;
    }

    /* Update activity timestamp */
    /* Update activity timestamp */
    session->last_activity_ts = time(NULL);

    /* Dispatch based on PPP Protocol */
    switch (proto) {
    case PPP_PROTO_LCP:
        return ppp_lcp_process_packet(session, payload, len - 2);

    case PPP_PROTO_IPCP:
        return ppp_ipcp_process_packet(session, payload, len - 2);

    case PPP_PROTO_PAP:
        return ppp_pap_process_packet(session, payload, len - 2);

    case PPP_PROTO_CHAP:
        return ppp_chap_process_packet(session, payload, len - 2);

    case PPP_PROTO_IP:
        YLOG_DEBUG("PPPoE: Received IP packet");

        /* Decapsulate: Move Ethernet header forward to skip PPPoE/PPP */
        /* Current: [Eth][PPPoE][PPP][IP...] */
        /* Target:  [Eth][IP...] (Eth type = IPv4) */

        uint16_t strip_len = sizeof(struct pppoe_hdr) + 2;

        /* Copy Ethernet header to new position (overwriting PPPoE header) */
        struct rte_ether_hdr *new_eth = (struct rte_ether_hdr *)((uint8_t *)eth + strip_len);
        rte_ether_addr_copy(&eth->dst_addr, &new_eth->dst_addr);
        rte_ether_addr_copy(&eth->src_addr, &new_eth->src_addr);
        new_eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        /* Adjust mbuf */
        rte_pktmbuf_adj(m, strip_len);
        pkt->data = rte_pktmbuf_mtod(m, uint8_t *);
        pkt->len = m->data_len;

        /* Re-inject into packet processing */
        packet_rx_process_packet(pkt);
        break;

    default:
        YLOG_WARNING("PPPoE: Unknown PPP protocol 0x%04x", proto);
        /* TODO: Send LCP Protocol-Reject */
        break;
    }

    return 0;
}

void pppoe_terminate_session(struct pppoe_session *session, const char *reason)
{
    if (!session) return;
    (void)reason; /* Used in log below */

    YLOG_INFO("PPPoE: Terminating session %u (reason: %s)", session->session_id, reason ? reason : "unknown");

    /* Send PADT for graceful termination */
    pppoe_send_padt(session);

    /* Send RADIUS Accounting Stop */
    radius_acct_request(RADIUS_ACCT_STATUS_STOP, session->session_id, NULL, session->client_ip);

    /* HA Sync */
    ha_send_sync(HA_MSG_SESSION_DEL, session->session_id, session->client_mac.addr_bytes, 0, session->state);

    /* Mark session as terminated */
    session->state = PPPOE_STATE_TERMINATED;
}

#define PPPOE_ECHO_INTERVAL    30  /* Send echo every 30 seconds */
#define PPPOE_ECHO_MAX_FAILS    3  /* Max failures before terminate */

void pppoe_check_keepalives(void)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    uint64_t now = time(NULL);

    while (curr) {
        struct pppoe_session *next = curr->next; /* Save next in case we terminate */

        if (curr->state == PPPOE_STATE_SESSION_ESTABLISHED && curr->lcp_state == LCP_STATE_OPENED) {
            /* LCP Echo/Keepalive */
            if (curr->last_echo_ts == 0 || (now - curr->last_echo_ts) >= PPPOE_ECHO_INTERVAL) {
                /* Time to send echo */
                if (curr->echo_failures >= PPPOE_ECHO_MAX_FAILS) {
                    /* Too many failures, terminate */
                    pppoe_terminate_session(curr, "Echo timeout");
                } else {
                    ppp_lcp_send_echo_request(curr);
                    curr->echo_failures++;
                    curr->last_echo_ts = now;
                }
            }

            /* Session Timeout */
            if (curr->session_timeout > 0 && curr->start_ts > 0) {
                if (now - curr->start_ts >= curr->session_timeout) {
                    pppoe_terminate_session(curr, "Session timeout");
                }
            }

            /* Idle Timeout */
            if (curr->idle_timeout > 0) {
                uint64_t last = (curr->last_activity_ts > 0) ? curr->last_activity_ts : curr->start_ts;
                if (now - last >= curr->idle_timeout) {
                    pppoe_terminate_session(curr, "Idle timeout");
                }
            }
        }
        curr = next;
    }
}

void pppoe_check_accounting(void)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    uint64_t now = time(NULL);

    while (curr) {
        if (curr->state == PPPOE_STATE_SESSION_ESTABLISHED && curr->acct_interim_interval > 0) {
            /* Check if it's time for interim update */
            if (now - curr->last_acct_ts >= curr->acct_interim_interval) {
                radius_acct_request(RADIUS_ACCT_STATUS_INTERIM, curr->session_id,
                                  NULL /* TODO: Store username in session */,
                                  curr->client_ip);
                curr->last_acct_ts = now;
            }
        }
        curr = curr->next;
    }
}

void pppoe_update_qos(const uint8_t *mac, uint64_t rate_bps)
{
    struct pppoe_session *curr = g_pppoe_ctx.sessions;
    while (curr) {
        if (rte_is_same_ether_addr(&curr->client_mac, (const struct rte_ether_addr *)mac)) {
            /* Update Token Bucket */
            /* Burst = Rate / 8 (1 second buffer) or fixed */
            uint64_t burst = rate_bps / 8;
            if (burst < 1500) burst = 1500;

            qos_tb_init(&curr->downlink_tb, rate_bps / 8, burst);
            YLOG_INFO("PPPoE: Updated QoS for %02x:%02x:%02x:%02x:%02x:%02x to %lu bps",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rate_bps);
            return;
        }
        curr = curr->next;
    }
    YLOG_WARNING("PPPoE: Session not found for QoS update");
}

static void pppoe_auth_callback(uint16_t session_id, bool success, uint32_t framed_ip, uint32_t session_timeout, uint32_t idle_timeout)
{
    struct pppoe_session *session = pppoe_find_session(session_id, NULL);

    if (!session) {
        YLOG_WARNING("PPPoE: Auth response for unknown session %u", session_id);
        return;
    }

    if (success) {
        YLOG_INFO("PPPoE: Session %u Auth Success (Framed-IP: %u.%u.%u.%u, Timeout: %u, Idle: %u)",
                  session_id,
                  (framed_ip >> 24) & 0xFF, (framed_ip >> 16) & 0xFF,
                  (framed_ip >> 8) & 0xFF, framed_ip & 0xFF,
                  session_timeout, idle_timeout);

        /* Use Framed-IP-Address if provided, otherwise allocate from pool */
        if (framed_ip != 0) {
            session->client_ip = framed_ip;
        }

        session->session_timeout = session_timeout;
        session->idle_timeout = idle_timeout;
        session->start_ts = time(NULL);

        /* Send Success Packet */
        const char *msg = "Login OK";
        if (session->lcp_state == LCP_STATE_OPENED) {
             if (session->chap_challenge_len > 0) {
                 ppp_auth_send(session, PPP_PROTO_CHAP, CHAP_CODE_SUCCESS, session->next_lcp_identifier, (const uint8_t *)msg, strlen(msg));
             } else {
                 uint8_t reply_data[256];
                 reply_data[0] = strlen(msg);
                 memcpy(reply_data + 1, msg, strlen(msg));
                 ppp_auth_send(session, PPP_PROTO_PAP, PAP_CODE_AUTH_ACK, session->next_lcp_identifier, reply_data, 1 + strlen(msg));
             }
        }

        /* Transition State */
        session->state = PPPOE_STATE_SESSION_ESTABLISHED;

        /* Start IPCP */
        ppp_ipcp_open(session);

        /* Send HA Sync */
        ha_send_sync(HA_MSG_SESSION_UPDATE, session->session_id, session->client_mac.addr_bytes, 0, session->state);

    } else {
        YLOG_INFO("PPPoE: Session %u Auth Failure", session_id);

        /* Send Failure Packet */
        const char *msg = "Auth Failed";
        if (session->chap_challenge_len > 0) {
             ppp_auth_send(session, PPP_PROTO_CHAP, CHAP_CODE_FAILURE, session->next_lcp_identifier, (const uint8_t *)msg, strlen(msg));
        } else {
             uint8_t reply_data[256];
             reply_data[0] = strlen(msg);
             memcpy(reply_data + 1, msg, strlen(msg));
             ppp_auth_send(session, PPP_PROTO_PAP, PAP_CODE_AUTH_NAK, session->next_lcp_identifier, reply_data, 1 + strlen(msg));
        }

        /* Terminate */
        session->state = PPPOE_STATE_TERMINATED;
        ha_send_sync(HA_MSG_SESSION_DEL, session->session_id, session->client_mac.addr_bytes, 0, session->state);
    }
}
