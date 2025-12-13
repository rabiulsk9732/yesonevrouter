/**
 * @file ipoe_coa.c
 * @brief IPoE CoA/DM Implementation
 */

#include <ipoe_coa.h>
#include <ipoe_session.h>
#include <ipoe_timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Global CoA Statistics
 *============================================================================*/

static struct {
    uint64_t coa_received;
    uint64_t coa_ack;
    uint64_t coa_nak;
    uint64_t dm_received;
    uint64_t dm_ack;
    uint64_t dm_nak;
    uint64_t sessions_disconnected;
    uint64_t rate_updates;
    uint64_t acl_updates;
} g_coa_stats = {0};

/*============================================================================
 * Initialization
 *============================================================================*/

int ipoe_coa_init(void)
{
    memset(&g_coa_stats, 0, sizeof(g_coa_stats));
    printf("ipoe_coa: initialized\n");
    return 0;
}

void ipoe_coa_cleanup(void)
{
    /* Nothing to clean up */
}

/*============================================================================
 * Session Lookup
 *============================================================================*/

static struct ipoe_session *find_session(struct ipoe_coa_request *req)
{
    struct ipoe_session *sess = NULL;

    /* Try session ID first */
    if (req->session_id != 0) {
        sess = ipoe_session_find_by_id(req->session_id);
        if (sess) return sess;
    }

    /* Try MAC */
    if (req->mac[0] || req->mac[1] || req->mac[2]) {
        sess = ipoe_session_find_by_mac(req->mac);
        if (sess) return sess;
    }

    /* Try IP */
    if (req->ip_addr != 0) {
        sess = ipoe_session_find_by_ip(req->ip_addr);
        if (sess) return sess;
    }

    return NULL;
}

/*============================================================================
 * CoA Processing
 *============================================================================*/

int ipoe_coa_process(struct ipoe_coa_request *req)
{
    if (!req) return -1;

    g_coa_stats.coa_received++;

    /* Find session */
    struct ipoe_session *sess = find_session(req);
    if (!sess) {
        req->coa_response = 1;
        req->error_cause = 503;  /* Session Not Found */
        g_coa_stats.coa_nak++;
        return -1;
    }

    /* Process action */
    int ret = 0;

    switch (req->action) {
        case IPOE_COA_ACTION_DISCONNECT:
            ret = ipoe_session_destroy(sess, IPOE_TERM_RADIUS_DM);
            g_coa_stats.sessions_disconnected++;
            break;

        case IPOE_COA_ACTION_UPDATE_RATE:
            ret = ipoe_coa_apply_rate_limit(sess->session_id,
                                             req->rate_limit_up,
                                             req->rate_limit_down);
            g_coa_stats.rate_updates++;
            break;

        case IPOE_COA_ACTION_UPDATE_ACL:
            ret = ipoe_coa_apply_acl(sess->session_id,
                                      req->acl_in,
                                      req->acl_out);
            g_coa_stats.acl_updates++;
            break;

        case IPOE_COA_ACTION_REAUTH:
            ret = ipoe_coa_trigger_reauth(sess->session_id);
            break;

        default:
            req->coa_response = 1;
            req->error_cause = 401;  /* Unsupported Attribute */
            g_coa_stats.coa_nak++;
            return -1;
    }

    if (ret == 0) {
        req->coa_response = 0;
        g_coa_stats.coa_ack++;
    } else {
        req->coa_response = 1;
        req->error_cause = 506;  /* Resources Unavailable */
        g_coa_stats.coa_nak++;
    }

    return ret;
}

/*============================================================================
 * Disconnect-Message Processing
 *============================================================================*/

int ipoe_dm_process(uint32_t session_id, const uint8_t *mac,
                    uint32_t ip_addr, const char *username)
{
    (void)username;

    g_coa_stats.dm_received++;

    struct ipoe_session *sess = NULL;

    /* Find session */
    if (session_id != 0) {
        sess = ipoe_session_find_by_id(session_id);
    } else if (mac && (mac[0] || mac[1] || mac[2])) {
        sess = ipoe_session_find_by_mac(mac);
    } else if (ip_addr != 0) {
        sess = ipoe_session_find_by_ip(ip_addr);
    }

    if (!sess) {
        g_coa_stats.dm_nak++;
        return -1;
    }

    /* Cancel all timers for this session */
    ipoe_timer_cancel_all(sess->session_id);

    /* Destroy session */
    if (ipoe_session_destroy(sess, IPOE_TERM_RADIUS_DM) == 0) {
        g_coa_stats.dm_ack++;
        g_coa_stats.sessions_disconnected++;
        return 0;
    }

    g_coa_stats.dm_nak++;
    return -1;
}

/*============================================================================
 * CoA Actions
 *============================================================================*/

int ipoe_coa_apply_rate_limit(uint32_t session_id, uint32_t up, uint32_t down)
{
    struct ipoe_session *sess = ipoe_session_find_by_id(session_id);
    if (!sess) return -1;

    sess->rate_limit_up = up;
    sess->rate_limit_down = down;

    /* TODO: Apply to QoS subsystem */
    printf("ipoe_coa: session %u rate limit updated: up=%u down=%u kbps\n",
           session_id, up, down);

    return 0;
}

int ipoe_coa_apply_acl(uint32_t session_id, const char *acl_in, const char *acl_out)
{
    struct ipoe_session *sess = ipoe_session_find_by_id(session_id);
    if (!sess) return -1;

    (void)acl_in;
    (void)acl_out;

    /* TODO: Apply to ACL subsystem */
    printf("ipoe_coa: session %u ACL updated\n", session_id);

    return 0;
}

int ipoe_coa_trigger_reauth(uint32_t session_id)
{
    struct ipoe_session *sess = ipoe_session_find_by_id(session_id);
    if (!sess) return -1;

    /* Update state to trigger re-authentication */
    ipoe_session_update_state(sess, IPOE_STATE_AUTH_PENDING);

    printf("ipoe_coa: session %u triggering re-auth\n", session_id);

    return 0;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void ipoe_coa_print_stats(void)
{
    printf("\nIPoE CoA/DM Statistics:\n");
    printf("  CoA Received:          %lu\n", g_coa_stats.coa_received);
    printf("  CoA ACK:               %lu\n", g_coa_stats.coa_ack);
    printf("  CoA NAK:               %lu\n", g_coa_stats.coa_nak);
    printf("  DM Received:           %lu\n", g_coa_stats.dm_received);
    printf("  DM ACK:                %lu\n", g_coa_stats.dm_ack);
    printf("  DM NAK:                %lu\n", g_coa_stats.dm_nak);
    printf("  Sessions Disconnected: %lu\n", g_coa_stats.sessions_disconnected);
    printf("  Rate Updates:          %lu\n", g_coa_stats.rate_updates);
    printf("  ACL Updates:           %lu\n", g_coa_stats.acl_updates);
    printf("\n");
}
