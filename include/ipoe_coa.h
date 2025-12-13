/**
 * @file ipoe_coa.h
 * @brief IPoE CoA/DM Handler - Change of Authorization
 *
 * Handles RADIUS CoA and Disconnect-Message for session control
 */

#ifndef IPOE_COA_H
#define IPOE_COA_H

#include <stdint.h>
#include <stdbool.h>

/*============================================================================
 * CoA Action Types
 *============================================================================*/

typedef enum {
    IPOE_COA_ACTION_DISCONNECT = 1,     /* Disconnect session */
    IPOE_COA_ACTION_UPDATE_RATE,        /* Update rate limits */
    IPOE_COA_ACTION_UPDATE_ACL,         /* Update ACL */
    IPOE_COA_ACTION_REAUTH,             /* Force re-authentication */
    IPOE_COA_ACTION_UPDATE_POOL,        /* Change IP pool */
    IPOE_COA_ACTION_MAX
} ipoe_coa_action_t;

/*============================================================================
 * CoA Request Attributes
 *============================================================================*/

struct ipoe_coa_request {
    /* Session identification */
    uint32_t session_id;
    uint32_t acct_session_id;
    uint8_t  mac[6];
    uint32_t ip_addr;
    char     username[64];

    /* Action */
    ipoe_coa_action_t action;

    /* Rate limit update */
    uint32_t rate_limit_up;     /* kbps */
    uint32_t rate_limit_down;

    /* ACL update */
    char     acl_in[32];
    char     acl_out[32];

    /* Pool update */
    char     new_pool[32];

    /* Response code */
    uint8_t  coa_response;      /* 0=ACK, non-0=NAK */
    uint32_t error_cause;
};

/*============================================================================
 * CoA API
 *============================================================================*/

/* Initialize CoA handler */
int ipoe_coa_init(void);
void ipoe_coa_cleanup(void);

/* Process CoA request (called from RADIUS module) */
int ipoe_coa_process(struct ipoe_coa_request *req);

/* Process Disconnect-Message (called from RADIUS module) */
int ipoe_dm_process(uint32_t session_id, const uint8_t *mac,
                    uint32_t ip_addr, const char *username);

/* Apply CoA action to session */
int ipoe_coa_apply_rate_limit(uint32_t session_id, uint32_t up, uint32_t down);
int ipoe_coa_apply_acl(uint32_t session_id, const char *acl_in, const char *acl_out);
int ipoe_coa_trigger_reauth(uint32_t session_id);

/* Statistics */
void ipoe_coa_print_stats(void);

#endif /* IPOE_COA_H */
