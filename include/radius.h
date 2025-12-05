/**
 * @file radius.h
 * @brief RADIUS Client (RFC 2865, 2866)
 */

#ifndef YESROUTER_RADIUS_H
#define YESROUTER_RADIUS_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* RADIUS Codes */
#define RADIUS_CODE_ACCESS_REQUEST      1
#define RADIUS_CODE_ACCESS_ACCEPT       2
#define RADIUS_CODE_ACCESS_REJECT       3
#define RADIUS_CODE_ACCOUNTING_REQUEST  4
#define RADIUS_CODE_ACCOUNTING_RESPONSE 5
#define RADIUS_CODE_DISCONNECT_REQUEST  40
#define RADIUS_CODE_DISCONNECT_ACK      41
#define RADIUS_CODE_DISCONNECT_NAK      42
#define RADIUS_CODE_COA_REQUEST         43
#define RADIUS_CODE_COA_ACK             44
#define RADIUS_CODE_COA_NAK             45

/* RADIUS Attributes */
#define RADIUS_ATTR_USER_NAME           1
#define RADIUS_ATTR_USER_PASSWORD       2
#define RADIUS_ATTR_CHAP_PASSWORD       3
#define RADIUS_ATTR_NAS_IP_ADDRESS      4
#define RADIUS_ATTR_NAS_PORT            5
#define RADIUS_ATTR_SERVICE_TYPE        6
#define RADIUS_ATTR_FRAMED_PROTOCOL     7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS   8
#define RADIUS_ATTR_FILTER_ID           11
#define RADIUS_ATTR_SESSION_TIMEOUT     27
#define RADIUS_ATTR_IDLE_TIMEOUT        28
#define RADIUS_ATTR_CALLED_STATION_ID   30
#define RADIUS_ATTR_CALLING_STATION_ID  31
#define RADIUS_ATTR_CHAP_CHALLENGE      60
#define RADIUS_ATTR_ACCT_STATUS_TYPE    40
#define RADIUS_ATTR_ACCT_SESSION_ID     44

/* Accounting Status Types */
#define RADIUS_ACCT_STATUS_START        1
#define RADIUS_ACCT_STATUS_STOP         2
#define RADIUS_ACCT_STATUS_INTERIM      3

struct radius_server {
    uint32_t ip;            /* Host order */
    uint16_t port;          /* Host order */
    uint16_t acct_port;     /* Host order */
    char secret[64];
};

/**
 * Initialize RADIUS subsystem
 */
int radius_init(void);

/**
 * Configure RADIUS server
 */
void radius_add_server(uint32_t ip, uint16_t port, const char *secret);

/**
 * Send Access-Request (PAP)
 * @param username Username
 * @param password Password
 * @param session_id Session ID
 * @param client_mac Calling Station ID
 * @return 0 on success (request sent), -1 on error
 */
int radius_auth_request(const char *username, const char *password, uint16_t session_id, const uint8_t *client_mac);
int radius_chap_auth_request(const char *username, const uint8_t *chap_challenge, uint8_t chap_challenge_len, const uint8_t *chap_password, uint8_t chap_password_len, uint16_t session_id, const uint8_t *client_mac);

/**
 * Send Accounting Request
 * @param status RADIUS_ACCT_STATUS_*
 * @param session_id Session ID
 * @param username Username
 * @param client_ip Framed IP Address (Host order)
 */
int radius_acct_request(uint8_t status, uint16_t session_id, const char *username, uint32_t client_ip);

/**
 * Poll for incoming RADIUS packets (CoA/DM)
 */
void radius_poll(void);

/**
 * Set callback for CoA rate updates
 */
void radius_set_coa_callback(void (*cb)(const uint8_t *mac, uint64_t rate));

/**
 * Set callback for Authentication results
 * @param cb Callback function (session_id, success, framed_ip, session_timeout, idle_timeout)
 */
void radius_set_auth_callback(void (*cb)(uint16_t session_id, bool success, uint32_t framed_ip, uint32_t session_timeout, uint32_t idle_timeout));

#endif /* YESROUTER_RADIUS_H */
