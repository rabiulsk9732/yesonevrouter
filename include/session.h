/**
 * @file session.h
 * @brief Session Management
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "user_db.h"
#include "ipv6/ipv6.h"

#define SESSION_MAX_SESSIONS 64
#define SESSION_ID_LEN 16

/* Session types */
typedef enum {
    SESSION_TYPE_CONSOLE,  /* Local console */
    SESSION_TYPE_SSH,      /* SSH connection */
    SESSION_TYPE_TELNET,   /* Telnet connection */
} session_type_t;

/* Session state */
typedef enum {
    SESSION_STATE_ACTIVE,
    SESSION_STATE_IDLE,
    SESSION_STATE_CLOSED,
} session_state_t;

/* Session structure */
struct session {
    uint32_t session_id;
    session_type_t type;
    session_state_t state;
    struct user *user;
    char remote_addr[64];  /* IP address */
    time_t login_time;
    time_t last_activity;
    uint32_t idle_timeout;  /* seconds */

    /* IPv6 Information */
    bool ipv6_active;
    struct ipv6_addr ipv6_prefix;    /* Delegated Prefix */
    uint8_t ipv6_prefix_len;
    struct ipv6_addr ipv6_address;   /* WAN Address (IA_NA) */
    struct ipv6_addr ipv6_dns_primary;
    struct ipv6_addr ipv6_dns_secondary;

    void *private_data;  /* Type-specific data */
    struct session *next;
};

/**
 * Initialize session management
 * @return 0 on success, -1 on error
 */
int session_init(void);

/**
 * Cleanup session management
 */
void session_cleanup(void);

/**
 * Create a new session
 * @param type Session type
 * @param user Authenticated user
 * @param remote_addr Remote IP address
 * @return Session ID or 0 on error
 */
uint32_t session_create(session_type_t type, struct user *user, const char *remote_addr);

/**
 * Destroy a session
 * @param session_id Session ID
 * @return 0 on success, -1 on error
 */
int session_destroy(uint32_t session_id);

/**
 * Find session by ID
 * @param session_id Session ID
 * @return Session pointer or NULL
 */
struct session *session_find(uint32_t session_id);

/**
 * Update session activity
 * @param session_id Session ID
 */
void session_update_activity(uint32_t session_id);

/**
 * Check for idle timeouts
 * @return Number of sessions timed out
 */
uint32_t session_check_timeouts(void);

/**
 * Get session count
 * @return Number of active sessions
 */
uint32_t session_get_count(void);

/**
 * Print all sessions
 */
void session_print_all(void);

/**
 * Print session details
 * @param session_id Session ID
 */
void session_print(uint32_t session_id);

#endif /* SESSION_H */
