/**
 * @file cli_session.h
 * @brief CLI Session Management API
 */

#ifndef CLI_SESSION_H
#define CLI_SESSION_H

#include <stdint.h>
#include <stddef.h>

/**
 * Initialize CLI session subsystem
 */
int cli_session_init(void);

/**
 * Cleanup CLI session subsystem
 */
void cli_session_cleanup(void);

/**
 * Create a new CLI session
 * @param transport_id SSH/Telnet session ID
 * @param username Authenticated username
 * @param privilege Privilege level (0=admin, 1=operator, 2=viewer)
 * @return Session ID or -1 on error
 */
int cli_session_create(int transport_id, const char *username, uint8_t privilege);

/**
 * Destroy a CLI session
 */
void cli_session_destroy(int session_id);

/**
 * Check if user is authorized to run command
 * @return 0 if authorized, -1 if not
 */
int cli_session_check_auth(int session_id, const char *command);

/**
 * Execute a command in session context
 */
int cli_session_execute(int session_id, const char *command, char *output, size_t output_size);

/**
 * Show all active sessions
 */
void cli_session_show_all(void);

/**
 * Get help for a partial command
 */
int cli_session_help(int session_id, const char *partial, char *output, size_t output_size);

#endif /* CLI_SESSION_H */
