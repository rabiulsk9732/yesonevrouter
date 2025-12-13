/**
 * @file ssh_server.h
 * @brief SSH Server API
 */

#ifndef SSH_SERVER_H
#define SSH_SERVER_H

#include <stdint.h>

/**
 * Initialize SSH server
 * @param port TCP port (default: 22)
 */
int ssh_server_init(uint16_t port);

/**
 * Stop SSH server
 */
void ssh_server_cleanup(void);

/**
 * Set session timeout
 */
void ssh_server_set_timeout(int seconds);

/**
 * Set maximum concurrent sessions
 */
void ssh_server_set_max_sessions(int max);

/**
 * Show active SSH sessions
 */
void ssh_server_show_sessions(void);

/**
 * Disconnect a session
 */
void ssh_server_disconnect(int session_id);

#endif /* SSH_SERVER_H */
