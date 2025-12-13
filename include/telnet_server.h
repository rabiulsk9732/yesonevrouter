/**
 * @file telnet_server.h
 * @brief Telnet Server Interface
 */

#ifndef TELNET_SERVER_H
#define TELNET_SERVER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Initialize Telnet server
 * @param port Port number (default 23)
 * @return 0 on success, -1 on error
 */
int telnet_server_init(uint16_t port);

/**
 * Start Telnet server
 * @return 0 on success, -1 on error
 */
int telnet_server_start(void);

/**
 * Stop Telnet server
 */
void telnet_server_stop(void);

/**
 * Cleanup Telnet server
 */
void telnet_server_cleanup(void);

/**
 * Check if server is running
 * @return true if running, false otherwise
 */
bool telnet_server_is_running(void);

#endif /* TELNET_SERVER_H */
