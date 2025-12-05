/**
 * @file rest_api.h
 * @brief REST API for Session Management
 */

#ifndef REST_API_H
#define REST_API_H

#include <stdint.h>

/**
 * Initialize REST API server
 * @param port TCP port (default: 8080)
 */
int rest_api_init(uint16_t port);

/**
 * Stop REST API server
 */
void rest_api_cleanup(void);

#endif /* REST_API_H */
