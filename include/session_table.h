/**
 * @file session_table.h
 * @brief Per-Core Session Table API
 */

#ifndef SESSION_TABLE_H
#define SESSION_TABLE_H

#include <stdint.h>

/**
 * Initialize session table
 */
int session_table_init(void);

/**
 * Cleanup session table
 */
void session_table_cleanup(void);

/**
 * Add session to table
 * @param client_ip Client IP (host order)
 * @param session_id PPPoE session ID
 * @param ifindex Egress interface index
 * @param mac Client MAC (6 bytes)
 */
int session_table_add(uint32_t client_ip, uint16_t session_id, uint16_t ifindex, const uint8_t *mac);

/**
 * Delete session from table
 */
int session_table_del(uint32_t client_ip);

/**
 * Lookup session by client IP
 * @return 0 on success, -1 if not found
 */
int session_table_lookup(uint32_t client_ip, uint16_t *session_id, uint16_t *ifindex);

/**
 * Get session count
 */
uint32_t session_table_count(void);

#endif /* SESSION_TABLE_H */
