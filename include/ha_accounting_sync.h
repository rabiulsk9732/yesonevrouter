/**
 * @file ha_accounting_sync.h
 * @brief RADIUS Accounting Synchronization API
 */

#ifndef HA_ACCOUNTING_SYNC_H
#define HA_ACCOUNTING_SYNC_H

#include <stdint.h>

/**
 * Initialize accounting sync
 * @param port UDP port for sync messages
 */
int ha_acct_sync_init(uint16_t port);

/**
 * Cleanup accounting sync
 */
void ha_acct_sync_cleanup(void);

/**
 * Add peer for sync
 */
int ha_acct_sync_add_peer(uint32_t ip, uint16_t port);

/**
 * Sync Accounting-Start
 */
void ha_acct_sync_start(uint16_t session_id, const char *username, uint32_t client_ip);

/**
 * Sync Accounting-Interim
 */
void ha_acct_sync_interim(uint16_t session_id, uint64_t bytes_in, uint64_t bytes_out,
                          uint64_t packets_in, uint64_t packets_out, uint32_t session_time);

/**
 * Sync Accounting-Stop
 */
void ha_acct_sync_stop(uint16_t session_id, uint64_t bytes_in, uint64_t bytes_out,
                       uint32_t session_time);

/**
 * Get sync statistics
 */
void ha_acct_sync_stats(uint64_t *sent, uint64_t *received, uint64_t *failed);

#endif /* HA_ACCOUNTING_SYNC_H */
