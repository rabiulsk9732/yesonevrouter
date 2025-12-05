/**
 * @file session_export.h
 * @brief Session Export and Lookup API
 */

#ifndef SESSION_EXPORT_H
#define SESSION_EXPORT_H

#include <stdint.h>
#include <stddef.h>

/* Session info structure */
struct session_info {
    uint16_t session_id;
    uint32_t client_ip;     /* Host order */
    uint8_t client_mac[6];
    char state_str[16];
    uint64_t uptime_sec;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
};

/**
 * Session iterator callback
 * @param ctx User context
 * @param index Session index (0-based)
 * @param info Output: session info
 * @return 0 on success, -1 if no more sessions
 */
typedef int (*session_iterator_fn)(void *ctx, int index, struct session_info *info);

/**
 * Set session iterator (called by PPPoE module)
 */
void session_export_set_iterator(session_iterator_fn fn, void *ctx);

/**
 * Export all sessions as JSON
 */
int session_export_json(char *buf, size_t buf_size);

/**
 * Export all sessions as CSV
 */
int session_export_csv(char *buf, size_t buf_size);

/**
 * Lookup session by client IP
 */
int session_lookup_by_ip(uint32_t ip, struct session_info *info);

/**
 * Lookup session by client MAC
 */
int session_lookup_by_mac(const uint8_t *mac, struct session_info *info);

/**
 * Lookup session by session ID
 */
int session_lookup_by_id(uint16_t session_id, struct session_info *info);

/**
 * Print session info to stdout
 */
void session_print_info(const struct session_info *info);

#endif /* SESSION_EXPORT_H */
