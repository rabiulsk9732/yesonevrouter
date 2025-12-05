/**
 * @file syslog_logger.h
 * @brief Syslog Integration API
 */

#ifndef SYSLOG_LOGGER_H
#define SYSLOG_LOGGER_H

#include <stdint.h>
#include <syslog.h>

/**
 * Initialize syslog logger
 * @param ident Program identifier (default: "yesrouter")
 * @param facility Syslog facility (e.g., LOG_LOCAL0)
 */
int syslog_logger_init(const char *ident, int facility);

/**
 * Cleanup syslog logger
 */
void syslog_logger_cleanup(void);

/**
 * Log a message to syslog
 */
void syslog_logger_log(int priority, const char *fmt, ...);

/**
 * Log session start
 */
void syslog_log_session_start(uint16_t session_id, uint32_t client_ip, const uint8_t *mac);

/**
 * Log session stop
 */
void syslog_log_session_stop(uint16_t session_id, uint32_t client_ip, const char *reason);

/**
 * Log successful authentication
 */
void syslog_log_auth_success(const char *username, uint32_t client_ip);

/**
 * Log failed authentication
 */
void syslog_log_auth_failure(const char *username, const char *reason);

/**
 * Log security event
 */
void syslog_log_security_event(const char *event, const uint8_t *mac, uint32_t ip);

#endif /* SYSLOG_LOGGER_H */
