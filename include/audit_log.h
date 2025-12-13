/**
 * @file audit_log.h
 * @brief Audit Logging API
 */

#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

/**
 * Initialize audit logging
 * @param logfile Path to audit log file (NULL for memory only)
 */
int audit_log_init(const char *logfile);

/**
 * Cleanup audit logging
 */
void audit_log_cleanup(void);

/**
 * Log an audit event
 * @param event_type Event type (LOGIN, LOGOUT, COMMAND, CONFIG, etc.)
 * @param username User who triggered the event
 * @param details Event details
 */
void audit_log_event(const char *event_type, const char *username, const char *details);

/**
 * Show recent audit log entries
 * @param count Number of entries to show (0 for all)
 */
void audit_log_show(int count);

/**
 * Clear audit log
 */
void audit_log_clear(void);

#endif /* AUDIT_LOG_H */
