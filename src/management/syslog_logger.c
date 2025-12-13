/**
 * @file syslog_logger.c
 * @brief Syslog Integration for PPPoE Logging
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include "syslog_logger.h"

static struct {
    int enabled;
    int facility;
    char ident[32];
} g_syslog = {
    .enabled = 0,
    .facility = LOG_LOCAL0,
    .ident = "yesrouter"
};

int syslog_logger_init(const char *ident, int facility)
{
    if (ident) {
        strncpy(g_syslog.ident, ident, sizeof(g_syslog.ident) - 1);
    }
    g_syslog.facility = facility;

    openlog(g_syslog.ident, LOG_PID | LOG_NDELAY, g_syslog.facility);
    g_syslog.enabled = 1;

    syslog(LOG_INFO, "Syslog logger initialized");
    return 0;
}

void syslog_logger_cleanup(void)
{
    if (g_syslog.enabled) {
        syslog(LOG_INFO, "Syslog logger shutdown");
        closelog();
        g_syslog.enabled = 0;
    }
}

void syslog_logger_log(int priority, const char *fmt, ...)
{
    if (!g_syslog.enabled) return;

    va_list ap;
    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}

void syslog_log_session_start(uint16_t session_id, uint32_t client_ip, const uint8_t *mac)
{
    if (!g_syslog.enabled) return;

    syslog(LOG_INFO, "SESSION-START: id=%u ip=%u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x",
           session_id,
           (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF,
           (client_ip >> 8) & 0xFF, client_ip & 0xFF,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void syslog_log_session_stop(uint16_t session_id, uint32_t client_ip, const char *reason)
{
    if (!g_syslog.enabled) return;

    syslog(LOG_INFO, "SESSION-STOP: id=%u ip=%u.%u.%u.%u reason=%s",
           session_id,
           (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF,
           (client_ip >> 8) & 0xFF, client_ip & 0xFF,
           reason ? reason : "unknown");
}

void syslog_log_auth_success(const char *username, uint32_t client_ip)
{
    if (!g_syslog.enabled) return;

    syslog(LOG_INFO, "AUTH-SUCCESS: user=%s ip=%u.%u.%u.%u",
           username ? username : "unknown",
           (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF,
           (client_ip >> 8) & 0xFF, client_ip & 0xFF);
}

void syslog_log_auth_failure(const char *username, const char *reason)
{
    if (!g_syslog.enabled) return;

    syslog(LOG_WARNING, "AUTH-FAILURE: user=%s reason=%s",
           username ? username : "unknown",
           reason ? reason : "unknown");
}

void syslog_log_security_event(const char *event, const uint8_t *mac, uint32_t ip)
{
    if (!g_syslog.enabled) return;

    syslog(LOG_WARNING, "SECURITY: event=%s mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%u.%u.%u.%u",
           event,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF, ip & 0xFF);
}
