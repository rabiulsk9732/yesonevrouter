/**
 * @file ppp_debug.c
 * @brief PPP Debug Logging
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "ppp_debug.h"

static struct {
    bool lcp_enabled;
    bool ipcp_enabled;
    bool pap_enabled;
    bool chap_enabled;
    bool pppoe_enabled;
    bool packet_enabled;
    FILE *log_file;
} g_debug = {0};

void ppp_debug_init(void)
{
    memset(&g_debug, 0, sizeof(g_debug));
}

void ppp_debug_set_flags(uint32_t flags)
{
    g_debug.lcp_enabled = (flags & PPP_DEBUG_LCP) != 0;
    g_debug.ipcp_enabled = (flags & PPP_DEBUG_IPCP) != 0;
    g_debug.pap_enabled = (flags & PPP_DEBUG_PAP) != 0;
    g_debug.chap_enabled = (flags & PPP_DEBUG_CHAP) != 0;
    g_debug.pppoe_enabled = (flags & PPP_DEBUG_PPPOE) != 0;
    g_debug.packet_enabled = (flags & PPP_DEBUG_PACKET) != 0;
}

void ppp_debug_set_file(const char *filename)
{
    if (g_debug.log_file && g_debug.log_file != stderr) {
        fclose(g_debug.log_file);
    }

    if (filename) {
        g_debug.log_file = fopen(filename, "a");
    } else {
        g_debug.log_file = stderr;
    }
}

static void ppp_debug_log_internal(const char *prefix, const char *fmt, va_list ap)
{
    FILE *out = g_debug.log_file ? g_debug.log_file : stderr;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    fprintf(out, "%02d:%02d:%02d [%s] ",
            tm->tm_hour, tm->tm_min, tm->tm_sec, prefix);
    vfprintf(out, fmt, ap);
    fprintf(out, "\n");
    fflush(out);
}

void ppp_debug_lcp(const char *fmt, ...)
{
    if (!g_debug.lcp_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    ppp_debug_log_internal("LCP", fmt, ap);
    va_end(ap);
}

void ppp_debug_ipcp(const char *fmt, ...)
{
    if (!g_debug.ipcp_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    ppp_debug_log_internal("IPCP", fmt, ap);
    va_end(ap);
}

void ppp_debug_pap(const char *fmt, ...)
{
    if (!g_debug.pap_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    ppp_debug_log_internal("PAP", fmt, ap);
    va_end(ap);
}

void ppp_debug_chap(const char *fmt, ...)
{
    if (!g_debug.chap_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    ppp_debug_log_internal("CHAP", fmt, ap);
    va_end(ap);
}

void ppp_debug_pppoe(const char *fmt, ...)
{
    if (!g_debug.pppoe_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    ppp_debug_log_internal("PPPOE", fmt, ap);
    va_end(ap);
}

void ppp_debug_packet(uint16_t session_id, const char *direction,
                      const uint8_t *data, size_t len)
{
    if (!g_debug.packet_enabled) return;

    FILE *out = g_debug.log_file ? g_debug.log_file : stderr;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    fprintf(out, "%02d:%02d:%02d [PKT] Session %u %s %zu bytes:",
            tm->tm_hour, tm->tm_min, tm->tm_sec, session_id, direction, len);

    size_t to_print = len > 64 ? 64 : len;
    for (size_t i = 0; i < to_print; i++) {
        if (i % 16 == 0) fprintf(out, "\n  ");
        fprintf(out, "%02x ", data[i]);
    }
    if (len > 64) fprintf(out, "...");
    fprintf(out, "\n");
    fflush(out);
}

void ppp_debug_cleanup(void)
{
    if (g_debug.log_file && g_debug.log_file != stderr) {
        fclose(g_debug.log_file);
    }
    memset(&g_debug, 0, sizeof(g_debug));
}
