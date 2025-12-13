/**
 * @file audit_log.c
 * @brief Audit Logging for Security Events
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "audit_log.h"
#include "log.h"

#define MAX_AUDIT_ENTRIES 10000
#define AUDIT_ENTRY_SIZE 256

/* Audit log entry */
struct audit_entry {
    time_t timestamp;
    char event_type[32];
    char username[32];
    char details[128];
};

static struct {
    struct audit_entry *entries;
    int count;
    int max_entries;
    FILE *file;
    pthread_mutex_t lock;
} g_audit = {
    .entries = NULL,
    .count = 0,
    .max_entries = MAX_AUDIT_ENTRIES,
    .file = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

int audit_log_init(const char *logfile)
{
    g_audit.entries = calloc(MAX_AUDIT_ENTRIES, sizeof(struct audit_entry));
    if (!g_audit.entries) {
        return -1;
    }

    if (logfile) {
        g_audit.file = fopen(logfile, "a");
        if (!g_audit.file) {
            YLOG_WARNING("Audit Log: Failed to open file '%s'", logfile);
        }
    }

    pthread_mutex_init(&g_audit.lock, NULL);

    audit_log_event("SYSTEM", "system", "Audit logging initialized");
    YLOG_INFO("Audit Log: Initialized");
    return 0;
}

void audit_log_event(const char *event_type, const char *username, const char *details)
{
    if (!g_audit.entries) return;

    pthread_mutex_lock(&g_audit.lock);

    /* Add to in-memory buffer (circular) */
    int idx = g_audit.count % MAX_AUDIT_ENTRIES;
    struct audit_entry *e = &g_audit.entries[idx];

    e->timestamp = time(NULL);
    snprintf(e->event_type, sizeof(e->event_type), "%s", event_type ? event_type : "UNKNOWN");
    snprintf(e->username, sizeof(e->username), "%s", username ? username : "-");
    snprintf(e->details, sizeof(e->details), "%s", details ? details : "");

    g_audit.count++;

    /* Write to file */
    if (g_audit.file) {
        char timebuf[32];
        struct tm *tm = localtime(&e->timestamp);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

        fprintf(g_audit.file, "%s %s %s %s\n",
                timebuf, e->event_type, e->username, e->details);
        fflush(g_audit.file);
    }

    pthread_mutex_unlock(&g_audit.lock);
}

void audit_log_show(int count)
{
    if (!g_audit.entries) {
        printf("Audit log not initialized\n");
        return;
    }

    pthread_mutex_lock(&g_audit.lock);

    int start = 0;
    int total = g_audit.count;

    if (total > MAX_AUDIT_ENTRIES) {
        total = MAX_AUDIT_ENTRIES;
        start = g_audit.count % MAX_AUDIT_ENTRIES;
    }

    if (count > 0 && count < total) {
        start = (start + total - count) % MAX_AUDIT_ENTRIES;
        total = count;
    }

    printf("Audit Log (last %d entries):\n", total);
    printf("%-20s %-12s %-16s %s\n", "Timestamp", "Event", "User", "Details");
    printf("%-20s %-12s %-16s %s\n", "--------------------", "------------", "----------------", "--------");

    for (int i = 0; i < total; i++) {
        int idx = (start + i) % MAX_AUDIT_ENTRIES;
        struct audit_entry *e = &g_audit.entries[idx];

        char timebuf[32];
        struct tm *tm = localtime(&e->timestamp);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

        printf("%-20s %-12s %-16s %s\n",
               timebuf, e->event_type, e->username, e->details);
    }

    pthread_mutex_unlock(&g_audit.lock);
}

void audit_log_clear(void)
{
    pthread_mutex_lock(&g_audit.lock);
    g_audit.count = 0;
    pthread_mutex_unlock(&g_audit.lock);

    audit_log_event("SYSTEM", "system", "Audit log cleared");
}

void audit_log_cleanup(void)
{
    audit_log_event("SYSTEM", "system", "Audit logging stopped");

    if (g_audit.file) {
        fclose(g_audit.file);
        g_audit.file = NULL;
    }

    if (g_audit.entries) {
        free(g_audit.entries);
        g_audit.entries = NULL;
    }

    pthread_mutex_destroy(&g_audit.lock);
    YLOG_INFO("Audit Log: Cleanup complete");
}
