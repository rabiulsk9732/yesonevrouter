/**
 * @file stats.c
 * @brief Statistics Collection Framework Implementation
 */

#define _GNU_SOURCE
#include "stats.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <math.h>

/* Global statistics context */
static struct stats_context g_stats_ctx = {
    .entries = NULL,
    .num_entries = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .enabled = true
};

/* Global health check context */
static struct health_check *g_health_checks = NULL;
static pthread_mutex_t g_health_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_health_initialized = false;

/* Statistics functions */

int stats_init(void)
{
    if (g_stats_ctx.enabled) {
        YLOG_INFO("Statistics subsystem initialized");
    }
    return 0;
}

static struct stats_entry *stats_find_entry(const char *name)
{
    struct stats_entry *entry;

    for (entry = g_stats_ctx.entries; entry; entry = entry->next) {
        if (strcmp(entry->name, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

int stats_register(const char *name, enum stats_type type,
                   const char *description, const char *unit, uint32_t flags)
{
    struct stats_entry *entry;

    if (!name) {
        return -1;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    /* Check if already exists */
    if (stats_find_entry(name)) {
        pthread_mutex_unlock(&g_stats_ctx.mutex);
        YLOG_WARNING("Statistics entry '%s' already exists", name);
        return -1;
    }

    /* Allocate new entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&g_stats_ctx.mutex);
        YLOG_ERROR("Failed to allocate statistics entry");
        return -1;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->type = type;
    entry->flags = flags;
    if (description) {
        strncpy(entry->description, description, sizeof(entry->description) - 1);
    }
    if (unit) {
        strncpy(entry->unit, unit, sizeof(entry->unit) - 1);
    }

    /* Initialize based on type */
    switch (type) {
    case STATS_TYPE_COUNTER:
        entry->value.counter = 0;
        break;
    case STATS_TYPE_GAUGE:
        entry->value.gauge = 0;
        break;
    case STATS_TYPE_HISTOGRAM:
        entry->value.histogram.count = 0;
        entry->value.histogram.sum = 0;
        entry->value.histogram.min = UINT64_MAX;
        entry->value.histogram.max = 0;
        break;
    case STATS_TYPE_RATE:
        entry->value.rate.value = 0;
        entry->value.rate.last_update = time(NULL);
        entry->value.rate.rate = 0.0;
        break;
    }

    /* Add to list */
    entry->next = g_stats_ctx.entries;
    g_stats_ctx.entries = entry;
    g_stats_ctx.num_entries++;

    pthread_mutex_unlock(&g_stats_ctx.mutex);

    YLOG_DEBUG("Registered statistics: %s (type: %d)", name, type);
    return 0;
}

void stats_counter_inc(const char *name, uint64_t value)
{
    struct stats_entry *entry;

    if (!g_stats_ctx.enabled || !name) {
        return;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    entry = stats_find_entry(name);
    if (entry && entry->type == STATS_TYPE_COUNTER) {
        if (entry->flags & STATS_FLAG_ATOMIC) {
            __atomic_add_fetch(&entry->value.counter, value, __ATOMIC_RELAXED);
        } else {
            entry->value.counter += value;
        }
    }

    pthread_mutex_unlock(&g_stats_ctx.mutex);
}

void stats_gauge_set(const char *name, int64_t value)
{
    struct stats_entry *entry;

    if (!g_stats_ctx.enabled || !name) {
        return;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    entry = stats_find_entry(name);
    if (entry && entry->type == STATS_TYPE_GAUGE) {
        if (entry->flags & STATS_FLAG_ATOMIC) {
            __atomic_store_n(&entry->value.gauge, value, __ATOMIC_RELAXED);
        } else {
            entry->value.gauge = value;
        }
    }

    pthread_mutex_unlock(&g_stats_ctx.mutex);
}

void stats_histogram_update(const char *name, uint64_t value)
{
    struct stats_entry *entry;

    if (!g_stats_ctx.enabled || !name) {
        return;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    entry = stats_find_entry(name);
    if (entry && entry->type == STATS_TYPE_HISTOGRAM) {
        entry->value.histogram.count++;
        entry->value.histogram.sum += value;
        if (value < entry->value.histogram.min) {
            entry->value.histogram.min = value;
        }
        if (value > entry->value.histogram.max) {
            entry->value.histogram.max = value;
        }
    }

    pthread_mutex_unlock(&g_stats_ctx.mutex);
}

int stats_get(const char *name, uint64_t *value)
{
    struct stats_entry *entry;
    int ret = -1;

    if (!name || !value) {
        return -1;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    entry = stats_find_entry(name);
    if (entry) {
        switch (entry->type) {
        case STATS_TYPE_COUNTER:
            *value = entry->value.counter;
            ret = 0;
            break;
        case STATS_TYPE_GAUGE:
            *value = (uint64_t)entry->value.gauge;
            ret = 0;
            break;
        case STATS_TYPE_HISTOGRAM:
            *value = entry->value.histogram.count;
            ret = 0;
            break;
        case STATS_TYPE_RATE:
            *value = entry->value.rate.value;
            ret = 0;
            break;
        }
    }

    pthread_mutex_unlock(&g_stats_ctx.mutex);

    return ret;
}

int stats_export_prometheus(char *buf, size_t buf_size)
{
    struct stats_entry *entry;
    int pos = 0;
    time_t now = time(NULL);

    if (!buf || buf_size == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    for (entry = g_stats_ctx.entries; entry; entry = entry->next) {
        const char *type_str = "";
        uint64_t value = 0;

        switch (entry->type) {
        case STATS_TYPE_COUNTER:
            type_str = "counter";
            value = entry->value.counter;
            break;
        case STATS_TYPE_GAUGE:
            type_str = "gauge";
            value = (uint64_t)entry->value.gauge;
            break;
        case STATS_TYPE_HISTOGRAM:
            type_str = "histogram";
            value = entry->value.histogram.count;
            break;
        case STATS_TYPE_RATE:
            type_str = "gauge";
            value = entry->value.rate.value;
            break;
        }

        /* Prometheus format: # HELP name description
         *                   # TYPE name type
         *                   name value timestamp */
        if (entry->description[0] != '\0') {
            pos += snprintf(buf + pos, buf_size - pos,
                           "# HELP %s %s\n", entry->name, entry->description);
        }
        pos += snprintf(buf + pos, buf_size - pos,
                       "# TYPE %s %s\n", entry->name, type_str);
        pos += snprintf(buf + pos, buf_size - pos,
                       "%s %lu %ld\n", entry->name, value, now);
    }

    pthread_mutex_unlock(&g_stats_ctx.mutex);

    return pos;
}

int stats_export_json(char *buf, size_t buf_size)
{
    struct stats_entry *entry;
    int pos = 0;
    bool first = true;

    if (!buf || buf_size == 0) {
        return -1;
    }

    pthread_mutex_lock(&g_stats_ctx.mutex);

    pos = snprintf(buf + pos, buf_size - pos, "{\n");

    for (entry = g_stats_ctx.entries; entry; entry = entry->next) {
        if (!first) {
            pos += snprintf(buf + pos, buf_size - pos, ",\n");
        }
        first = false;

        switch (entry->type) {
        case STATS_TYPE_COUNTER:
            pos += snprintf(buf + pos, buf_size - pos,
                           "  \"%s\": {\"type\":\"counter\",\"value\":%lu}",
                           entry->name, entry->value.counter);
            break;
        case STATS_TYPE_GAUGE:
            pos += snprintf(buf + pos, buf_size - pos,
                           "  \"%s\": {\"type\":\"gauge\",\"value\":%ld}",
                           entry->name, entry->value.gauge);
            break;
        case STATS_TYPE_HISTOGRAM:
            pos += snprintf(buf + pos, buf_size - pos,
                           "  \"%s\": {\"type\":\"histogram\",\"count\":%lu,"
                           "\"sum\":%lu,\"min\":%lu,\"max\":%lu}",
                           entry->name,
                           entry->value.histogram.count,
                           entry->value.histogram.sum,
                           entry->value.histogram.min,
                           entry->value.histogram.max);
            break;
        case STATS_TYPE_RATE:
            pos += snprintf(buf + pos, buf_size - pos,
                           "  \"%s\": {\"type\":\"rate\",\"value\":%lu,"
                           "\"rate\":%.2f}",
                           entry->name,
                           entry->value.rate.value,
                           entry->value.rate.rate);
            break;
        }
    }

    pos += snprintf(buf + pos, buf_size - pos, "\n}\n");

    pthread_mutex_unlock(&g_stats_ctx.mutex);

    return pos;
}

void stats_cleanup(void)
{
    struct stats_entry *entry, *next;

    pthread_mutex_lock(&g_stats_ctx.mutex);

    entry = g_stats_ctx.entries;
    while (entry) {
        next = entry->next;
        free(entry);
        entry = next;
    }

    g_stats_ctx.entries = NULL;
    g_stats_ctx.num_entries = 0;

    pthread_mutex_unlock(&g_stats_ctx.mutex);

    YLOG_INFO("Statistics subsystem cleanup");
}

/* Health check functions */

int health_init(void)
{
    if (g_health_initialized) {
        return 0;
    }

    g_health_initialized = true;
    YLOG_INFO("Health check subsystem initialized");
    return 0;
}

int health_register(const char *name,
                    int (*check_fn)(struct health_check *),
                    uint32_t check_interval, void *user_data)
{
    struct health_check *check;

    if (!name || !check_fn) {
        return -1;
    }

    pthread_mutex_lock(&g_health_mutex);

    /* Check if already exists */
    for (check = g_health_checks; check; check = check->next) {
        if (strcmp(check->name, name) == 0) {
            pthread_mutex_unlock(&g_health_mutex);
            YLOG_WARNING("Health check '%s' already exists", name);
            return -1;
        }
    }

    /* Allocate new check */
    check = calloc(1, sizeof(*check));
    if (!check) {
        pthread_mutex_unlock(&g_health_mutex);
            YLOG_ERROR("Failed to allocate health check");
        return -1;
    }

    strncpy(check->name, name, sizeof(check->name) - 1);
    check->status = HEALTH_STATUS_UNKNOWN;
    check->check_fn = check_fn;
    check->check_interval = check_interval;
    check->user_data = user_data;
    check->last_check = 0;

    /* Add to list */
    check->next = g_health_checks;
    g_health_checks = check;

    pthread_mutex_unlock(&g_health_mutex);

    YLOG_DEBUG("Registered health check: %s", name);
    return 0;
}

enum health_status health_check_all(void)
{
    struct health_check *check;
    enum health_status overall = HEALTH_STATUS_HEALTHY;
    time_t now = time(NULL);

    if (!g_health_initialized) {
        return HEALTH_STATUS_UNKNOWN;
    }

    pthread_mutex_lock(&g_health_mutex);

    for (check = g_health_checks; check; check = check->next) {
        /* Check if it's time to run this check */
        if (now - check->last_check < check->check_interval) {
            continue;
        }

        /* Run the check */
        if (check->check_fn) {
            int ret = check->check_fn(check);
            check->last_check = now;

            if (ret != 0) {
                check->status = HEALTH_STATUS_UNHEALTHY;
                snprintf(check->message, sizeof(check->message),
                        "Check failed with return code %d", ret);
            } else {
                check->status = HEALTH_STATUS_HEALTHY;
                snprintf(check->message, sizeof(check->message), "OK");
            }
        }

        /* Update overall status */
        if (check->status == HEALTH_STATUS_UNHEALTHY) {
            overall = HEALTH_STATUS_UNHEALTHY;
        } else if (check->status == HEALTH_STATUS_DEGRADED &&
                   overall == HEALTH_STATUS_HEALTHY) {
            overall = HEALTH_STATUS_DEGRADED;
        }
    }

    pthread_mutex_unlock(&g_health_mutex);

    return overall;
}

enum health_status health_get_status(const char *name)
{
    struct health_check *check;
    enum health_status status = HEALTH_STATUS_UNKNOWN;

    if (!g_health_initialized) {
        return HEALTH_STATUS_UNKNOWN;
    }

    pthread_mutex_lock(&g_health_mutex);

    if (name) {
        /* Get specific check status */
        for (check = g_health_checks; check; check = check->next) {
            if (strcmp(check->name, name) == 0) {
                status = check->status;
                break;
            }
        }
    } else {
        /* Get overall status */
        status = health_check_all();
    }

    pthread_mutex_unlock(&g_health_mutex);

    return status;
}

int health_export_json(char *buf, size_t buf_size)
{
    struct health_check *check;
    int pos = 0;
    bool first = true;
    enum health_status overall;

    if (!buf || buf_size == 0) {
        return -1;
    }

    overall = health_check_all();

    pthread_mutex_lock(&g_health_mutex);

    const char *status_str[] = {
        "unknown", "healthy", "degraded", "unhealthy"
    };

    pos = snprintf(buf + pos, buf_size - pos,
                   "{\"status\":\"%s\",\"checks\":[",
                   status_str[overall]);

    for (check = g_health_checks; check; check = check->next) {
        if (!first) {
            pos += snprintf(buf + pos, buf_size - pos, ",");
        }
        first = false;

        pos += snprintf(buf + pos, buf_size - pos,
                       "{\"name\":\"%s\",\"status\":\"%s\",\"message\":\"%s\"}",
                       check->name,
                       status_str[check->status],
                       check->message);
    }

    pos += snprintf(buf + pos, buf_size - pos, "]}\n");

    pthread_mutex_unlock(&g_health_mutex);

    return pos;
}

void health_cleanup(void)
{
    struct health_check *check, *next;

    if (!g_health_initialized) {
        return;
    }

    pthread_mutex_lock(&g_health_mutex);

    check = g_health_checks;
    while (check) {
        next = check->next;
        free(check);
        check = next;
    }

    g_health_checks = NULL;
    g_health_initialized = false;

    pthread_mutex_unlock(&g_health_mutex);

    YLOG_INFO("Health check subsystem cleanup");
}
