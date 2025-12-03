/**
 * @file stats.h
 * @brief Statistics Collection and Health Check Framework
 *
 * Provides statistics collection, metrics export (Prometheus/JSON),
 * and health check functionality.
 */

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#define STATS_NAME_MAX      64
#define STATS_DESC_MAX      256
#define STATS_UNIT_MAX      32
#define STATS_MSG_MAX       256

/* Statistics types */
enum stats_type {
    STATS_TYPE_COUNTER = 0,     /* Monotonically increasing counter */
    STATS_TYPE_GAUGE,           /* Value that can go up or down */
    STATS_TYPE_HISTOGRAM,       /* Distribution of values */
    STATS_TYPE_RATE             /* Rate of change over time */
};

/* Statistics flags */
enum stats_flag {
    STATS_FLAG_NONE = 0,
    STATS_FLAG_ATOMIC = (1 << 0),   /* Use atomic operations */
    STATS_FLAG_PERSIST = (1 << 1), /* Persist across restarts */
    STATS_FLAG_HIDDEN = (1 << 2)   /* Hide from export */
};

/* Histogram data */
struct stats_histogram {
    uint64_t count;
    uint64_t sum;
    uint64_t min;
    uint64_t max;
};

/* Rate data */
struct stats_rate {
    uint64_t value;
    time_t last_update;
    double rate;
};

/* Statistics value union */
union stats_value {
    uint64_t counter;
    int64_t gauge;
    struct stats_histogram histogram;
    struct stats_rate rate;
};

/* Statistics entry */
struct stats_entry {
    char name[STATS_NAME_MAX];
    char description[STATS_DESC_MAX];
    char unit[STATS_UNIT_MAX];
    enum stats_type type;
    uint32_t flags;
    union stats_value value;
    struct stats_entry *next;
};

/* Statistics context */
struct stats_context {
    struct stats_entry *entries;
    uint32_t num_entries;
    pthread_mutex_t mutex;
    bool enabled;
};

/* Health check status */
enum health_status {
    HEALTH_STATUS_UNKNOWN = 0,
    HEALTH_STATUS_HEALTHY,
    HEALTH_STATUS_DEGRADED,
    HEALTH_STATUS_UNHEALTHY
};

/* Forward declaration */
struct health_check;

/* Health check callback */
typedef int (*health_check_fn)(struct health_check *check);

/* Health check entry */
struct health_check {
    char name[STATS_NAME_MAX];
    enum health_status status;
    char message[STATS_MSG_MAX];
    health_check_fn check_fn;
    uint32_t check_interval;    /* seconds */
    time_t last_check;
    void *user_data;
    struct health_check *next;
};

/**
 * Initialize statistics subsystem
 * @return 0 on success, -1 on failure
 */
int stats_init(void);

/**
 * Register a new statistic
 * @param name Statistic name
 * @param type Statistic type
 * @param description Human-readable description
 * @param unit Unit of measurement
 * @param flags Statistics flags
 * @return 0 on success, -1 on failure
 */
int stats_register(const char *name, enum stats_type type,
                   const char *description, const char *unit, uint32_t flags);

/**
 * Increment a counter
 * @param name Counter name
 * @param value Value to add
 */
void stats_counter_inc(const char *name, uint64_t value);

/**
 * Set a gauge value
 * @param name Gauge name
 * @param value New value
 */
void stats_gauge_set(const char *name, int64_t value);

/**
 * Update a histogram
 * @param name Histogram name
 * @param value Sample value
 */
void stats_histogram_update(const char *name, uint64_t value);

/**
 * Get a statistic value
 * @param name Statistic name
 * @param value Output value
 * @return 0 on success, -1 on failure
 */
int stats_get(const char *name, uint64_t *value);

/**
 * Export statistics in Prometheus format
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Number of bytes written, or -1 on error
 */
int stats_export_prometheus(char *buf, size_t buf_size);

/**
 * Export statistics in JSON format
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Number of bytes written, or -1 on error
 */
int stats_export_json(char *buf, size_t buf_size);

/**
 * Cleanup statistics subsystem
 */
void stats_cleanup(void);

/**
 * Initialize health check subsystem
 * @return 0 on success, -1 on failure
 */
int health_init(void);

/**
 * Register a health check
 * @param name Check name
 * @param check_fn Check function
 * @param check_interval Interval between checks (seconds)
 * @param user_data User data passed to check function
 * @return 0 on success, -1 on failure
 */
int health_register(const char *name,
                    int (*check_fn)(struct health_check *),
                    uint32_t check_interval, void *user_data);

/**
 * Run all health checks
 * @return Overall health status
 */
enum health_status health_check_all(void);

/**
 * Get health status
 * @param name Check name (NULL for overall status)
 * @return Health status
 */
enum health_status health_get_status(const char *name);

/**
 * Export health status in JSON format
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Number of bytes written, or -1 on error
 */
int health_export_json(char *buf, size_t buf_size);

/**
 * Cleanup health check subsystem
 */
void health_cleanup(void);

#endif /* STATS_H */
